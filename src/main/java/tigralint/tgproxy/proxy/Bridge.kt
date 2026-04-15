package tigralint.tgproxy.proxy

import android.util.Log
import kotlinx.coroutines.*
import io.ktor.utils.io.*
import io.ktor.network.selector.*
import io.ktor.network.sockets.*

/**
 * Bidirectional TCP ↔ WS bridge with re-encryption.
 * This is the CORE logic of the proxy.
 *
 * Data flow:
 *   Client ciphertext → cltDec(AES-CTR) → plaintext → tgEnc(AES-CTR) → WS frame → Telegram
 *   Telegram WS frame → tgDec(AES-CTR) → plaintext → cltEnc(AES-CTR) → Client TCP
 *
 * Port of bridge.py bridge_ws_reencrypt, _tcp_fallback, and _cfproxy_fallback.
 *
 * Architecture notes:
 * - Uses structured concurrency (coroutineScope) for automatic cleanup
 * - When either direction (up/down) terminates, the entire scope cancels both
 * - Zero-allocation re-encryption in the TCP fallback hot path (reused buffers)
 */
object Bridge {
    private const val TAG = "Bridge"
    private const val READ_BUF_SIZE = 65536

    /**
     * Bridge client TCP connection to a WebSocket connection with re-encryption.
     *
     * Both directions run in a `coroutineScope`. When either direction finishes
     * (EOF, error, or cancellation), the scope cancels the other automatically.
     */
    suspend fun bridgeWsReencrypt(
        clientInput: ByteReadChannel,
        clientOutput: ByteWriteChannel,
        ws: ProxyWebSocket,
        label: String,
        dc: Int,
        isMedia: Boolean,
        ctx: CryptoCtx,
        splitter: MsgSplitter?,
        stats: ProxyStats,
        trafficShaping: Boolean = false
    ) {
        val dcTag = "DC$dc${if (isMedia) "m" else ""}"
        var upBytes = 0L
        var downBytes = 0L
        var upPackets = 0
        var downPackets = 0
        val startTime = System.currentTimeMillis()

        try {
            coroutineScope {
                // TCP → WS (client to Telegram)
                launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(READ_BUF_SIZE)
                        while (isActive && !clientInput.isClosedForRead) {
                            val n = clientInput.readAvailable(buf)
                            if (n == -1) {
                                // Client disconnected — flush splitter
                                if (splitter != null) {
                                    val tail = splitter.flush()
                                    for (part in tail) {
                                        ws.send(part)
                                    }
                                }
                                break
                            }

                            stats.bytesUp.addAndGet(n.toLong())
                            upBytes += n

                            // Anti-DPI: traffic shaping micro-delays during handshake
                            if (trafficShaping) {
                                val shapeDelay = AntiDpi.trafficShapingDelayMs(upPackets)
                                if (shapeDelay > 0) delay(shapeDelay)
                            }
                            upPackets++

                            // Re-encrypt: ONE ALLOCATION PER READ. client cipher → plaintext → telegram cipher
                            // Since we need a precisely sized array for WebSocket.send(), we allocate
                            // targetBuf(n), decrypt into it, then encrypt it in-place.
                            val targetBuf = ByteArray(n)
                            ctx.cltDec.update(buf, 0, n, targetBuf, 0)
                            ctx.tgEnc.update(targetBuf, 0, n, targetBuf, 0)

                            if (splitter != null) {
                                val parts = splitter.split(targetBuf)
                                if (parts.isEmpty()) continue
                                if (parts.size > 1) {
                                    ws.sendBatch(parts)
                                } else {
                                    ws.send(parts[0])
                                }
                            } else {
                                ws.send(targetBuf)
                            }
                        }
                    } catch (_: kotlinx.coroutines.CancellationException) {
                        throw kotlinx.coroutines.CancellationException() // propagate to cancel peer
                    } catch (e: Exception) {
                        Log.d(TAG, "[$label] tcp→ws ended: $e")
                    }
                    // When this finishes, cancel the scope → kills wsToTcp
                    cancel()
                }

                // WS → TCP (Telegram to client)
                launch(Dispatchers.IO) {
                    try {
                        while (isActive) {
                            val data = ws.recv() ?: break
                            val n = data.size
                            stats.bytesDown.addAndGet(n.toLong())
                            downBytes += n
                            downPackets++

                            // Anti-DPI: traffic shaping micro-delays during handshake
                            if (trafficShaping) {
                                val shapeDelay = AntiDpi.trafficShapingDelayMs(downPackets)
                                if (shapeDelay > 0) delay(shapeDelay)
                            }

                            // Re-encrypt IN-PLACE! (ZERO ALLOCATION)
                            // telegram cipher → plaintext → client cipher
                            // Since `data` array is fully owned by us after recv(), we mutate it in-place.
                            ctx.tgDec.update(data, 0, n, data, 0)
                            ctx.cltEnc.update(data, 0, n, data, 0)

                            clientOutput.writeFully(data)
                            clientOutput.flush()
                        }
                    } catch (_: kotlinx.coroutines.CancellationException) {
                        throw kotlinx.coroutines.CancellationException() // propagate to cancel peer
                    } catch (e: Exception) {
                        Log.d(TAG, "[$label] ws→tcp ended: $e")
                    }
                    // When this finishes, cancel the scope → kills tcpToWs
                    cancel()
                }
            }
        } catch (_: kotlinx.coroutines.CancellationException) {
            // Normal: one direction finished, scope cancelled the other
        }

        val elapsed = (System.currentTimeMillis() - startTime) / 1000.0
        Log.i(TAG, "[$label] $dcTag WS session closed: " +
                "^${Constants.humanBytes(upBytes)} ($upPackets pkts) " +
                "v${Constants.humanBytes(downBytes)} ($downPackets pkts) " +
                "in %.1fs".format(elapsed))

        ws.close()
        stats.publishSnapshot()
    }

    /**
     * TCP direct fallback to Telegram DC.
     *
     * Uses zero-allocation re-encryption with pre-allocated buffer pairs.
     * Structured concurrency ensures both directions clean up when either ends.
     */
    suspend fun tcpFallback(
        clientInput: ByteReadChannel,
        clientOutput: ByteWriteChannel,
        dstIp: String,
        dstPort: Int,
        relayInit: ByteArray,
        label: String,
        dc: Int,
        isMedia: Boolean,
        ctx: CryptoCtx,
        stats: ProxyStats
    ): Boolean {
        val socket = try {
            withTimeout(15000) {
                val selectorManager = ActorSelectorManager(Dispatchers.IO)
                aSocket(selectorManager).tcp().connect(io.ktor.network.sockets.InetSocketAddress(dstIp, dstPort)) {
                    socketTimeout = 15000
                    receiveBufferSize = 131072
                    sendBufferSize = 131072
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "[$label] TCP fallback to $dstIp:$dstPort failed: $e")
            return false
        }

        stats.connectionsTcpFallback.incrementAndGet()

        try {
            val remoteInput = socket.openReadChannel()
            val remoteOutput = socket.openWriteChannel(autoFlush = true)

            // Send relay init with Randomized TCP Fragmentation (DPI Bypass)
            // Break the handshake into random-sized fragments (3-7 chunks) with random delays
            // to evade DPI signature matching. Old fixed 3×8 pattern was a detectable signature.
            withContext(Dispatchers.IO) {
                if (relayInit.size >= 12) {
                    val chunks = AntiDpi.randomFragmentSizes(relayInit.size)
                    var offset = 0
                    for ((i, chunkSize) in chunks.withIndex()) {
                        remoteOutput.writeFully(relayInit, offset, chunkSize)
                        offset += chunkSize
                        // Random delay between fragments (skip delay after last chunk)
                        if (i < chunks.size - 1) {
                            delay(AntiDpi.randomFragmentDelayMs())
                        }
                    }
                    Log.d(TAG, "[$label] relay_init fragmented: ${chunks.size} chunks, sizes=$chunks")
                } else {
                    remoteOutput.writeFully(relayInit)
                }
            }

            // Bidirectional TCP ↔ TCP with re-encryption (structured concurrency)
            try {
                coroutineScope {
                    launch(Dispatchers.IO) {
                        try {
                            val buf = ByteArray(READ_BUF_SIZE)
                            val outBuf = ByteArray(READ_BUF_SIZE)
                            var upPackets = 0
                            while (isActive && !clientInput.isClosedForRead) {
                                val n = clientInput.readAvailable(buf)
                                if (n == -1) break
                                stats.bytesUp.addAndGet(n.toLong())

                                // Cross-Layer RTT Padding: random delay on first packets
                                // to mask TCP↔TLS RTT discrepancy (defeats dMAP/NDSS 2025)
                                val shapeDelay = AntiDpi.trafficShapingDelayMs(upPackets)
                                if (shapeDelay > 0) delay(shapeDelay)
                                upPackets++
                                
                                // ZERO-ALLOCATION chain: buf -> outBuf -> buf
                                ctx.cltDec.update(buf, 0, n, outBuf, 0)
                                ctx.tgEnc.update(outBuf, 0, n, buf, 0)
                                remoteOutput.writeFully(buf, 0, n)
                            }
                        } catch (_: kotlinx.coroutines.CancellationException) {
                            throw kotlinx.coroutines.CancellationException()
                        } catch (e: Exception) {
                            Log.d(TAG, "[$label] tcp→tcp up ended: $e")
                        }
                        cancel()
                    }

                    launch(Dispatchers.IO) {
                        try {
                            val buf = ByteArray(READ_BUF_SIZE)
                            val outBuf = ByteArray(READ_BUF_SIZE)
                            var downPackets = 0
                            while (isActive && !remoteInput.isClosedForRead) {
                                val n = remoteInput.readAvailable(buf)
                                if (n == -1) break
                                stats.bytesDown.addAndGet(n.toLong())

                                // Cross-Layer RTT Padding: random delay on first packets
                                val shapeDelay = AntiDpi.trafficShapingDelayMs(downPackets)
                                if (shapeDelay > 0) delay(shapeDelay)
                                downPackets++
                                
                                // ZERO-ALLOCATION chain: buf -> outBuf -> buf
                                ctx.tgDec.update(buf, 0, n, outBuf, 0)
                                ctx.cltEnc.update(outBuf, 0, n, buf, 0)
                                clientOutput.writeFully(buf, 0, n)
                                clientOutput.flush()
                            }
                        } catch (_: kotlinx.coroutines.CancellationException) {
                            throw kotlinx.coroutines.CancellationException()
                        } catch (e: Exception) {
                            Log.d(TAG, "[$label] tcp→tcp down ended: $e")
                        }
                        cancel()
                    }
                }
            } catch (_: kotlinx.coroutines.CancellationException) {
                // Normal: one direction finished
            }
        } finally {
            try { socket.dispose() } catch (_: Exception) {}
        }

        stats.publishSnapshot()
        return true
    }

    /**
     * Cloudflare proxy fallback.
     */
    suspend fun cfProxyFallback(
        clientInput: ByteReadChannel,
        clientOutput: ByteWriteChannel,
        relayInit: ByteArray,
        label: String,
        dc: Int,
        isMedia: Boolean,
        ctx: CryptoCtx,
        splitter: MsgSplitter?,
        config: ProxyConfig,
        stats: ProxyStats
    ): Boolean {
        val mediaTag = if (isMedia) " media" else ""
        
        val userDomain = config.cfProxyUserDomain
        if (userDomain.isEmpty() && config.cfProxyDomains.isEmpty()) return false

        val active = config.activeCfProxyDomain
        val others = config.cfProxyDomains.filter { it != active }
        val prioritizedList = mutableListOf<String>()
        
        if (userDomain.isNotEmpty()) prioritizedList.add(userDomain)
        if (active.isNotEmpty() && active != userDomain) prioritizedList.add(active)
        others.forEach { if (it != userDomain && it != active) prioritizedList.add(it) }

        var ws: ProxyWebSocket? = null
        var chosenDomain: String? = null

        Log.i(TAG, "[$label] DC$dc$mediaTag → trying CF proxy (options: ${prioritizedList.size})")

        for (baseDomain in prioritizedList) {
            // Using path-based routing (e.g., domain/dc2)
            val connectTarget = if (baseDomain.contains("/")) {
                if (baseDomain.endsWith("/")) "${baseDomain}dc$dc" else "$baseDomain/dc$dc"
            } else {
                "$baseDomain/dc$dc"
            }

            try {
                ws = ProxyWebSocket.connect(connectTarget, baseDomain.split("/")[0], timeoutMs = 10000, antiDpiEnabled = config.antiDpiEnabled)
                chosenDomain = baseDomain
                break
            } catch (e: Exception) {
                Log.w(TAG, "[$label] DC$dc$mediaTag CF proxy failed ($baseDomain): $e")
            }
        }

        if (ws == null) return false

        if (chosenDomain != null && config.cfProxyUserDomain.isEmpty() && chosenDomain != config.activeCfProxyDomain) {
            Log.i(TAG, "[$label] Switching active public CF domain to $chosenDomain")
            config.activeCfProxyDomain = chosenDomain
        }

        stats.connectionsCfProxy.incrementAndGet()
        ws.send(relayInit)

        bridgeWsReencrypt(clientInput, clientOutput, ws, label, dc, isMedia, ctx, splitter, stats, trafficShaping = config.trafficShaping)
        return true
    }

    /**
     * Try all available fallback methods for a DC.
     */
    suspend fun doFallback(
        clientInput: ByteReadChannel,
        clientOutput: ByteWriteChannel,
        relayInit: ByteArray,
        label: String,
        dc: Int,
        isMedia: Boolean,
        ctx: CryptoCtx,
        splitter: MsgSplitter?,
        config: ProxyConfig,
        stats: ProxyStats
    ): Boolean {
        val mediaTag = if (isMedia) " media" else ""
        val fallbackDst = Constants.DC_DEFAULT_IPS[dc]
        val useCf = config.fallbackCfProxy
        val cfFirst = config.fallbackCfProxyPriority

        val methods = mutableListOf("tcp")
        if (useCf) {
            methods.add(if (cfFirst) 0 else 1, "cf")
        }

        for (method in methods) {
            when (method) {
                "cf" -> {
                    val ok = cfProxyFallback(
                        clientInput, clientOutput, relayInit, label,
                        dc, isMedia, ctx, splitter, config, stats
                    )
                    if (ok) return true
                }
                "tcp" -> {
                    if (fallbackDst != null) {
                        Log.i(TAG, "[$label] DC$dc$mediaTag → TCP fallback to $fallbackDst:443")
                        val ok = tcpFallback(
                            clientInput, clientOutput, fallbackDst, 443,
                            relayInit, label, dc, isMedia, ctx, stats
                        )
                        if (ok) return true
                    }
                }
            }
        }
        return false
    }
}
