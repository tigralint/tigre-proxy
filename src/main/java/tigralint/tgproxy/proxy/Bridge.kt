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
 */
object Bridge {
    private const val TAG = "Bridge"
    private const val READ_BUF_SIZE = 65536

    /**
     * Bridge client TCP connection to a WebSocket connection with re-encryption.
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
        stats: ProxyStats
    ) {
        val dcTag = "DC$dc${if (isMedia) "m" else ""}"
        var upBytes = 0L
        var downBytes = 0L
        var upPackets = 0
        var downPackets = 0
        val startTime = System.currentTimeMillis()

        coroutineScope {
            val tcpToWs = launch(Dispatchers.IO) {
                try {
                    val buf = ByteArray(READ_BUF_SIZE)
                    val outBuf = ByteArray(READ_BUF_SIZE)
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
                        upPackets++

                        // Re-encrypt: ZERO ALLOCATION (mostly). client cipher → plaintext → telegram cipher
                        // We use a shared outBuf to avoid allocating `plain`.
                        // The final target buffer must be precisely sized for the WebSocket to send.
                        ctx.cltDec.update(buf, 0, n, outBuf, 0)
                        val tgCipher = ByteArray(n)
                        ctx.tgEnc.update(outBuf, 0, n, tgCipher, 0)

                        if (splitter != null) {
                            val parts = splitter.split(tgCipher)
                            if (parts.isEmpty()) continue
                            if (parts.size > 1) {
                                ws.sendBatch(parts)
                            } else {
                                ws.send(parts[0])
                            }
                        } else {
                            ws.send(tgCipher)
                        }
                    }
                } catch (_: kotlinx.coroutines.CancellationException) {
                } catch (e: Exception) {
                    Log.d(TAG, "[$label] tcp→ws ended: $e")
                }
            }

            val wsToTcp = launch(Dispatchers.IO) {
                try {
                    while (isActive) {
                        val data = ws.recv() ?: break
                        val n = data.size
                        stats.bytesDown.addAndGet(n.toLong())
                        downBytes += n
                        downPackets++

                        // Re-encrypt IN-PLACE! (ZERO ALLOCATION)
                        // telegram cipher → plaintext → client cipher
                        // Since `data` array is fully owned by us after recv(), we mutate it in-place.
                        ctx.tgDec.update(data, 0, n, data, 0)
                        ctx.cltEnc.update(data, 0, n, data, 0)

                        clientOutput.writeFully(data)
                        clientOutput.flush()
                    }
                } catch (_: kotlinx.coroutines.CancellationException) {
                } catch (e: Exception) {
                    Log.d(TAG, "[$label] ws→tcp ended: $e")
                }
            }

            // Wait for either direction to finish, then cancel the other
            select(tcpToWs, wsToTcp)
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

            // Send relay init with TCP Fragmentation (DPI Bypass)
            // Break the handshake packet into tiny fragments to evade DPI signature matching (GoodbyeDPI style)
            withContext(Dispatchers.IO) {
                if (relayInit.size >= 24) {
                    val chunks = listOf(8, 8, 8)
                    var offset = 0
                    for (chunkSize in chunks) {
                        remoteOutput.writeFully(relayInit, offset, chunkSize)
                        offset += chunkSize
                        delay(5) // Non-blocking delay for fragmentation
                    }
                    // Send the remainings
                    remoteOutput.writeFully(relayInit, offset, relayInit.size - offset)
                } else {
                    remoteOutput.writeFully(relayInit)
                }
            }

            // Bidirectional TCP ↔ TCP with re-encryption
            coroutineScope {
                val up = launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(READ_BUF_SIZE)
                        val outBuf = ByteArray(READ_BUF_SIZE)
                        while (isActive && !clientInput.isClosedForRead) {
                            val n = clientInput.readAvailable(buf)
                            if (n == -1) break
                            stats.bytesUp.addAndGet(n.toLong())
                            
                            // ZERO-ALLOCATION chain: buf -> outBuf -> buf
                            ctx.cltDec.update(buf, 0, n, outBuf, 0)
                            ctx.tgEnc.update(outBuf, 0, n, buf, 0)
                            remoteOutput.writeFully(buf, 0, n)
                        }
                    } catch (_: kotlinx.coroutines.CancellationException) {
                    } catch (e: Exception) {
                        Log.d(TAG, "[$label] tcp→tcp up ended: $e")
                    }
                }

                val down = launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(READ_BUF_SIZE)
                        val outBuf = ByteArray(READ_BUF_SIZE)
                        while (isActive && !remoteInput.isClosedForRead) {
                            val n = remoteInput.readAvailable(buf)
                            if (n == -1) break
                            stats.bytesDown.addAndGet(n.toLong())
                            
                            // ZERO-ALLOCATION chain: buf -> outBuf -> buf
                            ctx.tgDec.update(buf, 0, n, outBuf, 0)
                            ctx.cltEnc.update(outBuf, 0, n, buf, 0)
                            clientOutput.writeFully(buf, 0, n)
                            clientOutput.flush()
                        }
                    } catch (_: kotlinx.coroutines.CancellationException) {
                    } catch (e: Exception) {
                        Log.d(TAG, "[$label] tcp→tcp down ended: $e")
                    }
                }

                select(up, down)
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
        val active = config.activeCfProxyDomain
        val others = config.cfProxyDomains.filter { it != active }

        var ws: ProxyWebSocket? = null
        var chosenDomain: String? = null

        Log.i(TAG, "[$label] DC$dc$mediaTag → trying CF proxy")

        for (baseDomain in listOf(active) + others) {
            val domain = "kws$dc.$baseDomain"
            try {
                ws = ProxyWebSocket.connect(domain, domain, timeoutMs = 10000)
                chosenDomain = baseDomain
                break
            } catch (e: Exception) {
                Log.w(TAG, "[$label] DC$dc$mediaTag CF proxy failed: $e")
            }
        }

        if (ws == null) return false

        if (chosenDomain != null && chosenDomain != config.activeCfProxyDomain) {
            Log.i(TAG, "[$label] Switching active CF domain to $chosenDomain")
            config.activeCfProxyDomain = chosenDomain
        }

        stats.connectionsCfProxy.incrementAndGet()
        ws.send(relayInit)

        bridgeWsReencrypt(clientInput, clientOutput, ws, label, dc, isMedia, ctx, splitter, stats)
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

    /**
     * Select: wait for either job to complete, then cancel the other.
     */
    private suspend fun select(vararg jobs: Job) {
        try {
            kotlinx.coroutines.selects.select {
                jobs.forEach { job -> job.onJoin { } }
            }
        } finally {
            for (job in jobs) {
                if (job.isActive) job.cancel()
            }
            for (job in jobs) {
                try { job.join() } catch (_: Exception) {}
            }
        }
    }
}
