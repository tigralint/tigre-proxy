package tigralint.tgproxy.proxy

import android.util.Log
import kotlinx.coroutines.*
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

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
        clientInput: InputStream,
        clientOutput: OutputStream,
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
                    while (isActive) {
                        val n = clientInput.read(buf)
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

                        // Re-encrypt: client cipher → plaintext → telegram cipher
                        val plain = ctx.cltDec.update(buf, 0, n)
                        val tgCipher = ctx.tgEnc.update(plain)

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
                } catch (_: CancellationException) {
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

                        // Re-encrypt: telegram cipher → plaintext → client cipher
                        val plain = ctx.tgDec.update(data)
                        val clientCipher = ctx.cltEnc.update(plain)

                        clientOutput.write(clientCipher)
                        clientOutput.flush()
                    }
                } catch (_: CancellationException) {
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
        clientInput: InputStream,
        clientOutput: OutputStream,
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
            withTimeout(10000) {
                withContext(Dispatchers.IO) {
                    Socket().apply {
                        tcpNoDelay = true
                        connect(InetSocketAddress(dstIp, dstPort), 10000)
                    }
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "[$label] TCP fallback to $dstIp:$dstPort failed: $e")
            return false
        }

        stats.connectionsTcpFallback.incrementAndGet()

        try {
            val remoteInput = socket.getInputStream()
            val remoteOutput = socket.getOutputStream()

            // Send relay init with TCP Fragmentation (DPI Bypass)
            // Break the handshake packet into tiny fragments to evade DPI signature matching (GoodbyeDPI style)
            withContext(Dispatchers.IO) {
                if (relayInit.size >= 24) {
                    val chunks = listOf(8, 8, 8)
                    var offset = 0
                    for (chunkSize in chunks) {
                        remoteOutput.write(relayInit, offset, chunkSize)
                        remoteOutput.flush()
                        offset += chunkSize
                        Thread.sleep(5) // Guarantees exactly 5ms blocking on IO thread, evading slow coroutine scheduler wakeups
                    }
                    // Send the remainings
                    remoteOutput.write(relayInit, offset, relayInit.size - offset)
                    remoteOutput.flush()
                } else {
                    remoteOutput.write(relayInit)
                    remoteOutput.flush()
                }
            }

            // Bidirectional TCP ↔ TCP with re-encryption
            coroutineScope {
                val up = launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(READ_BUF_SIZE)
                        while (isActive) {
                            val n = clientInput.read(buf)
                            if (n == -1) break
                            stats.bytesUp.addAndGet(n.toLong())
                            val plain = ctx.cltDec.update(buf, 0, n)
                            val tgData = ctx.tgEnc.update(plain)
                            remoteOutput.write(tgData)
                            remoteOutput.flush()
                        }
                    } catch (_: CancellationException) {
                    } catch (e: Exception) {
                        Log.d(TAG, "[$label] tcp→tcp up ended: $e")
                    }
                }

                val down = launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(READ_BUF_SIZE)
                        while (isActive) {
                            val n = remoteInput.read(buf)
                            if (n == -1) break
                            stats.bytesDown.addAndGet(n.toLong())
                            val plain = ctx.tgDec.update(buf, 0, n)
                            val clientData = ctx.cltEnc.update(plain)
                            clientOutput.write(clientData)
                            clientOutput.flush()
                        }
                    } catch (_: CancellationException) {
                    } catch (e: Exception) {
                        Log.d(TAG, "[$label] tcp→tcp down ended: $e")
                    }
                }

                select(up, down)
            }
        } finally {
            try { socket.close() } catch (_: Exception) {}
        }

        stats.publishSnapshot()
        return true
    }

    /**
     * Cloudflare proxy fallback.
     */
    suspend fun cfProxyFallback(
        clientInput: InputStream,
        clientOutput: OutputStream,
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
        clientInput: InputStream,
        clientOutput: OutputStream,
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
