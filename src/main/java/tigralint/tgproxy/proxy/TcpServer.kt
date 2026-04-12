package tigralint.tgproxy.proxy

import tigralint.tgproxy.util.AppLogger
import kotlinx.coroutines.*
import io.ktor.utils.io.*
import io.ktor.network.selector.*
import io.ktor.network.sockets.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * TCP server that listens for Telegram client connections and bridges
 * them to Telegram's WebSocket endpoints with re-encryption.
 *
 * This is the main entry point for the proxy engine.
 * Port of _run and _handle_client from tg_ws_proxy.py.
 */
class TcpServer(
    private val config: ProxyConfig,
    val stats: ProxyStats
) {
    companion object {
        private const val TAG = "TcpServer"
        private const val DC_FAIL_COOLDOWN_MS = 30_000L
        private const val WS_FAIL_TIMEOUT_MS = 2_000L
    }

    private var serverSocket: ServerSocket? = null
    private var scope: CoroutineScope? = null
    private var wsPool: WsPool? = null

    private val wsBlacklist = ConcurrentHashMap.newKeySet<String>()
    private val dcFailUntil = ConcurrentHashMap<String, Long>()

    @Volatile
    var isRunning = false
        private set

    private fun log(level: String, message: String) {
        when (level) {
            "DEBUG" -> AppLogger.d(TAG, message)
            "INFO" -> AppLogger.i(TAG, message)
            "WARN" -> AppLogger.w(TAG, message)
            "ERROR" -> AppLogger.e(TAG, message)
            else -> AppLogger.d(TAG, message)
        }
    }

    /**
     * Start the TCP server. This function blocks the calling coroutine.
     */
    suspend fun start() = withContext(Dispatchers.IO) {
        if (isRunning) {
            log("WARN", "Server already running")
            return@withContext
        }

        val serverScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        scope = serverScope
        wsBlacklist.clear()
        dcFailUntil.clear()

        if (config.fallbackCfProxy) {
            config.initCfProxyDomains()
            // Background domain refresh
            serverScope.launch {
                while (isActive) {
                    delay(3600_000) // Refresh every hour
                    val fetched = ProxyConfig.fetchCfProxyDomains()
                    if (fetched.isNotEmpty()) {
                        config.cfProxyDomains = fetched.toMutableList()
                        config.activeCfProxyDomain = fetched.random()
                        log("INFO", "CF proxy domains refreshed: ${fetched.size} domains")
                    }
                }
            }
        }

        val secret = try {
            hexStringToByteArray(config.secret)
        } catch (e: Exception) {
            log("ERROR", "Invalid secret: ${e.message}")
            return@withContext
        }

        val pool = WsPool(config, stats, serverScope)
        wsPool = pool

        val selectorManager = ActorSelectorManager(Dispatchers.IO)
        val server = aSocket(selectorManager).tcp().bind(io.ktor.network.sockets.InetSocketAddress(config.host, config.port))
        serverSocket = server
        isRunning = true

        // Generate connect link
        val ftls = config.fakeTlsDomain
        if (ftls.isNotEmpty()) {
            val domainHex = ftls.toByteArray(Charsets.US_ASCII)
                .joinToString("") { "%02x".format(it) }
            log("INFO", "Connect: tg://proxy?server=${config.host}&port=${config.port}&secret=ee${config.secret}$domainHex")
        } else {
            log("INFO", "Connect: tg://proxy?server=${config.host}&port=${config.port}&secret=dd${config.secret}")
        }

        log("INFO", "════════════════════════════════════════")
        log("INFO", "  Telegram MTProto WS Bridge Proxy")
        log("INFO", "  Listening on ${config.host}:${config.port}")
        log("INFO", "  Secret: ${config.secret}")
        if (ftls.isNotEmpty()) {
            log("INFO", "  Fake TLS: $ftls")
        }
        log("INFO", "  Target DCs: ${config.dcRedirects}")
        log("INFO", "════════════════════════════════════════")

        // Warmup WS pool
        pool.warmup(config.dcRedirects)

        // Stats logging loop
        serverScope.launch {
            while (isActive) {
                delay(60_000)
                stats.publishSnapshot()
                log("INFO", "stats: ${stats.summary()}")
            }
        }

        // Accept loop
        try {
            while (isActive && !server.isClosed) {
                try {
                    val client = server.accept()
                    
                    serverScope.launch(Dispatchers.IO) {
                        try {
                            handleClient(client, secret, pool)
                        } catch (e: Exception) {
                            if (e !is kotlinx.coroutines.CancellationException) {
                                log("DEBUG", "Client error: $e")
                            }
                        } finally {
                            try { client.dispose() } catch (_: Exception) {}
                        }
                    }
                } catch (_: kotlinx.coroutines.CancellationException) {
                    break
                } catch (e: Exception) {
                    if (isRunning) {
                        log("ERROR", "Accept error: $e")
                    }
                }
            }
        } finally {
            isRunning = false
            pool.reset()
            try { server.dispose() } catch (_: Exception) {}
        }
    }

    /**
     * Stop the server gracefully.
     */
    fun stop() {
        isRunning = false
        scope?.cancel()
        try { serverSocket?.dispose() } catch (_: Exception) {}
        wsPool?.reset()
        serverSocket = null
        wsPool = null
        scope = null
        log("INFO", "Server stopped")
    }

    /**
     * Handle a single client connection.
     * Port of _handle_client from tg_ws_proxy.py.
     */
    private suspend fun handleClient(client: Socket, secret: ByteArray, pool: WsPool) {
        stats.connectionsTotal.incrementAndGet()
        stats.connectionsActive.incrementAndGet()

        val peer = client.remoteAddress.toString()
        var label = peer

        try {
            val input = client.openReadChannel()
            val output = client.openWriteChannel(autoFlush = true)

            val masking = config.fakeTlsDomain

            // Read first byte to detect TLS
            val firstByte = readBytesWithTimeout(input, 1) ?: run {
                log("DEBUG", "[$label] disconnected before handshake")
                return
            }

            var clientInput: ByteReadChannel = input
            var clientOutput: ByteWriteChannel = output
            var handshake: ByteArray

            if (firstByte[0] == FakeTls.TLS_RECORD_HANDSHAKE && masking.isNotEmpty()) {
                // FakeTLS path
                val hdrRest = readBytesWithTimeout(input, 4) ?: run {
                    log("DEBUG", "[$label] incomplete TLS record header")
                    return
                }

                val tlsHeader = firstByte + hdrRest
                val recordLen = ByteBuffer.wrap(tlsHeader, 3, 2).short.toInt() and 0xFFFF

                val recordBody = readBytesWithTimeout(input, recordLen) ?: run {
                    log("DEBUG", "[$label] incomplete TLS record body")
                    return
                }

                val clientHello = tlsHeader + recordBody
                val tlsResult = FakeTls.verifyClientHello(clientHello, secret)

                if (tlsResult == null) {
                    log("DEBUG", "[$label] Fake TLS verify failed → masking to $masking")
                    // Proxy to masking domain (transparent pass-through)
                    proxyToMaskingDomain(input, output, clientHello, masking, label)
                    return
                }

                log("DEBUG", "[$label] Fake TLS handshake ok (ts=${tlsResult.timestamp})")

                val serverHello = FakeTls.buildServerHello(secret, tlsResult.clientRandom, tlsResult.sessionId)
                output.writeFully(serverHello)
                output.flush()

                // Wrap FakeTls channels
                clientInput = FakeTls.run { unwrapFakeTls(input) }
                clientOutput = FakeTls.run { wrapFakeTls(output) }

                handshake = try {
                    val buf = ByteArray(Constants.HANDSHAKE_LEN)
                    clientInput.readFully(buf)
                    buf
                } catch (e: Exception) {
                    log("DEBUG", "[$label] incomplete obfs2 init inside TLS")
                    return
                }

            } else if (masking.isNotEmpty()) {
                log("DEBUG", "[$label] non-TLS byte 0x%02X → HTTP redirect".format(firstByte[0].toInt() and 0xFF))
                val redirect = ("HTTP/1.1 301 Moved Permanently\r\n" +
                        "Location: https://$masking/\r\n" +
                        "Content-Length: 0\r\n" +
                        "Connection: close\r\n\r\n").toByteArray()
                output.writeFully(redirect)
                output.flush()
                return
            } else {
                // No FakeTLS — read remaining 63 bytes for handshake
                val rest = readBytesWithTimeout(input, Constants.HANDSHAKE_LEN - 1) ?: run {
                    log("DEBUG", "[$label] disconnected before handshake")
                    return
                }
                handshake = firstByte + rest
            }

            // Parse MTProto handshake
            val result = MtProtoHandshake.tryHandshake(handshake, secret)
            if (result == null) {
                stats.connectionsBad.incrementAndGet()
                log("DEBUG", "[$label] bad handshake (wrong secret or proto)")
                // Drain to prevent connection reset
                try {
                    clientInput.discard()
                } catch (_: Exception) {}
                return
            }

            val (dc, isMedia, protoTag, clientDecPrekeyIv) = result

            val protoInt = when {
                protoTag.contentEquals(Constants.PROTO_TAG_ABRIDGED) -> Constants.PROTO_ABRIDGED_INT
                protoTag.contentEquals(Constants.PROTO_TAG_INTERMEDIATE) -> Constants.PROTO_INTERMEDIATE_INT
                else -> Constants.PROTO_PADDED_INTERMEDIATE_INT
            }

            val dcIdx = if (isMedia) -dc else dc
            val mediaTag = if (isMedia) " media" else ""

            log("DEBUG", "[$label] handshake ok: DC$dc$mediaTag proto=0x%08X".format(protoInt))

            // Generate relay init
            val relayInit = MtProtoHandshake.generateRelayInit(protoTag, dcIdx)

            // Setup 4 cipher contexts
            val ctx = setupCryptoCtx(clientDecPrekeyIv, secret, relayInit)

            val dcKey = "$dc${if (isMedia) "m" else ""}"

            // Fallback if DC not in config or WS blacklisted
            if (dc !in config.dcRedirects || dcKey in wsBlacklist) {
                if (dc !in config.dcRedirects) {
                    log("INFO", "[$label] DC$dc not in config → fallback")
                } else {
                    log("INFO", "[$label] DC$dc$mediaTag WS blacklisted → fallback")
                }
                val splitter = try { MsgSplitter(relayInit, protoInt) } catch (_: Exception) { null }
                val ok = Bridge.doFallback(
                    clientInput, clientOutput, relayInit, label,
                    dc, isMedia, ctx, splitter, config, stats
                )
                if (!ok) {
                    log("WARN", "[$label] DC$dc$mediaTag no fallback available")
                }
                return
            }

            // Try WebSocket connection
            val now = System.currentTimeMillis()
            val failUntil = dcFailUntil[dcKey] ?: 0
            val wsTimeout = if (now < failUntil) WS_FAIL_TIMEOUT_MS else 10_000L

            val domains = WsPool.wsDomains(dc, isMedia)
            val target = config.dcRedirects[dc]!!
            var ws: ProxyWebSocket? = null
            var wsFailedRedirect = false
            var allRedirects = true

            // Try pool first
            ws = pool.get(dc, isMedia, target, domains)
            if (ws != null) {
                log("INFO", "[$label] DC$dc$mediaTag → pool hit via $target")
            } else {
                // Direct connect
                for (domain in domains) {
                    log("INFO", "[$label] DC$dc$mediaTag → wss://$domain/apiws via $target")
                    try {
                        ws = ProxyWebSocket.connect(target, domain, timeoutMs = wsTimeout, antiDpiEnabled = config.antiDpiEnabled)
                        allRedirects = false
                        break
                    } catch (e: WsHandshakeError) {
                        stats.wsErrors.incrementAndGet()
                        if (e.isRedirect) {
                            wsFailedRedirect = true
                            log("WARN", "[$label] DC$dc$mediaTag got ${e.statusCode} from $domain → ${e.location ?: "?"}")
                            continue
                        } else {
                            allRedirects = false
                            log("WARN", "[$label] DC$dc$mediaTag WS handshake: ${e.statusLine}")
                        }
                    } catch (e: Exception) {
                        stats.wsErrors.incrementAndGet()
                        allRedirects = false
                        log("WARN", "[$label] DC$dc$mediaTag WS connect failed: $e")
                    }
                }
            }

            // WS failed → fallback
            if (ws == null) {
                if (wsFailedRedirect && allRedirects) {
                    wsBlacklist.add(dcKey)
                    log("WARN", "[$label] DC$dc$mediaTag blacklisted for WS (all 302)")
                } else {
                    dcFailUntil[dcKey] = now + DC_FAIL_COOLDOWN_MS
                    if (!wsFailedRedirect) {
                        log("INFO", "[$label] DC$dc$mediaTag WS cooldown for ${DC_FAIL_COOLDOWN_MS / 1000}s")
                    }
                }

                val splitterFb = try { MsgSplitter(relayInit, protoInt) } catch (_: Exception) { null }
                val ok = Bridge.doFallback(
                    clientInput, clientOutput, relayInit, label,
                    dc, isMedia, ctx, splitterFb, config, stats
                )
                if (ok) {
                    log("INFO", "[$label] DC$dc$mediaTag fallback closed")
                }
                return
            }

            dcFailUntil.remove(dcKey)
            stats.connectionsWs.incrementAndGet()

            val splitter = try {
                MsgSplitter(relayInit, protoInt).also {
                    log("DEBUG", "[$label] MsgSplitter activated for proto 0x%08X".format(protoInt))
                }
            } catch (_: Exception) { null }

            // Send relay init to Telegram via WS
            ws.send(relayInit)

            // Start the bidirectional bridge
            Bridge.bridgeWsReencrypt(
                clientInput, clientOutput, ws, label,
                dc, isMedia, ctx, splitter, stats,
                trafficShaping = config.trafficShaping
            )

        } catch (_: kotlinx.coroutines.CancellationException) {
            log("DEBUG", "[$label] cancelled")
        } catch (e: Exception) {
            log("ERROR", "[$label] unexpected: $e")
        } finally {
            stats.connectionsActive.decrementAndGet()
            stats.publishSnapshot()
            try { client.close() } catch (_: Exception) {}
        }
    }

    /**
     * Setup the 4 AES-CTR cipher contexts for re-encryption.
     */
    private fun setupCryptoCtx(
        clientDecPrekeyIv: ByteArray,
        secret: ByteArray,
        relayInit: ByteArray
    ): CryptoCtx {
        val sha256 = MessageDigest.getInstance("SHA-256")

        // Client decrypt: key = SHA256(prekey + secret), iv from handshake
        val cltDecPrekey = clientDecPrekeyIv.copyOfRange(0, Constants.PREKEY_LEN)
        val cltDecIv = clientDecPrekeyIv.copyOfRange(Constants.PREKEY_LEN, Constants.PREKEY_LEN + Constants.IV_LEN)

        sha256.reset()
        sha256.update(cltDecPrekey)
        sha256.update(secret)
        val cltDecKey = sha256.digest()

        // Client encrypt: reverse prekey+iv, then SHA256(reversed_prekey + secret)
        val cltEncPrekeyIv = clientDecPrekeyIv.reversedArray()
        val cltEncPrekey = cltEncPrekeyIv.copyOfRange(0, Constants.PREKEY_LEN)
        val cltEncIv = cltEncPrekeyIv.copyOfRange(Constants.PREKEY_LEN, Constants.PREKEY_LEN + Constants.IV_LEN)

        sha256.reset()
        sha256.update(cltEncPrekey)
        sha256.update(secret)
        val cltEncKey = sha256.digest()

        val cltDecryptor = AesCtrCipher(cltDecKey, cltDecIv)
        val cltEncryptor = AesCtrCipher(cltEncKey, cltEncIv)

        // Fast-forward client decryptor past the 64-byte init
        cltDecryptor.skip(64)

        // Relay side: standard obfuscation (no secret hash — raw key from relay_init)
        val relayEncKey = relayInit.copyOfRange(Constants.SKIP_LEN, Constants.SKIP_LEN + Constants.PREKEY_LEN)
        val relayEncIv = relayInit.copyOfRange(
            Constants.SKIP_LEN + Constants.PREKEY_LEN,
            Constants.SKIP_LEN + Constants.PREKEY_LEN + Constants.IV_LEN
        )

        val relayDecPrekeyIv = relayInit.copyOfRange(
            Constants.SKIP_LEN,
            Constants.SKIP_LEN + Constants.PREKEY_LEN + Constants.IV_LEN
        ).reversedArray()
        val relayDecKey = relayDecPrekeyIv.copyOfRange(0, Constants.KEY_LEN)
        val relayDecIv = relayDecPrekeyIv.copyOfRange(Constants.KEY_LEN, Constants.KEY_LEN + Constants.IV_LEN)

        val tgEncryptor = AesCtrCipher(relayEncKey, relayEncIv)
        val tgDecryptor = AesCtrCipher(relayDecKey, relayDecIv)

        // Fast-forward relay encryptor past the init
        tgEncryptor.skip(64)

        return CryptoCtx(cltDecryptor, cltEncryptor, tgEncryptor, tgDecryptor)
    }

    /**
     * Proxy traffic to the masking domain transparently.
     * Port of proxy_to_masking_domain from fake_tls.py.
     */
    private suspend fun proxyToMaskingDomain(
        clientInput: ByteReadChannel,
        clientOutput: ByteWriteChannel,
        initialData: ByteArray,
        domain: String,
        label: String
    ) {
        val upstream = try {
            withTimeout(15000) {
                val selectorManager = ActorSelectorManager(Dispatchers.IO)
                aSocket(selectorManager).tcp().connect(io.ktor.network.sockets.InetSocketAddress(domain, 443)) {
                    socketTimeout = 15000
                }
            }
        } catch (e: Exception) {
            log("DEBUG", "[$label] masking: cannot connect to $domain:443: $e")
            return
        }

        log("DEBUG", "[$label] masking → $domain:443")
        stats.connectionsMasked.incrementAndGet()

        try {
            val upInput = upstream.openReadChannel()
            val upOutput = upstream.openWriteChannel(autoFlush = true)

            // Send initial data
            if (initialData.isNotEmpty()) {
                withContext(Dispatchers.IO) {
                    upOutput.writeFully(initialData)
                    upOutput.flush()
                }
            }

            coroutineScope {
                launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(16384)
                        while (isActive && !clientInput.isClosedForRead) {
                            val n = clientInput.readAvailable(buf)
                            if (n == -1) break
                            upOutput.writeFully(buf, 0, n)
                            upOutput.flush()
                        }
                    } catch (_: Exception) {}
                }
                launch(Dispatchers.IO) {
                    try {
                        val buf = ByteArray(16384)
                        while (isActive && !upInput.isClosedForRead) {
                            val n = upInput.readAvailable(buf)
                            if (n == -1) break
                            clientOutput.writeFully(buf, 0, n)
                            clientOutput.flush()
                        }
                    } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {
        } finally {
            try { upstream.dispose() } catch (_: Exception) {}
        }
    }

    private suspend fun readBytesWithTimeout(input: ByteReadChannel, len: Int): ByteArray? {
        return try {
            withTimeout(2000) {
                val buf = ByteArray(len)
                input.readFully(buf, 0, len)
                buf
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun hexStringToByteArray(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}


