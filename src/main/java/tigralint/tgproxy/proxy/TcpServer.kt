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
        private const val WS_FAIL_TIMEOUT_MS = 2000L

        /**
         * WebSocket gateway IP — shared by all kws*.web.telegram.org domains.
         * The raw DC IPs (149.154.175.50 etc.) do NOT support WebSocket!
         * Telegram's WS gateway routes to the correct DC based on the domain name
         * (kws1 → DC1, kws2 → DC2, etc.), not by IP.
         */
        private const val WS_GATEWAY_IP = "149.154.167.220"

        /**
         * Default DC-to-IP mappings for WS gateway.
         * Only DC2 and DC4 are supported by the WS gateway 149.154.167.220.
         * DC1/3/5 return 302 redirect loops and must fall through to CF proxy/TCP.
         */
        private val DEFAULT_DC_IPS = mapOf(
            2 to WS_GATEWAY_IP,
            4 to WS_GATEWAY_IP
        )

        /**
         * Map CDN/special DCs to their parent DC.
         *
         * Telegram CDN scheme: DCxxx → DCx via modulo, EXCEPT DC203 which
         * empirically routes to DC2 (not DC3). This was confirmed in previous
         * sessions — DC203 is DC2's CDN media node for CIS users.
         */
        fun effectiveDc(dc: Int): Int = when {
            dc == 203 -> 2   // DC203 = DC2 CDN media (empirically confirmed, NOT dc%100=3!)
            dc > 100 -> dc % 100
            else -> dc
        }
    }

    private var serverSocket: ServerSocket? = null
    private var scope: CoroutineScope? = null
    private var wsPool: WsPool? = null

    private val wsBlacklist = ConcurrentHashMap.newKeySet<String>()
    private val dcFailUntil = ConcurrentHashMap<String, Long>()
    private val replayProtection = ReplayProtection()

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

        // CF Proxy fallback logic
        if (config.fallbackCfProxy) {
            config.initCfProxyDomains()
            // Background domain refresh from GitHub
            serverScope.launch {
                while (isActive) {
                    val fetched = CfProxyManager.fetchDomains()
                    if (fetched.isNotEmpty()) {
                        config.cfProxyDomains = fetched.toMutableList()
                        if (config.cfProxyUserDomain.isEmpty()) {
                            config.activeCfProxyDomain = fetched.random()
                        }
                        log("INFO", "CF proxy domains refreshed: ${fetched.size} domains")
                    }
                    delay(3600_000) // Every hour after initial fetch
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
        val link = config.toTgLink(config.host)
        log("INFO", "Connect: $link")
        log("INFO", "==================================================")
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
                delay(30_000)
                stats.publishSnapshot()
                val bl = wsBlacklist.joinToString(",") { it }.ifEmpty { "none" }
                val cooldowns = dcFailUntil.entries
                    .filter { it.value > System.currentTimeMillis() }
                    .joinToString(",") { "${it.key}:${(it.value - System.currentTimeMillis()) / 1000}s" }
                    .ifEmpty { "none" }
                log("INFO", "stats: ${stats.summary()} | ws_bl=$bl | cooldowns=$cooldowns")
            }
        }

        // Accept loop
        try {
            while (isActive && !server.isClosed) {
                try {
                    val client = server.accept()
                    
                    serverScope.launch(Dispatchers.IO) {
                        try {
                            handleClient(client, secret, pool, this)
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
        replayProtection.clear()
        serverSocket = null
        wsPool = null
        scope = null
        log("INFO", "Server stopped")
    }

    /**
     * Handle a single client connection.
     * Port of _handle_client from tg_ws_proxy.py.
     */
    private suspend fun handleClient(client: Socket, secret: ByteArray, pool: WsPool, clientScope: CoroutineScope) {
        stats.connectionsTotal.incrementAndGet()
        stats.connectionsActive.incrementAndGet()

        val peer = client.remoteAddress.toString()
        var label = peer

        try {
            val input = client.openReadChannel()
            val output = client.openWriteChannel(autoFlush = false)

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
                    log("INFO", "[$label] Fake TLS handshake failed (Invalid HMAC or timestamp) → forwarding to masking domain")
                    // Proxy to masking domain (transparent pass-through)
                    proxyToMaskingDomain(input, output, clientHello, masking, label)
                    return
                }

                log("DEBUG", "[$label] Fake TLS handshake ok (ts=${tlsResult.timestamp})")

                val serverHello = FakeTls.buildServerHello(secret, tlsResult.clientRandom, tlsResult.sessionId)
                output.writeFully(serverHello)
                output.flush()

                // Wrap FakeTls channels (structured concurrency — tied to client lifecycle)
                clientInput = FakeTls.unwrapFakeTls(input, clientScope)
                clientOutput = FakeTls.wrapFakeTls(output, clientScope)

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

            // Replay attack protection: reject handshakes we've already seen.
            // TSPU can capture a valid handshake and replay it to probe our port.
            // Without this check, we'd accept it and reveal ourselves as a proxy.
            if (!replayProtection.checkAndRecord(handshake)) {
                stats.connectionsBad.incrementAndGet()
                log("WARN", "[$label] REPLAY DETECTED — rejecting duplicate handshake nonce")
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

            // Relay proto must match client's proto — we re-encrypt bytes without translating framing.
            // If the client speaks Intermediate, the relay must also speak Intermediate.
            val relayProtoTag = protoTag

            // Generate relay init with the client's protocol
            val relayInit = MtProtoHandshake.generateRelayInit(relayProtoTag, dcIdx)

            // Setup 4 cipher contexts
            val ctx = setupCryptoCtx(clientDecPrekeyIv, secret, relayInit)

            // Resolve effective DC for routing (DC203 → DC2, etc.)
            val effectDc = effectiveDc(dc)
            val dcKey = "$effectDc${if (isMedia) "m" else ""}"

            // === DC ROUTING DECISION ===
            // Only DC2 and DC4 have working WS gateways. DC1/3/5 go straight to fallback.
            var targetIp: String? = config.dcRedirects[effectDc]
            var routingSource = "config"

            if (targetIp == null && effectDc in DEFAULT_DC_IPS) {
                targetIp = DEFAULT_DC_IPS[effectDc]
                config.dcRedirects[effectDc] = targetIp!!
                routingSource = "default"
                log("INFO", "[$label] DC$dc auto-mapped to DC$effectDc ($targetIp) [source=$routingSource]")
            }

            // Note: CF proxy priority is handled inside Bridge.doFallback() —
            // it controls order of fallback methods (CF first vs TCP first),
            // NOT whether to skip WS gateway attempts.

            // Fallback if DC has no WS gateway or is blacklisted
            if (targetIp == null || dcKey in wsBlacklist) {
                if (targetIp == null) {
                    log("INFO", "[$label] DC$dc$mediaTag no WS gateway → fallback")
                } else {
                    log("INFO", "[$label] DC$dc$mediaTag WS blacklisted → fallback")
                }
                val fbSplitter = try { MsgSplitter(relayInit, protoInt) } catch (_: Exception) { null }
                val ok = Bridge.doFallback(
                    clientInput, clientOutput, relayInit, label,
                    dc, isMedia, ctx, fbSplitter, config, stats
                )
                if (!ok) {
                    log("WARN", "[$label] DC$dc$mediaTag no fallback available!")
                }
                return
            }

            // Try WebSocket connection
            val now = System.currentTimeMillis()
            val failUntil = dcFailUntil[dcKey] ?: 0
            val wsTimeout = if (now < failUntil) WS_FAIL_TIMEOUT_MS else 10_000L

            val domains = WsPool.wsDomains(effectDc, isMedia)
            val target = targetIp!!
            var ws: ProxyWebSocket? = null
            var wsFailedRedirect = false
            var allRedirects = true

            log("DEBUG", "[$label] DC$dc$mediaTag routing: target=$target source=$routingSource timeout=${wsTimeout}ms")

            // Try pool first
            ws = pool.get(dc, isMedia, target, domains)
            if (ws != null) {
                log("INFO", "[$label] DC$dc$mediaTag → pool hit via $target")
            } else {
                for ((idx, domain) in domains.withIndex()) {
                    val connStart = System.currentTimeMillis()
                    log("INFO", "[$label] DC$dc$mediaTag → wss://$domain/apiws via $target [${idx+1}/${domains.size}]")
                    try {
                        ws = ProxyWebSocket.connect(target, domain, timeoutMs = wsTimeout, antiDpiEnabled = config.antiDpiEnabled)
                        val connTime = System.currentTimeMillis() - connStart
                        log("INFO", "[$label] DC$dc$mediaTag WS connected in ${connTime}ms")
                        allRedirects = false
                        break
                    } catch (e: WsHandshakeError) {
                        val connTime = System.currentTimeMillis() - connStart
                        stats.wsErrors.incrementAndGet()
                        if (e.isRedirect) {
                            wsFailedRedirect = true
                            log("WARN", "[$label] DC$dc$mediaTag ${e.statusCode} from $domain (${connTime}ms)")
                        } else {
                            allRedirects = false
                            log("WARN", "[$label] DC$dc$mediaTag WS error: ${e.statusLine} (${connTime}ms)")
                        }
                    } catch (e: Exception) {
                        val connTime = System.currentTimeMillis() - connStart
                        stats.wsErrors.incrementAndGet()
                        allRedirects = false
                        log("WARN", "[$label] DC$dc$mediaTag WS failed: ${e::class.simpleName} (${connTime}ms)")
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
                        log("INFO", "[$label] DC$dc$mediaTag WS cooldown ${DC_FAIL_COOLDOWN_MS / 1000}s")
                    }
                }

                val fbSplitter = try { MsgSplitter(relayInit, protoInt) } catch (_: Exception) { null }
                val ok = Bridge.doFallback(
                    clientInput, clientOutput, relayInit, label,
                    dc, isMedia, ctx, fbSplitter, config, stats
                )
                if (!ok) {
                    log("WARN", "[$label] DC$dc$mediaTag no fallback available!")
                }
                return
            }

            dcFailUntil.remove(dcKey)
            stats.connectionsWs.incrementAndGet()

            val wsSplitter = try {
                MsgSplitter(relayInit, protoInt).also {
                    log("DEBUG", "[$label] MsgSplitter activated for proto 0x%08X".format(protoInt))
                }
            } catch (_: Exception) { null }

            // Send relay init to Telegram via WS
            log("DEBUG", "[$label] sending relay_init (${relayInit.size}B) to WS...")
            try {
                ws.send(relayInit)
            } catch (e: Exception) {
                log("ERROR", "[$label] relay_init send FAILED: $e")
                ws.close()
                return
            }
            log("DEBUG", "[$label] relay_init sent, starting bridge...")

            // Start the bidirectional bridge
            Bridge.bridgeWsReencrypt(
                clientInput, clientOutput, ws, label,
                dc, isMedia, ctx, wsSplitter, stats,
                trafficShaping = config.trafficShaping
            )

        } catch (_: kotlinx.coroutines.CancellationException) {
            log("DEBUG", "[$label] cancelled")
        } catch (e: Exception) {
            log("ERROR", "[$label] unexpected: $e")
        } finally {
            stats.connectionsActive.decrementAndGet()
            stats.publishSnapshot()
            try { client.dispose() } catch (_: Exception) {}
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
            val upOutput = upstream.openWriteChannel(autoFlush = false)

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


