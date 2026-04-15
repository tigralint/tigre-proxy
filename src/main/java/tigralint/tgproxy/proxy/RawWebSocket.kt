package tigralint.tgproxy.proxy

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.withTimeout
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier

/**
 * WebSocket client wrapper using OkHttp + Conscrypt (BoringSSL).
 * Port of raw_websocket.py — connects to Telegram's WSS endpoints
 * with proper SNI masking and anti-DPI countermeasures.
 *
 * Anti-DPI features:
 * - Conscrypt (BoringSSL) TLS engine → Chrome-like JA3/JA4 fingerprint
 * - DNS-over-HTTPS resolver → ECH (Encrypted Client Hello) support
 * - Random padding HTTP headers → breaks packet-size signatures
 * - HTTP/2 protocol preference → avoids detectable HTTP/1.1 Upgrade pattern
 */
class ProxyWebSocket private constructor(
    private val ws: WebSocket,
    private val recvChannel: Channel<ByteArray>,
    private val isDead: java.util.concurrent.atomic.AtomicBoolean
) {
    @Volatile
    private var closed = false

    /** Send binary data as a WebSocket frame. */
    suspend fun send(data: ByteArray) {
        if (closed) throw ConnectionException("WebSocket closed")
        try {
            if (!ws.send(data.toByteString())) {
                throw ConnectionException("WebSocket send queue full or closing")
            }
        } catch (e: Exception) {
            closed = true
            throw ConnectionException("WebSocket send failed: ${e.message}")
        }
    }

    /**
     * Send a slice of a buffer as a WebSocket frame.
     * Avoids the double-copy of copyOfRange() + toByteString() by using
     * ByteString.of(buf, offset, length) which does a single copy.
     */
    suspend fun sendDirect(buf: ByteArray, offset: Int, length: Int) {
        if (closed) throw ConnectionException("WebSocket closed")
        try {
            val bs = buf.toByteString(offset, length)
            if (!ws.send(bs)) {
                throw ConnectionException("WebSocket send queue full or closing")
            }
        } catch (e: Exception) {
            closed = true
            throw ConnectionException("WebSocket send failed: ${e.message}")
        }
    }

    /** Send multiple binary frames in batch. */
    suspend fun sendBatch(parts: List<ByteArray>) {
        if (closed) throw ConnectionException("WebSocket closed")
        try {
            for (part in parts) {
                if (!ws.send(part.toByteString())) {
                    throw ConnectionException("WebSocket send queue full or closing")
                }
            }
        } catch (e: Exception) {
            closed = true
            throw ConnectionException("WebSocket send failed: ${e.message}")
        }
    }

    /**
     * Receive the next binary message.
     * Returns null if the WebSocket was closed.
     */
    suspend fun recv(): ByteArray? {
        if (closed) return null
        return try {
            recvChannel.receive()
        } catch (_: ClosedReceiveChannelException) {
            null
        }
    }

    /** Close the WebSocket connection. */
    fun close() {
        if (closed) return
        closed = true
        try {
            ws.close(1000, null)
        } catch (_: Exception) {}
        recvChannel.close()
    }

    val isClosed: Boolean get() = closed || isDead.get()

    /** True if the receive channel has no buffered data (all frames consumed). */
    val isRecvEmpty: Boolean get() = recvChannel.isEmpty

    class ConnectionException(message: String) : Exception(message)

    companion object {

        /**
         * Shared connection pool and dispatcher for all per-request OkHttp clients.
         *
         * Without sharing, each `newBuilder().dns(pinnedDns).build()` would
         * create independent pools/dispatchers — leading to thread leak and
         * connection sprawl on mobile devices with limited resources.
         */
        private val sharedPool = ConnectionPool(32, 2, TimeUnit.MINUTES)
        private val sharedDispatcher = Dispatcher()

        /**
         * Dual-mode hostname verifier for Telegram + CF proxy connections.
         *
         * 1. First tries standard hostname verification (covers CF proxy,
         *    CF DNS proxy domains, and any domain where URL matches the cert).
         * 2. Falls back to checking for *.telegram.org in SAN — covers
         *    edge cases where DNS-pinning routes to a gateway whose cert
         *    may not exactly match the kws{N} subdomain we're requesting.
         *
         * This replaces the old `hostnameVerifier { _, _ -> true }` which
         * was completely MITM-vulnerable.
         */
        private val telegramHostnameVerifier = HostnameVerifier { hostname, session ->
            try {
                // Standard verification: works for CF proxy and direct Telegram domains
                val defaultVerifier = javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier()
                if (defaultVerifier.verify(hostname, session)) return@HostnameVerifier true

                // Telegram-specific fallback: accept certs with *.telegram.org SAN
                val certs = session.peerCertificates
                certs.any { cert ->
                    (cert as? X509Certificate)?.subjectAlternativeNames?.any { san ->
                        val name = san[1].toString()
                        name.endsWith(".telegram.org") || name == "telegram.org"
                    } == true
                }
            } catch (_: Exception) {
                false
            }
        }

        /**
         * OkHttp client with Conscrypt (BoringSSL) TLS and DoH DNS.
         *
         * Key anti-DPI properties:
         * - SSLSocketFactory from Conscrypt → Chrome-like cipher suites, extensions, ALPN
         * - DNS-over-HTTPS → enables ECH (Encrypted Client Hello) on Cloudflare
         * - HTTP/2 protocol → WebSocket muxed as H2 stream when server supports RFC 8441
         * - Telegram cert pinning → accepts only certs with *.telegram.org SAN
         */
        private val antiDpiClient: OkHttpClient by lazy {
            val (sslFactory, trustManager) = AntiDpi.createTrustAllConscryptSslContext()
            OkHttpClient.Builder()
                .sslSocketFactory(TlsRecordSplittingFactory(sslFactory), trustManager) // TLS Record Splitting for DPI bypass
                .hostnameVerifier(telegramHostnameVerifier) // Telegram cert pinning (not trust-all!)
                .dns(AntiDpi.DohDns()) // DNS-over-HTTPS for ECH support
                .connectionPool(sharedPool)
                .dispatcher(sharedDispatcher)
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .connectTimeout(7, TimeUnit.SECONDS) // 7s optimal for mobile (was 10s)
                .readTimeout(0, TimeUnit.SECONDS)  // No read timeout for WS
                .pingInterval(30, TimeUnit.SECONDS)
                .build()
        }

        /**
         * Legacy OkHttp client without anti-DPI (fallback for direct IPs).
         * Uses Trust-All because SNI won't match the IP's certificate.
         */
        private val legacyClient: OkHttpClient by lazy {
            val (sslFactory, trustManager) = AntiDpi.createTrustAllConscryptSslContext()
            OkHttpClient.Builder()
                .sslSocketFactory(sslFactory, trustManager)
                .hostnameVerifier(telegramHostnameVerifier) // Telegram cert pinning
                .connectionPool(sharedPool)
                .dispatcher(sharedDispatcher)
                .connectTimeout(7, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.SECONDS)
                .pingInterval(30, TimeUnit.SECONDS)
                .build()
        }

        /**
         * Connect to a WebSocket endpoint with anti-DPI countermeasures.
         *
         * @param host The actual IP/hostname to connect to
         * @param domain The SNI domain for TLS and Host header
         * @param timeoutMs Connection timeout in milliseconds
         * @param antiDpiEnabled Whether to apply anti-DPI countermeasures
         */
        suspend fun connect(
            host: String,
            domain: String,
            timeoutMs: Long = 10000,
            antiDpiEnabled: Boolean = true
        ): ProxyWebSocket = withTimeout(timeoutMs) {
            suspendCancellableCoroutine { cont ->
                // Use domain in URL for correct TLS SNI, but override DNS
                // to resolve domain → target IP. This ensures:
                // 1. TLS ClientHello has SNI = kws2.web.telegram.org (correct for Telegram)
                // 2. TCP connects to target IP (149.154.167.220), not DNS-resolved IP
                // For CF proxy: host == domain (e.g. kws1.pclead.co.uk), DNS resolves normally.
                val url = "wss://$domain/apiws"

                // Create a per-request client with DNS pinned to target IP.
                // Pool/dispatcher are shared via the base client — newBuilder()
                // inherits them, so we only override DNS resolution.
                val targetAddr = InetAddress.getByName(host)
                val pinnedDns = object : Dns {
                    override fun lookup(hostname: String): List<InetAddress> = listOf(targetAddr)
                }
                val baseClient = if (antiDpiEnabled) antiDpiClient else legacyClient
                val client = baseClient.newBuilder()
                    .dns(pinnedDns)
                    .connectionPool(sharedPool)
                    .dispatcher(sharedDispatcher)
                    .build()

                val requestBuilder = Request.Builder()
                    .url(url)
                    .header("Host", domain)
                    .header("Sec-WebSocket-Protocol", "binary")

                if (antiDpiEnabled) {
                    // Apply anti-DPI padding headers
                    val paddingHeaders = AntiDpi.generatePaddingHeaders()
                    for ((key, value) in paddingHeaders) {
                        requestBuilder.header(key, value)
                    }
                } else {
                    // Minimal headers without padding
                    requestBuilder.header(
                        "User-Agent",
                        AntiDpi.randomUserAgent()
                    )
                }

                val request = requestBuilder.build()
                // UNLIMITED capacity: OkHttp already limits each WS to 16MB output buffer.
                // Bounded channels (64) caused either:
                //   - trySend drop → connection kill → media never loads
                //   - runBlocking → OkHttp thread pool deadlock (5 threads, 13+ connections)
                // UNLIMITED + trySend never blocks OkHttp reader threads.
                val recvChannel = Channel<ByteArray>(Channel.UNLIMITED)
                val isDead = java.util.concurrent.atomic.AtomicBoolean(false)
                var connected = false

                val ws = client.newWebSocket(request, object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        connected = true
                        val proxy = ProxyWebSocket(webSocket, recvChannel, isDead)
                        cont.resume(proxy)
                    }

                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        // Never block OkHttp reader threads!
                        // With UNLIMITED channel, trySend always succeeds.
                        // Memory is bounded by OkHttp's own 16MB per-WS receive buffer.
                        recvChannel.trySend(bytes.toByteArray())
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        isDead.set(true)
                        if (!connected) {
                            val statusCode = response?.code ?: 0
                            val location = response?.header("Location")
                            cont.resumeWithException(
                                WsHandshakeError(statusCode, t.message ?: "Connection failed", location)
                            )
                        }
                        recvChannel.close() // recv() will return null → bridge loop exits
                    }

                    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                        isDead.set(true)
                        recvChannel.close()
                        webSocket.close(code, reason)
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        isDead.set(true)
                        recvChannel.close()
                    }
                })

                cont.invokeOnCancellation {
                    ws.cancel()
                    recvChannel.close()
                }
            }
        }
    }
}

/**
 * WebSocket handshake error, indicating connection failure.
 */
class WsHandshakeError(
    val statusCode: Int,
    val statusLine: String,
    val location: String? = null
) : Exception("WS handshake failed: HTTP $statusCode $statusLine") {
    val isRedirect: Boolean get() = statusCode in listOf(301, 302, 303, 307, 308)
}

