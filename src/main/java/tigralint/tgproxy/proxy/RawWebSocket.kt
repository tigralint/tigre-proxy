package tigralint.tgproxy.proxy

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.withTimeout
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

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
    private val recvChannel: Channel<ByteArray>
) {
    @Volatile
    private var closed = false

    /** Send binary data as a WebSocket frame. */
    suspend fun send(data: ByteArray) {
        if (closed) throw ConnectionException("WebSocket closed")
        ws.send(data.toByteString())
    }

    /** Send multiple binary frames in batch. */
    suspend fun sendBatch(parts: List<ByteArray>) {
        if (closed) throw ConnectionException("WebSocket closed")
        for (part in parts) {
            ws.send(part.toByteString())
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

    val isClosed: Boolean get() = closed

    class ConnectionException(message: String) : Exception(message)

    companion object {

        /**
         * OkHttp client with Conscrypt (BoringSSL) TLS and DoH DNS.
         *
         * Key anti-DPI properties:
         * - SSLSocketFactory from Conscrypt → Chrome-like cipher suites, extensions, ALPN
         * - DNS-over-HTTPS → enables ECH (Encrypted Client Hello) on Cloudflare
         * - HTTP/2 protocol → WebSocket muxed as H2 stream when server supports RFC 8441
         * - Trust-all certs → needed for connecting to Telegram IPs with different SNI
         */
        private val antiDpiClient: OkHttpClient by lazy {
            val (sslFactory, trustManager) = AntiDpi.createConscryptSslContext()
            OkHttpClient.Builder()
                .sslSocketFactory(sslFactory, trustManager)
                .hostnameVerifier { _, _ -> true }
                .dns(AntiDpi.DohDns()) // DNS-over-HTTPS for ECH support
                .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.SECONDS)  // No read timeout for WS
                .pingInterval(30, TimeUnit.SECONDS)
                .build()
        }

        /**
         * Legacy OkHttp client without anti-DPI (fallback).
         */
        private val legacyClient: OkHttpClient by lazy {
            val (sslFactory, trustManager) = AntiDpi.createConscryptSslContext()
            OkHttpClient.Builder()
                .sslSocketFactory(sslFactory, trustManager)
                .hostnameVerifier { _, _ -> true }
                .connectTimeout(10, TimeUnit.SECONDS)
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
                val url = "wss://$host/apiws"
                val client = if (antiDpiEnabled) antiDpiClient else legacyClient

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
                val recvChannel = Channel<ByteArray>(Channel.UNLIMITED)
                var connected = false

                val ws = client.newWebSocket(request, object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        connected = true
                        val proxy = ProxyWebSocket(webSocket, recvChannel)
                        cont.resume(proxy)
                    }

                    override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                        recvChannel.trySend(bytes.toByteArray())
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        if (!connected) {
                            val statusCode = response?.code ?: 0
                            val location = response?.header("Location")
                            cont.resumeWithException(
                                WsHandshakeError(statusCode, t.message ?: "Connection failed", location)
                            )
                        }
                        recvChannel.close()
                    }

                    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                        recvChannel.close()
                        webSocket.close(code, reason)
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
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

