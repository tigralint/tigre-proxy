package tigralint.tgproxy.proxy

import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.withTimeout
import okhttp3.*
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * WebSocket client wrapper using OkHttp.
 * Port of raw_websocket.py — connects to Telegram's WSS endpoints
 * with proper SNI masking.
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
        // Trust-all SSL context (like Python's ssl.CERT_NONE)
        private val trustAllManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }

        private val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf<TrustManager>(trustAllManager), SecureRandom())
        }

        private val baseClient = OkHttpClient.Builder()
            .sslSocketFactory(sslContext.socketFactory, trustAllManager)
            .hostnameVerifier { _, _ -> true }
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.SECONDS)  // No read timeout for WS
            .pingInterval(30, TimeUnit.SECONDS)
            .build()

        /**
         * Connect to a WebSocket endpoint.
         *
         * @param host The actual IP/hostname to connect to
         * @param domain The SNI domain for TLS and Host header
         * @param timeoutMs Connection timeout in milliseconds
         */
        suspend fun connect(
            host: String,
            domain: String,
            timeoutMs: Long = 10000
        ): ProxyWebSocket = withTimeout(timeoutMs) {
            suspendCancellableCoroutine { cont ->
                val url = "wss://$host/apiws"

                val request = Request.Builder()
                    .url(url)
                    .header("Host", domain)
                    .header("Sec-WebSocket-Protocol", "binary")
                    .header(
                        "User-Agent",
                        "Mozilla/5.0 (Linux; Android 14; Pixel 8) " +
                                "AppleWebKit/537.36 (KHTML, like Gecko) " +
                                "Chrome/131.0.0.0 Mobile Safari/537.36"
                    )
                    .build()

                val recvChannel = Channel<ByteArray>(Channel.UNLIMITED)
                var connected = false

                val ws = baseClient.newWebSocket(request, object : WebSocketListener() {
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
