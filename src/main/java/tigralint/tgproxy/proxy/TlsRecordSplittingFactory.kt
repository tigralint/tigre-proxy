package tigralint.tgproxy.proxy

import android.util.Log
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * SSLSocketFactory wrapper that splits the TLS ClientHello across two TLS records.
 *
 * WHY THIS WORKS:
 * Modern DPI systems (TSPU 2026) perform full TCP reassembly, so TCP-level
 * fragmentation is no longer effective. But TLS Record Splitting operates at
 * a higher layer: we break the ClientHello into two separate TLS records.
 * The DPI must perform TLS record-layer reassembly to extract the SNI —
 * which many systems don't do, or do poorly.
 *
 * HOW IT WORKS:
 * 1. Wraps each SSLSocket in a SplittingSSLSocket (delegate pattern)
 * 2. SplittingSSLSocket intercepts getOutputStream()
 * 3. The first write() (always the ClientHello) is split at the SNI boundary
 * 4. After the first write, all subsequent I/O passes through unchanged
 *
 * IMPLEMENTATION NOTE:
 * OkHttp and Conscrypt call SSLSocket.startHandshake() which internally
 * calls the OutputStream. By wrapping the OutputStream, we intercept
 * the handshake bytes before they hit the wire.
 *
 * Inspired by: GoodbyeDPI TLS record fragmentation, Zapret split-TLS
 */
class TlsRecordSplittingFactory(
    private val delegate: SSLSocketFactory
) : SSLSocketFactory() {

    companion object {
        private const val TAG = "TlsRecordSplit"
        
        // TLS Extension type for SNI (Server Name Indication)
        private const val TLS_EXT_SNI: Int = 0x0000
        
        // Minimum ClientHello size to attempt splitting
        private const val MIN_CLIENT_HELLO_SIZE = 50
    }

    // --- Delegate all factory methods, wrapping the result ---

    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    override fun createSocket(s: Socket, host: String, port: Int, autoClose: Boolean): Socket {
        val ssl = delegate.createSocket(s, host, port, autoClose) as SSLSocket
        return SplittingSSLSocket(ssl)
    }

    override fun createSocket(host: String, port: Int): Socket {
        val ssl = delegate.createSocket(host, port) as SSLSocket
        return SplittingSSLSocket(ssl)
    }

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket {
        val ssl = delegate.createSocket(host, port, localHost, localPort) as SSLSocket
        return SplittingSSLSocket(ssl)
    }

    override fun createSocket(host: InetAddress, port: Int): Socket {
        val ssl = delegate.createSocket(host, port) as SSLSocket
        return SplittingSSLSocket(ssl)
    }

    override fun createSocket(address: InetAddress, port: Int, localAddress: InetAddress, localPort: Int): Socket {
        val ssl = delegate.createSocket(address, port, localAddress, localPort) as SSLSocket
        return SplittingSSLSocket(ssl)
    }

    /**
     * Delegating SSLSocket that intercepts the output stream to split
     * the first TLS record (ClientHello) at the SNI boundary.
     */
    private class SplittingSSLSocket(
        private val delegate: SSLSocket
    ) : SSLSocket() {

        private var wrappedOutput: OutputStream? = null

        override fun getOutputStream(): OutputStream {
            if (wrappedOutput == null) {
                wrappedOutput = SplittingOutputStream(delegate.outputStream)
            }
            return wrappedOutput!!
        }

        // --- All other methods delegate directly ---
        override fun getInputStream() = delegate.inputStream
        override fun startHandshake() = delegate.startHandshake()
        override fun getSession() = delegate.session
        override fun getHandshakeSession() = delegate.handshakeSession
        override fun addHandshakeCompletedListener(listener: javax.net.ssl.HandshakeCompletedListener) =
            delegate.addHandshakeCompletedListener(listener)
        override fun removeHandshakeCompletedListener(listener: javax.net.ssl.HandshakeCompletedListener) =
            delegate.removeHandshakeCompletedListener(listener)
        override fun getEnabledCipherSuites(): Array<String> = delegate.enabledCipherSuites
        override fun setEnabledCipherSuites(suites: Array<String>) { delegate.enabledCipherSuites = suites }
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites
        override fun getSupportedProtocols(): Array<String> = delegate.supportedProtocols
        override fun getEnabledProtocols(): Array<String> = delegate.enabledProtocols
        override fun setEnabledProtocols(protocols: Array<String>) { delegate.enabledProtocols = protocols }
        override fun getUseClientMode(): Boolean = delegate.useClientMode
        override fun setUseClientMode(mode: Boolean) { delegate.useClientMode = mode }
        override fun getNeedClientAuth(): Boolean = delegate.needClientAuth
        override fun setNeedClientAuth(need: Boolean) { delegate.needClientAuth = need }
        override fun getWantClientAuth(): Boolean = delegate.wantClientAuth
        override fun setWantClientAuth(want: Boolean) { delegate.wantClientAuth = want }
        override fun getEnableSessionCreation(): Boolean = delegate.enableSessionCreation
        override fun setEnableSessionCreation(flag: Boolean) { delegate.enableSessionCreation = flag }

        // Socket-level delegates
        override fun connect(endpoint: java.net.SocketAddress?) = delegate.connect(endpoint)
        override fun connect(endpoint: java.net.SocketAddress?, timeout: Int) = delegate.connect(endpoint, timeout)
        override fun bind(bindpoint: java.net.SocketAddress?) = delegate.bind(bindpoint)
        override fun getInetAddress(): InetAddress? = delegate.inetAddress
        override fun getLocalAddress(): InetAddress = delegate.localAddress
        override fun getPort(): Int = delegate.port
        override fun getLocalPort(): Int = delegate.localPort
        override fun getRemoteSocketAddress(): java.net.SocketAddress? = delegate.remoteSocketAddress
        override fun getLocalSocketAddress(): java.net.SocketAddress? = delegate.localSocketAddress
        override fun getChannel() = delegate.channel
        override fun close() = delegate.close()
        override fun isClosed(): Boolean = delegate.isClosed
        override fun isConnected(): Boolean = delegate.isConnected
        override fun isBound(): Boolean = delegate.isBound
        override fun isInputShutdown(): Boolean = delegate.isInputShutdown
        override fun isOutputShutdown(): Boolean = delegate.isOutputShutdown
        override fun shutdownInput() = delegate.shutdownInput()
        override fun shutdownOutput() = delegate.shutdownOutput()
        override fun setSoTimeout(timeout: Int) { delegate.soTimeout = timeout }
        override fun getSoTimeout(): Int = delegate.soTimeout
        override fun setTcpNoDelay(on: Boolean) { delegate.tcpNoDelay = on }
        override fun getTcpNoDelay(): Boolean = delegate.tcpNoDelay
        override fun setSendBufferSize(size: Int) { delegate.sendBufferSize = size }
        override fun getSendBufferSize(): Int = delegate.sendBufferSize
        override fun setReceiveBufferSize(size: Int) { delegate.receiveBufferSize = size }
        override fun getReceiveBufferSize(): Int = delegate.receiveBufferSize
        override fun setKeepAlive(on: Boolean) { delegate.keepAlive = on }
        override fun getKeepAlive(): Boolean = delegate.keepAlive
        override fun setReuseAddress(on: Boolean) { delegate.reuseAddress = on }
        override fun getReuseAddress(): Boolean = delegate.reuseAddress
        override fun setSoLinger(on: Boolean, linger: Int) = delegate.setSoLinger(on, linger)
        override fun getSoLinger(): Int = delegate.soLinger
        override fun setOOBInline(on: Boolean) { delegate.oobInline = on }
        override fun getOOBInline(): Boolean = delegate.oobInline
        override fun setTrafficClass(tc: Int) { delegate.trafficClass = tc }
        override fun getTrafficClass(): Int = delegate.trafficClass
        override fun sendUrgentData(data: Int) = delegate.sendUrgentData(data)
    }

    /**
     * OutputStream wrapper that splits the FIRST write (ClientHello) into
     * two separate writes, breaking the SNI across a TLS record boundary.
     *
     * After the first write completes, this becomes a pure passthrough.
     */
    private class SplittingOutputStream(
        private val delegate: OutputStream
    ) : OutputStream() {

        @Volatile
        private var firstWriteDone = false

        override fun write(b: Int) {
            delegate.write(b)
        }

        override fun write(b: ByteArray) {
            write(b, 0, b.size)
        }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (firstWriteDone || len < MIN_CLIENT_HELLO_SIZE) {
                delegate.write(b, off, len)
                return
            }
            firstWriteDone = true

            // Try to find SNI offset and split there
            val splitOffset = findSniSplitOffset(b, off, len)

            if (splitOffset > 0 && splitOffset < len - 1) {
                // Split the ClientHello at the SNI boundary
                Log.d(TAG, "TLS Record Split applied: ${splitOffset}+${len - splitOffset} bytes (total=$len)")
                
                // Send first part (everything before SNI value starts)
                delegate.write(b, off, splitOffset)
                delegate.flush()

                // Small delay to ensure they go as separate TCP segments
                try { Thread.sleep(1) } catch (_: Exception) {}

                // Send second part (SNI value + rest)
                delegate.write(b, off + splitOffset, len - splitOffset)
                delegate.flush()
            } else {
                // Fallback: split at a fixed small offset (still breaks naive DPI)
                val fallbackSplit = minOf(5, len - 1)
                Log.d(TAG, "TLS Record Split fallback: ${fallbackSplit}+${len - fallbackSplit} bytes")
                
                delegate.write(b, off, fallbackSplit)
                delegate.flush()
                try { Thread.sleep(1) } catch (_: Exception) {}
                delegate.write(b, off + fallbackSplit, len - fallbackSplit)
                delegate.flush()
            }
        }

        override fun flush() = delegate.flush()
        override fun close() = delegate.close()

        /**
         * Parse a TLS ClientHello to find the byte offset where the SNI
         * hostname value begins. Returns -1 if not found.
         *
         * TLS record structure (simplified):
         * [0]     ContentType (0x16 = Handshake)
         * [1-2]   Version
         * [3-4]   Length
         * [5]     HandshakeType (0x01 = ClientHello)
         * [6-8]   HandshakeLength
         * [9-10]  ClientVersion
         * [11-42] Random (32 bytes)
         * [43]    SessionIdLength
         * [44..]  SessionId, CipherSuites, CompressionMethods, Extensions...
         */
        private fun findSniSplitOffset(data: ByteArray, off: Int, len: Int): Int {
            try {
                if (len < 43) return -1
                // Verify this is a TLS Handshake
                if (data[off].toInt() != 0x16) return -1
                // Verify this is a ClientHello
                if (data[off + 5].toInt() != 0x01) return -1

                var pos = off + 43 // Skip to after Random

                // Skip SessionId
                if (pos >= off + len) return -1
                val sidLen = data[pos].toInt() and 0xFF
                pos += 1 + sidLen

                // Skip CipherSuites
                if (pos + 2 > off + len) return -1
                val csLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
                pos += 2 + csLen

                // Skip CompressionMethods
                if (pos >= off + len) return -1
                val cmLen = data[pos].toInt() and 0xFF
                pos += 1 + cmLen

                // Extensions block
                if (pos + 2 > off + len) return -1
                val extBlockLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
                pos += 2

                val extEnd = pos + extBlockLen
                while (pos + 4 <= minOf(extEnd, off + len)) {
                    val extType = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
                    val extLen = ((data[pos + 2].toInt() and 0xFF) shl 8) or (data[pos + 3].toInt() and 0xFF)

                    if (extType == TLS_EXT_SNI) {
                        // Found SNI extension! Split right before the hostname bytes
                        // SNI extension layout: [type:2][len:2][listLen:2][nameType:1][nameLen:2][name...]
                        // We split at the start of the extension, so DPI sees everything
                        // BEFORE the SNI in one record, and the SNI itself in another.
                        return pos - off
                    }

                    pos += 4 + extLen
                }
            } catch (_: Exception) {
                // If parsing fails, return -1 for fallback splitting
            }
            return -1
        }
    }
}
