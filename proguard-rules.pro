# ProGuard rules for Tigre Proxy

# OkHttp — standard rules (don't keep everything, just what's needed)
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# OkIO
-dontwarn okio.**

# Keep WebSocket listener callbacks (used via reflection by OkHttp)
-keep class tigralint.tgproxy.proxy.ProxyWebSocket$Companion$connect$* { *; }

# Keep crypto classes
-keep class javax.crypto.** { *; }

# Keep R8 from stripping Kotlin coroutines internals
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
