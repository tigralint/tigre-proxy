package tigralint.tgproxy.util

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.*

object AppLogger {
    private const val MAX_LOGS = 1000

    /**
     * Using ArrayDeque instead of MutableList for O(1) addFirst.
     * MutableList.add(0, item) does O(N) shift on every log line.
     */
    private val rawLogs = ArrayDeque<String>(MAX_LOGS)
    
    private val _logsFlow = MutableStateFlow<List<String>>(emptyList())
    val logsFlow: StateFlow<List<String>> = _logsFlow.asStateFlow()

    private val dateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    /**
     * Throttle: don't update StateFlow more than once per 100ms.
     * At 200 logs/sec this reduces List copies from 200/sec to 10/sec.
     */
    @Volatile
    private var lastPublishMs = 0L
    private const val PUBLISH_INTERVAL_MS = 100L

    @Synchronized
    private fun appendLog(level: String, tag: String, message: String) {
        val time = dateFormat.format(Date())
        val formatted = "[$time] $level/$tag: $message"
        rawLogs.addFirst(formatted) // O(1) — ArrayDeque
        if (rawLogs.size > MAX_LOGS) {
            rawLogs.removeLast() // O(1) — ArrayDeque
        }
        
        // Throttle StateFlow updates — avoid O(N) toList() on every log
        val now = System.currentTimeMillis()
        if (now - lastPublishMs >= PUBLISH_INTERVAL_MS) {
            lastPublishMs = now
            _logsFlow.value = rawLogs.toList()
        }
    }

    fun d(tag: String, message: String) {
        Log.d(tag, message)
        appendLog("D", tag, message)
    }

    fun w(tag: String, message: String) {
        Log.w(tag, message)
        appendLog("W", tag, message)
    }

    fun e(tag: String, message: String, tr: Throwable? = null) {
        val msg = if (tr != null) "$message\n${Log.getStackTraceString(tr)}" else message
        Log.e(tag, msg)
        appendLog("E", tag, msg)
    }

    fun i(tag: String, message: String) {
        Log.i(tag, message)
        appendLog("I", tag, message)
    }

    /**
     * Force-publish the current log state (call when UI becomes visible).
     */
    fun flush() {
        synchronized(this) {
            _logsFlow.value = rawLogs.toList()
        }
    }

    @Synchronized
    fun clear() {
        rawLogs.clear()
        _logsFlow.value = emptyList()
    }
}
