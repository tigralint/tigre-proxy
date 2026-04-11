package tigralint.tgproxy.util

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.*

object AppLogger {
    private const val MAX_LOGS = 1000
    private val rawLogs = mutableListOf<String>()
    
    private val _logsFlow = MutableStateFlow<List<String>>(emptyList())
    val logsFlow: StateFlow<List<String>> = _logsFlow.asStateFlow()

    private val dateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    @Synchronized
    private fun appendLog(level: String, tag: String, message: String) {
        val time = dateFormat.format(Date())
        val formatted = "[$time] $level/$tag: $message"
        rawLogs.add(0, formatted) // newest at top
        if (rawLogs.size > MAX_LOGS) {
            rawLogs.removeLast()
        }
        _logsFlow.value = rawLogs.toList()
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

    @Synchronized
    fun clear() {
        rawLogs.clear()
        _logsFlow.value = emptyList()
    }
}
