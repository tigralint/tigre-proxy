package tigralint.tgproxy.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import tigralint.tgproxy.ui.theme.*
import tigralint.tgproxy.util.AppLogger
import tigralint.tgproxy.util.Texts

@Composable
fun LogsScreen(modifier: Modifier = Modifier) {
    val logs by AppLogger.logsFlow.collectAsState()
    val listState = rememberLazyListState()
    val context = LocalContext.current

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color.Black)
    ) {
        // App Bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 20.dp, vertical = 24.dp)
                .padding(top = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                Texts.logsTitle,
                style = MaterialTheme.typography.displayLarge.copy(fontWeight = FontWeight.Bold),
                color = TextPrimary
            )

            Row {
                IconButton(
                    onClick = {
                        val text = logs.joinToString("\n")
                        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        clipboard.setPrimaryClip(ClipData.newPlainText("logs", text))
                        Toast.makeText(context, Texts.copied, Toast.LENGTH_SHORT).show()
                    },
                    colors = IconButtonDefaults.iconButtonColors(contentColor = TextSecondary)
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = "Copy")
                }
                
                IconButton(
                    onClick = { AppLogger.clear() },
                    colors = IconButtonDefaults.iconButtonColors(contentColor = TextSecondary)
                ) {
                    Icon(Icons.Filled.Delete, contentDescription = "Clear")
                }
            }
        }

        // Logs List
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = Color.Black
        ) {
            LazyColumn(
                state = listState,
                contentPadding = PaddingValues(horizontal = 16.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(logs) { log ->
                    LogItem(log)
                }
                
                if (logs.isEmpty()) {
                    item {
                        Box(modifier = Modifier.fillMaxWidth().padding(40.dp), contentAlignment = Alignment.Center) {
                            Text("No logs", color = TextSecondary)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun LogItem(log: String) {
    val isError = log.contains("] E/")
    val isWarn = log.contains("] W/")
    
    val textColor = when {
        isError -> AppleRed
        isWarn -> AppleOrange
        else -> AppleGreen
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = AppleSurface)
    ) {
        Text(
            text = log,
            fontFamily = JetBrainsMonoFont,
            fontSize = 11.sp,
            color = textColor,
            lineHeight = 14.sp,
            modifier = Modifier.padding(12.dp)
        )
    }
}
