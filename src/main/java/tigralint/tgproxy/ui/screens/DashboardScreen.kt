package tigralint.tgproxy.ui.screens

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import tigralint.tgproxy.proxy.Constants
import tigralint.tgproxy.proxy.ProxyStats
import tigralint.tgproxy.service.ProxyForegroundService
import tigralint.tgproxy.service.ProxyForegroundService.ProxyStatus
import tigralint.tgproxy.ui.theme.*
import tigralint.tgproxy.util.Texts

@Composable
fun DashboardScreen(
    status: ProxyStatus,
    stats: ProxyStats.Snapshot,
    proxyLink: String,
    onToggleProxy: () -> Unit,
    isBatteryOptimized: Boolean,
    onRequestBatteryOptimization: () -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color.Black) // True pitch black for iOS Dark Mode
            .padding(horizontal = 20.dp)
            .verticalScroll(scrollState),
        horizontalAlignment = Alignment.Start
    ) {
        Spacer(modifier = Modifier.height(32.dp))
        
        Text(
            Texts.dashboard,
            style = MaterialTheme.typography.displayLarge.copy(fontWeight = FontWeight.Bold),
            color = TextPrimary
        )

        Spacer(modifier = Modifier.height(24.dp))

        if (isBatteryOptimized) {
            Card(
                colors = CardDefaults.cardColors(containerColor = AppleSurface),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth().padding(bottom = 24.dp),
                onClick = onRequestBatteryOptimization
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Filled.Warning, null, tint = AppleOrange, modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(
                            "Внимание! Ограничения фона",
                            style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.Bold),
                            color = AppleOrange
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            "Нажмите здесь, чтобы отключить выгрузку прокси из памяти",
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextSecondary
                        )
                    }
                }
            }
        }

        // Central Status Indicator (Apple Style)
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = AppleSurface)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Icon(
                    imageVector = when (status) {
                        ProxyStatus.RUNNING -> Icons.Filled.CheckCircle
                        ProxyStatus.STOPPED -> Icons.Filled.PauseCircle
                        ProxyStatus.STARTING -> Icons.Filled.Sync
                        ProxyStatus.ERROR -> Icons.Filled.Error
                    },
                    contentDescription = null,
                    tint = when (status) {
                        ProxyStatus.RUNNING -> AppleGreen
                        ProxyStatus.STOPPED -> TextSecondary
                        ProxyStatus.STARTING -> AppleOrange
                        ProxyStatus.ERROR -> AppleRed
                    },
                    modifier = Modifier.size(64.dp)
                )

                Spacer(modifier = Modifier.height(16.dp))

                Text(
                    text = when (status) {
                        ProxyStatus.RUNNING -> Texts.proxyActive
                        ProxyStatus.STOPPED -> Texts.proxyStopped
                        ProxyStatus.STARTING -> Texts.starting
                        ProxyStatus.ERROR -> Texts.error
                    },
                    style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.SemiBold),
                    color = TextPrimary
                )
                
                Spacer(modifier = Modifier.height(24.dp))

                val context = LocalContext.current
                Button(
                    onClick = onToggleProxy,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(50.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = if (status == ProxyStatus.RUNNING) AppleSurfaceVariant else AppleBlue,
                        contentColor = if (status == ProxyStatus.RUNNING) AppleRed else Color.White
                    )
                ) {
                    Text(
                        text = if (status == ProxyStatus.RUNNING) Texts.stopProxy else Texts.startProxy,
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        // Traffic Stats (iOS Grouped Style)
        Text(
            Texts.trafficUsed,
            style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold),
            color = TextSecondary,
            modifier = Modifier.padding(bottom = 8.dp, start = 16.dp)
        )
        
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = AppleSurface)
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                // Uploaded Row
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(30.dp)
                                .background(AppleBlue.copy(alpha = 0.2f), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Outlined.ArrowUpward, null, tint = AppleBlue, modifier = Modifier.size(18.dp))
                        }
                        Spacer(modifier = Modifier.width(16.dp))
                        Text(Texts.uploaded, color = TextPrimary, style = MaterialTheme.typography.bodyLarge)
                    }
                    Text(Constants.humanBytes(stats.bytesUp), color = TextSecondary, style = MaterialTheme.typography.bodyLarge)
                }

                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(start = 62.dp))

                // Downloaded Row
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(30.dp)
                                .background(AppleGreen.copy(alpha = 0.2f), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(Icons.Outlined.ArrowDownward, null, tint = AppleGreen, modifier = Modifier.size(18.dp))
                        }
                        Spacer(modifier = Modifier.width(16.dp))
                        Text(Texts.downloaded, color = TextPrimary, style = MaterialTheme.typography.bodyLarge)
                    }
                    Text(Constants.humanBytes(stats.bytesDown), color = TextSecondary, style = MaterialTheme.typography.bodyLarge)
                }
            }
        }

        if (status == ProxyStatus.RUNNING && proxyLink.isNotEmpty()) {
            Spacer(modifier = Modifier.height(32.dp))
            ProxyLinkCard(link = proxyLink)
        }
        
        Spacer(modifier = Modifier.height(40.dp))
    }
}

@Composable
fun ProxyLinkCard(link: String) {
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    var copied by remember { mutableStateOf(false) }

    Text(
        Texts.proxyLink,
        style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold),
        color = TextSecondary,
        modifier = Modifier.padding(bottom = 8.dp, start = 16.dp)
    )
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = AppleSurface)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            // Link Box
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(Color.Black, RoundedCornerShape(8.dp))
                    .padding(12.dp)
            ) {
                Text(
                    link,
                    style = MaterialTheme.typography.bodyMedium.copy(fontFamily = JetBrainsMonoFont),
                    color = AppleBlue,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Buttons
            Button(
                onClick = {
                    try {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(link))
                        context.startActivity(intent)
                    } catch (e: Exception) {
                        Toast.makeText(context, Texts.noTelegram, Toast.LENGTH_SHORT).show()
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = AppleBlue, contentColor = Color.White)
            ) {
                Icon(Icons.Filled.Send, null, modifier = Modifier.size(20.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(Texts.openInTelegram, style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold))
            }

            Spacer(modifier = Modifier.height(12.dp))

            Button(
                onClick = {
                    clipboardManager.setText(AnnotatedString(link))
                    copied = true
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(50.dp),
                shape = RoundedCornerShape(12.dp),
                colors = ButtonDefaults.buttonColors(containerColor = AppleSurfaceVariant, contentColor = if (copied) AppleGreen else TextPrimary)
            ) {
                Icon(if (copied) Icons.Filled.Check else Icons.Outlined.ContentCopy, null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(if (copied) Texts.copied else Texts.copy, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
