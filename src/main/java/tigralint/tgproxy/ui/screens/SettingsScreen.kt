package tigralint.tgproxy.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import tigralint.tgproxy.proxy.ProxyConfig
import tigralint.tgproxy.ui.theme.*
import tigralint.tgproxy.util.Texts

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    config: ProxyConfig,
    isRunning: Boolean,
    onSave: (ProxyConfig) -> Unit,
    onRequestBatteryOptimization: () -> Unit,
    isBatteryOptimized: Boolean,
    hasAutoStart: Boolean,
    onRequestAutoStart: () -> Unit,
    modifier: Modifier = Modifier
) {
    var secret by remember(config) { mutableStateOf(config.secret) }
    var port by remember(config) { mutableStateOf(config.port.toString()) }
    var fakeTlsDomain by remember(config) { mutableStateOf(config.fakeTlsDomain) }
    var antiBlockEnabled by remember(config) { mutableStateOf(config.fallbackCfProxy) }
    var cfPriorityEnabled by remember(config) { mutableStateOf(config.fallbackCfProxyPriority) }
    var cfProxyDomain by remember(config) { mutableStateOf(config.cfProxyUserDomain) }
    var dcIps by remember(config) {
        mutableStateOf(config.dcRedirects.entries.joinToString("\n") { "${it.key}:${it.value}" })
    }
    
    var antiDpiEnabled by remember(config) { mutableStateOf(config.antiDpiEnabled) }
    var dohEnabled by remember(config) { mutableStateOf(config.dohEnabled) }
    var trafficShaping by remember(config) { mutableStateOf(config.trafficShaping) }
    
    var showAdvanced by remember { mutableStateOf(false) }

    val scrollState = rememberScrollState()

    Column(
        modifier = modifier
            .fillMaxSize()
            .background(Color.Black)
            .verticalScroll(scrollState)
            .padding(horizontal = 20.dp),
        horizontalAlignment = Alignment.Start
    ) {
        Spacer(modifier = Modifier.height(32.dp))
        
        Text(
            Texts.settings,
            style = MaterialTheme.typography.displayLarge.copy(fontWeight = FontWeight.Bold),
            color = TextPrimary
        )

        Spacer(modifier = Modifier.height(32.dp))

        if (isRunning) {
            Card(
                colors = CardDefaults.cardColors(containerColor = AppleSurface),
                shape = RoundedCornerShape(12.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Filled.Warning, null, tint = AppleOrange, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(
                        Texts.stopToChange,
                        style = MaterialTheme.typography.bodyMedium,
                        color = AppleOrange
                    )
                }
            }
            Spacer(modifier = Modifier.height(24.dp))
        }

        // --- GENERAL SECTION ---
        Text(
            Texts.antiBlock.uppercase(),
            style = MaterialTheme.typography.labelMedium,
            color = TextSecondary,
            modifier = Modifier.padding(bottom = 8.dp, start = 16.dp)
        )
        Card(
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = AppleSurface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(Texts.antiBlock, style = MaterialTheme.typography.bodyLarge, color = TextPrimary)
                Switch(
                    checked = antiBlockEnabled,
                    onCheckedChange = { antiBlockEnabled = it },
                    enabled = !isRunning,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = AppleGreen,
                        uncheckedThumbColor = Color.White,
                        uncheckedTrackColor = AppleSurfaceVariant
                    )
                )
            }
        }
        
        Text(
            Texts.antiBlockDesc,
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary,
            modifier = Modifier.padding(top = 8.dp, start = 16.dp, bottom = 12.dp)
        )

        Card(
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = AppleSurface)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(Texts.cfPriority, style = MaterialTheme.typography.bodyLarge, color = TextPrimary)
                Switch(
                    checked = cfPriorityEnabled,
                    onCheckedChange = { cfPriorityEnabled = it },
                    enabled = !isRunning && antiBlockEnabled,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = Color.White,
                        checkedTrackColor = AppleGreen,
                        uncheckedThumbColor = Color.White,
                        uncheckedTrackColor = AppleSurfaceVariant
                    )
                )
            }
        }

        Text(
            Texts.cfPriorityDesc,
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary,
            modifier = Modifier.padding(top = 8.dp, start = 16.dp, bottom = 24.dp)
        )

        // --- ANTI-DPI SECTION ---
        Text(
            Texts.antiDpi.uppercase(),
            style = MaterialTheme.typography.labelMedium,
            color = TextSecondary,
            modifier = Modifier.padding(bottom = 8.dp, start = 16.dp)
        )
        Card(
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = AppleSurface)
        ) {
            Column {
                // Anti-DPI (BoringSSL + Padding)
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(Texts.antiDpi, style = MaterialTheme.typography.bodyLarge, color = TextPrimary)
                        Text(Texts.antiDpiDesc, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                    Switch(
                        checked = antiDpiEnabled,
                        onCheckedChange = { antiDpiEnabled = it },
                        enabled = !isRunning,
                        colors = AppleSwitchColors()
                    )
                }
                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(start = 16.dp))
                
                // DoH (DNS over HTTPS / ECH)
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(Texts.useDoh, style = MaterialTheme.typography.bodyLarge, color = TextPrimary)
                        Text(Texts.useDohDesc, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                    Switch(
                        checked = dohEnabled,
                        onCheckedChange = { dohEnabled = it },
                        enabled = !isRunning,
                        colors = AppleSwitchColors()
                    )
                }
                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(start = 16.dp))
                
                // Traffic Shaping
                Row(
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(Texts.useTrafficShaping, style = MaterialTheme.typography.bodyLarge, color = TextPrimary)
                        Text(Texts.useTrafficShapingDesc, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }
                    Switch(
                        checked = trafficShaping,
                        onCheckedChange = { trafficShaping = it },
                        enabled = !isRunning,
                        colors = AppleSwitchColors()
                    )
                }
            }
        }
        Spacer(modifier = Modifier.height(24.dp))

        // --- SYSTEM SECTION ---
        Text(
            Texts.system.uppercase(),
            style = MaterialTheme.typography.labelMedium,
            color = TextSecondary,
            modifier = Modifier.padding(bottom = 8.dp, start = 16.dp)
        )
        Card(
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = AppleSurface)
        ) {
            Column {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = if (isBatteryOptimized) Icons.Outlined.BatteryAlert else Icons.Outlined.BatteryChargingFull,
                        contentDescription = null,
                        tint = if (isBatteryOptimized) AppleOrange else AppleGreen,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(16.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(Texts.batteryOpt, style = MaterialTheme.typography.bodyLarge, color = TextPrimary)
                        Text(
                            if (isBatteryOptimized) Texts.batteryNotDisabled else Texts.batteryDisabled,
                            style = MaterialTheme.typography.bodySmall,
                            color = TextSecondary
                        )
                    }
                    if (isBatteryOptimized) {
                        TextButton(onClick = onRequestBatteryOptimization) {
                            Text(Texts.fix, color = AppleBlue, style = MaterialTheme.typography.bodyLarge)
                        }
                    }
                }
                
                if (hasAutoStart) {
                    HorizontalDivider(color = DividerColor, modifier = Modifier.padding(start = 56.dp))
                    
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onRequestAutoStart() }
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = Icons.Outlined.AppRegistration,
                            contentDescription = null,
                            tint = AppleOrange,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(modifier = Modifier.width(16.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(Texts.autoStart, style = MaterialTheme.typography.bodyLarge, color = TextPrimary)
                            Text(
                                Texts.autoStartDesc,
                                style = MaterialTheme.typography.bodySmall,
                                color = TextSecondary
                            )
                        }
                        Icon(Icons.Outlined.ArrowForwardIos, null, tint = TextSecondary, modifier = Modifier.size(16.dp))
                    }
                }
                
                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(start = 56.dp))
                
                // Language Settings
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Outlined.Language, null, tint = AppleBlue, modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(16.dp))
                        Text(Texts.language, style = MaterialTheme.typography.bodyLarge, color = TextPrimary)
                    }
                    
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("EN", color = if (!Texts.isRu) AppleBlue else TextSecondary, style = MaterialTheme.typography.bodyMedium)
                        Spacer(modifier = Modifier.width(8.dp))
                        val context = androidx.compose.ui.platform.LocalContext.current
                        Switch(
                            checked = Texts.isRu,
                            onCheckedChange = { isRu -> 
                                Texts.isRu = isRu
                                val prefs = context.getSharedPreferences("TgProxyPrefs", android.content.Context.MODE_PRIVATE)
                                prefs.edit().putBoolean("isRu", isRu).apply()
                            },
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("RU", color = if (Texts.isRu) AppleBlue else TextSecondary, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        
        Spacer(modifier = Modifier.height(32.dp))

        // --- ADVANCED SETTINGS TOGGLE ---
        Card(
            modifier = Modifier.fillMaxWidth().clickable { showAdvanced = !showAdvanced },
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = AppleSurface)
        ) {
            Row(
                modifier = Modifier.padding(16.dp).fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(Texts.advancedSettings, color = AppleBlue, style = MaterialTheme.typography.bodyLarge)
                Icon(
                    imageVector = if (showAdvanced) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore,
                    contentDescription = null,
                    tint = TextSecondary
                )
            }
        }

        if (showAdvanced) {
            Spacer(modifier = Modifier.height(16.dp))

            // Secret & Port
            Card(shape = RoundedCornerShape(14.dp), colors = CardDefaults.cardColors(containerColor = AppleSurface)) {
                Column {
                    OutlinedTextField(
                        value = secret,
                        onValueChange = { input ->
                            val cleanInput = input.trim()
                            if (cleanInput.startsWith("tg://proxy?") || cleanInput.startsWith("https://t.me/proxy?")) {
                                // Full link parsing
                                val uri = Uri.parse(cleanInput.replace("https://t.me/proxy?", "tg://proxy?"))
                                val s = uri.getQueryParameter("secret")
                                val p = uri.getQueryParameter("port")
                                if (s != null) {
                                    if (s.startsWith("ee") && s.length >= 34) {
                                        secret = s.substring(2, 34)
                                        val domainHex = s.substring(34)
                                        if (domainHex.isNotEmpty()) {
                                            try {
                                                fakeTlsDomain = String(
                                                    domainHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                                )
                                            } catch (_: Exception) {}
                                        }
                                    } else if (s.startsWith("dd")) {
                                        secret = s.substring(2).take(32)
                                    } else {
                                        secret = s.take(32)
                                    }
                                }
                                if (p != null) port = p
                            } else if (cleanInput.startsWith("ee") && cleanInput.length >= 34) {
                                secret = cleanInput.substring(2, 34)
                                val domainHex = cleanInput.substring(34)
                                try {
                                    fakeTlsDomain = String(
                                        domainHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                                    )
                                } catch (_: Exception) {}
                            } else if (cleanInput.startsWith("dd")) {
                                secret = cleanInput.substring(2).take(32).filter { it in "0123456789abcdefABCDEF" }
                            } else {
                                val filtered = cleanInput.filter { it in "0123456789abcdefABCDEF" }
                                if (filtered.length <= 32) secret = filtered
                            }
                        },
                        label = { Text(Texts.secret) },
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        enabled = !isRunning,
                        singleLine = true,
                        colors = settingsTextFieldColors(),
                        trailingIcon = {
                            IconButton(onClick = { secret = ProxyConfig.generateSecret() }, enabled = !isRunning) {
                                Icon(Icons.Filled.AutoFixHigh, "Generate", tint = AppleBlue)
                            }
                        }
                    )
                    HorizontalDivider(color = DividerColor, modifier = Modifier.padding(start = 16.dp))
                    OutlinedTextField(
                        value = port,
                        onValueChange = { port = it.filter { c -> c.isDigit() }.take(5) },
                        label = { Text(Texts.localPort) },
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        enabled = !isRunning,
                        singleLine = true,
                        colors = settingsTextFieldColors(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number)
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // FakeTLS
            Card(shape = RoundedCornerShape(14.dp), colors = CardDefaults.cardColors(containerColor = AppleSurface)) {
                OutlinedTextField(
                    value = fakeTlsDomain,
                    onValueChange = { fakeTlsDomain = it.trim() },
                    label = { Text(Texts.maskingDomain) },
                    placeholder = { Text(Texts.egGoogle) },
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    enabled = !isRunning,
                    singleLine = true,
                    colors = settingsTextFieldColors()
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // CF Domain
            Card(shape = RoundedCornerShape(14.dp), colors = CardDefaults.cardColors(containerColor = AppleSurface)) {
                OutlinedTextField(
                    value = cfProxyDomain,
                    onValueChange = { cfProxyDomain = it.trim() },
                    label = { Text(Texts.customCfDomain) },
                    placeholder = { Text(Texts.leaveEmptyAuto) },
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    enabled = !isRunning,
                    singleLine = true,
                    colors = settingsTextFieldColors()
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // DC IPs
            Card(shape = RoundedCornerShape(14.dp), colors = CardDefaults.cardColors(containerColor = AppleSurface)) {
                OutlinedTextField(
                    value = dcIps,
                    onValueChange = { dcIps = it },
                    label = { Text(Texts.dcMappings) },
                    placeholder = { Text("2:149.154.167.220\n4:149.154.167.220") },
                    modifier = Modifier.fillMaxWidth().height(120.dp).padding(16.dp),
                    enabled = !isRunning,
                    colors = settingsTextFieldColors()
                )
            }
        }

        Spacer(modifier = Modifier.height(32.dp))

        // Save Button
        Button(
            onClick = {
                val parsedPort = port.toIntOrNull() ?: 1443
                val dcMap = mutableMapOf<Int, String>()
                for (line in dcIps.lines()) {
                    val parts = line.trim().split(":", limit = 2)
                    if (parts.size == 2) {
                        val dcNum = parts[0].trim().toIntOrNull()
                        val ip = parts[1].trim()
                        if (dcNum != null && ip.isNotEmpty()) {
                            dcMap[dcNum] = ip
                        }
                    }
                }
                onSave(
                    config.copy(
                        secret = secret.ifEmpty { ProxyConfig.generateSecret() },
                        port = parsedPort,
                        fakeTlsDomain = fakeTlsDomain,
                        fallbackCfProxy = antiBlockEnabled,
                        fallbackCfProxyPriority = cfPriorityEnabled,
                        cfProxyUserDomain = cfProxyDomain,
                        dcRedirects = dcMap,
                        antiDpiEnabled = antiDpiEnabled,
                        dohEnabled = dohEnabled,
                        trafficShaping = trafficShaping
                    )
                )
            },
            modifier = Modifier.fillMaxWidth().height(50.dp),
            enabled = !isRunning,
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = AppleBlue, contentColor = Color.White)
        ) {
            Text(Texts.saveSettings, style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.SemiBold))
        }

        Spacer(modifier = Modifier.height(40.dp))
    }
}

@Composable
private fun AppleSwitchColors() = SwitchDefaults.colors(
    checkedThumbColor = Color.White,
    checkedTrackColor = AppleGreen,
    uncheckedThumbColor = Color.White,
    uncheckedTrackColor = AppleSurfaceVariant
)

@Composable
private fun settingsTextFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = AppleBlue,
    unfocusedBorderColor = Color.Transparent,
    focusedLabelColor = AppleBlue,
    unfocusedLabelColor = TextSecondary,
    cursorColor = AppleBlue,
    focusedTextColor = TextPrimary,
    unfocusedTextColor = TextPrimary,
    disabledBorderColor = Color.Transparent,
    disabledTextColor = TextSecondary,
    focusedContainerColor = AppleSurfaceVariant,
    unfocusedContainerColor = AppleBlack
)
