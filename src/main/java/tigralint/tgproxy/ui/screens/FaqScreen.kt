package tigralint.tgproxy.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import tigralint.tgproxy.ui.theme.*
import tigralint.tgproxy.util.Texts

@Composable
fun FaqScreen(modifier: Modifier = Modifier) {
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
            Texts.faq,
            style = MaterialTheme.typography.displayLarge.copy(fontWeight = FontWeight.Bold),
            color = TextPrimary
        )
        
        Spacer(modifier = Modifier.height(32.dp))
        
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(14.dp),
            colors = CardDefaults.cardColors(containerColor = AppleSurface)
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                FaqItem(
                    title = Texts.faqTitle1,
                    text = Texts.faqText1,
                    icon = Icons.Filled.Info,
                    isBlue = true
                )
                
                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(start = 56.dp))
                
                FaqItem(
                    title = Texts.faqTitle2,
                    text = Texts.faqText2,
                    icon = Icons.Filled.Warning,
                    isBlue = false
                )
                
                HorizontalDivider(color = DividerColor, modifier = Modifier.padding(start = 56.dp))
                
                FaqItem(
                    title = Texts.faqTitle3,
                    text = Texts.faqText3,
                    icon = Icons.Filled.Info,
                    isBlue = true
                )
            }
        }
        
        Spacer(modifier = Modifier.height(32.dp))
        
        Text(
            text = Texts.developedBy,
            style = MaterialTheme.typography.bodyMedium,
            color = TextSecondary,
            modifier = Modifier.align(Alignment.CenterHorizontally)
        )
        
        Spacer(modifier = Modifier.height(40.dp))
    }
}

@Composable
private fun FaqItem(title: String, text: String, icon: androidx.compose.ui.graphics.vector.ImageVector, isBlue: Boolean) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = if (isBlue) AppleBlue else AppleOrange,
            modifier = Modifier.size(24.dp).padding(top = 2.dp)
        )
        Spacer(modifier = Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge.copy(fontWeight = FontWeight.SemiBold),
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(6.dp))
            Text(
                text = text,
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary,
                lineHeight = 20.sp
            )
        }
    }
}
