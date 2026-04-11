package tigralint.tgproxy.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val DarkColorScheme = darkColorScheme(
    primary = AppleBlue,
    onPrimary = AppleBlack,
    primaryContainer = AppleSurfaceVariant,
    onPrimaryContainer = AppleBlue,

    secondary = AppleGreen,
    onSecondary = AppleBlack,
    secondaryContainer = AppleSurfaceVariant,
    onSecondaryContainer = AppleGreen,

    tertiary = AppleOrange,
    error = AppleRed,

    background = AppleBlack,
    onBackground = TextPrimary,

    surface = AppleSurface,
    onSurface = TextPrimary,
    surfaceVariant = AppleSurfaceVariant,
    onSurfaceVariant = TextSecondary,

    outline = DividerColor,
    outlineVariant = AppleBlack,
)

@Composable
fun TgProxyTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        typography = AppTypography,
        content = content
    )
}
