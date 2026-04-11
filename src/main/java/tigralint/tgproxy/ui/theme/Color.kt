package tigralint.tgproxy.ui.theme

import androidx.compose.ui.graphics.Color

// iOS Dark Theme Palette
val AppleBlack = Color(0xFF000000)
val AppleSurface = Color(0xFF1C1C1E)
val AppleSurfaceVariant = Color(0xFF2C2C2E)

// iOS Accents
val AppleBlue = Color(0xFF0A84FF)
val AppleGreen = Color(0xFF30D158)
val AppleRed = Color(0xFFFF453A)
val AppleOrange = Color(0xFFFF9F0A)

// Text Colors
val TextPrimary = Color(0xFFFFFFFF)
val TextSecondary = Color(0xFF8E8E93)
val TextTertiary = Color(0xFF48484A)
val DividerColor = Color(0xFF38383A)

// Map to old variables to prevent breaking immediately (we'll phase these out or re-assign)
val DarkBackground = AppleBlack
val DarkSurface = AppleSurface
val DarkSurfaceVariant = AppleSurfaceVariant
val DarkCard = AppleSurface

val CyanAccent = AppleBlue
val CyanBright = Color(0xFF64D2FF) // Apple Light Blue
val CyanDim = Color(0xFF004080)

val GreenAccent = AppleGreen
val GreenBright = Color(0xFF34C759)
val GreenDim = Color(0xFF248A3D)

val AmberAccent = AppleOrange
val RedAccent = AppleRed
val TextDim = TextTertiary

val GradientStart = AppleBlack
val GradientEnd = AppleBlack

val StatusRunning = AppleGreen
val StatusStopped = TextSecondary
val StatusStarting = AppleOrange
val StatusError = AppleRed
