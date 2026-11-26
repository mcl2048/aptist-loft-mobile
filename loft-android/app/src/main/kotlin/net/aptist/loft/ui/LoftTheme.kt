package net.aptist.loft.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

enum class ThemeChoice { SYSTEM, LIGHT, DARK }
data class LoftColors(val secondaryText: Color, val divider: Color, val rail: Color,
    val warning: Color, val warningContainer: Color, val link: Color)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF3B63FB), onPrimary = Color.White,
    primaryContainer = Color(0xFF1B2549), onPrimaryContainer = Color(0xFFB2C2FF),
    background = Color(0xFF111113), onBackground = Color.White,
    surface = Color(0xFF1C1C1E), onSurface = Color.White,
    surfaceVariant = Color(0xFF1D1D1F), onSurfaceVariant = Color(0xFFA7ABB5),
    outline = Color(0xFF727782), error = Color(0xFFFF9494), errorContainer = Color(0xFF352024),
)
private val LightColors = lightColorScheme(
    primary = Color(0xFF3B63FB), onPrimary = Color.White,
    primaryContainer = Color(0xFFEAF0FF), onPrimaryContainer = Color(0xFF2D4FD5),
    background = Color(0xFFF6F7FA), onBackground = Color(0xFF17181C),
    surface = Color.White, onSurface = Color(0xFF17181C),
    surfaceVariant = Color(0xFFEFF1F6), onSurfaceVariant = Color(0xFF606572),
    outline = Color(0xFF727782), error = Color(0xFFB62632), errorContainer = Color(0xFFFFF0F1),
)
private val DarkExtras = LoftColors(Color(0xFFA7ABB5), Color(0xFF303238), Color(0xFF151517),
    Color(0xFFF7C46C), Color(0xFF302719), Color(0xFFB2C2FF))
private val LightExtras = LoftColors(Color(0xFF606572), Color(0xFFE1E4EC), Color(0xFFEFF1F6),
    Color(0xFF8A4B00), Color(0xFFFFF4DE), Color(0xFF2D4FD5))

val LocalLoftColors = staticCompositionLocalOf { LightExtras }
private val LoftTypography = Typography(
    displaySmall = TextStyle(fontFamily = FontFamily.Default, fontSize = 36.sp, lineHeight = 44.sp, fontWeight = FontWeight.SemiBold),
    headlineSmall = TextStyle(fontFamily = FontFamily.Default, fontSize = 24.sp, lineHeight = 32.sp, fontWeight = FontWeight.SemiBold),
    titleMedium = TextStyle(fontFamily = FontFamily.Default, fontSize = 16.sp, lineHeight = 24.sp, fontWeight = FontWeight.SemiBold),
    bodyLarge = TextStyle(fontFamily = FontFamily.Default, fontSize = 16.sp, lineHeight = 24.sp),
    bodyMedium = TextStyle(fontFamily = FontFamily.Default, fontSize = 14.sp, lineHeight = 22.sp),
    bodySmall = TextStyle(fontFamily = FontFamily.Default, fontSize = 12.sp, lineHeight = 18.sp),
    labelLarge = TextStyle(fontFamily = FontFamily.Default, fontSize = 14.sp, lineHeight = 22.sp, fontWeight = FontWeight.Medium),
    labelSmall = TextStyle(fontFamily = FontFamily.Default, fontSize = 11.sp, lineHeight = 16.sp, fontWeight = FontWeight.Medium),
)

@Composable
fun LoftTheme(choice: ThemeChoice, content: @Composable () -> Unit) {
    val dark = when (choice) {
        ThemeChoice.SYSTEM -> isSystemInDarkTheme()
        ThemeChoice.LIGHT -> false
        ThemeChoice.DARK -> true
    }
    CompositionLocalProvider(LocalLoftColors provides if (dark) DarkExtras else LightExtras) {
        MaterialTheme(colorScheme = if (dark) DarkColors else LightColors, typography = LoftTypography, content = content)
    }
}
