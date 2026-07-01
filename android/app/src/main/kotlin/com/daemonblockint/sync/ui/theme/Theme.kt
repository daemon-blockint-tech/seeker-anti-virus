package com.daemonblockint.sync.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF00E5FF),
    secondary = Color(0xFF7C4DFF),
    tertiary = Color(0xFFFF5252),
    background = Color(0xFF0A0E14),
    surface = Color(0xFF111821),
    onPrimary = Color(0xFF000000),
    onSecondary = Color(0xFFFFFFFF),
    onBackground = Color(0xFFE0E0E0),
    onSurface = Color(0xFFE0E0E0),
    error = Color(0xFFFF1744),
    onError = Color(0xFFFFFFFF),
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF00B8D4),
    secondary = Color(0xFF6200EA),
    tertiary = Color(0xFFD32F2F),
    background = Color(0xFFF5F7FA),
    surface = Color(0xFFFFFFFF),
    onPrimary = Color(0xFFFFFFFF),
    onSecondary = Color(0xFFFFFFFF),
    onBackground = Color(0xFF1A1A2E),
    onSurface = Color(0xFF1A1A2E),
    error = Color(0xFFD32F2F),
    onError = Color(0xFFFFFFFF),
)

@Composable
fun SyncTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors = if (darkTheme) DarkColorScheme else LightColorScheme
    MaterialTheme(
        colorScheme = colors,
        content = content,
    )
}
