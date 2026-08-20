package com.reveny.devicecheck.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Button
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LargeTopAppBar
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalUriHandler
import com.reveny.devicecheck.DeviceCheckClient
import com.reveny.devicecheck.DeviceCheckResult
import compose.icons.TablerIcons
import compose.icons.tablericons.Filled
import compose.icons.tablericons.Outline
import compose.icons.tablericons.filled.BrandGithub
import compose.icons.tablericons.filled.BrandPatreon
import compose.icons.tablericons.outline.BrandTelegram
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.SocketTimeoutException
import java.net.UnknownHostException

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DeviceCheckTheme {
                DeviceCheckApp()
            }
        }
    }

    @Composable
    private fun DeviceCheckApp() {
        val context = this
        val appVersion = BuildConfig.VERSION_NAME
        val client = remember { DeviceCheckClient() }
        var state by remember {
            mutableStateOf<CheckState>(
                if (hasPrivacyConsent()) {
                    CheckState.Loading(DeviceInfo.collect(appVersion))
                } else {
                    CheckState.Consent
                }
            )
        }

        fun startCheck() {
            state = CheckState.Loading(DeviceInfo.collect(appVersion))
        }

        fun retry() {
            startCheck()
        }

        LaunchedEffect(state is CheckState.Loading) {
            val loading = state as? CheckState.Loading ?: return@LaunchedEffect
            state = try {
                val result = withContext(Dispatchers.IO) {
                    client.check(context, appVersion)
                }
                CheckState.Success(loading.deviceInfo, result)
            } catch (error: Exception) {
                CheckState.Error(loading.deviceInfo, checkErrorMessage(error))
            }
        }

        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.background
        ) {
            when (val current = state) {
                CheckState.Consent -> ConsentScreen(
                    onAgree = {
                        setPrivacyConsentAccepted()
                        startCheck()
                    }
                )
                is CheckState.Loading -> LoadingScreen(current.deviceInfo)
                is CheckState.Success -> ResultScreen(current.deviceInfo, current.result)
                is CheckState.Error -> ErrorScreen(current.message)
            }
        }
    }

    private fun hasPrivacyConsent(): Boolean {
        return getSharedPreferences(kPrefsName, MODE_PRIVATE).getBoolean(kPrivacyAccepted, false)
    }

    private fun setPrivacyConsentAccepted() {
        getSharedPreferences(kPrefsName, MODE_PRIVATE)
            .edit()
            .putBoolean(kPrivacyAccepted, true)
            .apply()
    }
}

private sealed interface CheckState {
    object Consent : CheckState

    data class Loading(val deviceInfo: DeviceInfo) : CheckState
    data class Success(val deviceInfo: DeviceInfo, val result: DeviceCheckResult) : CheckState
    data class Error(val deviceInfo: DeviceInfo, val message: String) : CheckState
}

@Composable
private fun ConsentScreen(onAgree: () -> Unit) {
    val uriHandler = LocalUriHandler.current

    Box(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.safeDrawing)
            .padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            Text(
                text = "Device Check",
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center
            )
            Text(
                text = "This demo collects device signals and sends them to a server for attestation testing. See the Privacy Policy for details.",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onBackground,
                textAlign = TextAlign.Center
            )
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                TextButton(onClick = { uriHandler.openUri(kPrivacyPolicyUrl) }) {
                    Text("View Privacy Policy")
                }
                Button(onClick = onAgree) {
                    Text("I agree. Run Check")
                }
            }
        }
    }
}

@Composable
private fun LoadingScreen(@Suppress("UNUSED_PARAMETER") deviceInfo: DeviceInfo) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator(
            color = MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
private fun ResultScreen(deviceInfo: DeviceInfo, result: DeviceCheckResult) {
    Page {
        item {
            val normal = result.environmentStatus == "normal"
            StatusBanner(
                title = value(result.environmentTitle),
                description = value(result.environmentMessage),
                color = if (normal) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                contentColor = if (normal) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onError
            )
        }
        item { IdentityCard(result) }
        item { SystemCard(deviceInfo) }
        item { SupportCard() }
    }
}

@Composable
private fun ErrorScreen(@Suppress("UNUSED_PARAMETER") message: String) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .windowInsetsPadding(WindowInsets.safeDrawing),
        contentAlignment = Alignment.Center
    ) {
        Text(
            text = "Server unavailable.\nTry again later.",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onBackground,
            fontWeight = FontWeight.Normal,
            textAlign = TextAlign.Center
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun Page(content: androidx.compose.foundation.lazy.LazyListScope.() -> Unit) {
    val scrollBehavior = TopAppBarDefaults.exitUntilCollapsedScrollBehavior()

    Scaffold(
        modifier = Modifier
            .fillMaxSize()
            .nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            LargeTopAppBar(
                title = { Text("Device Check") },
                scrollBehavior = scrollBehavior,
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.background,
                    titleContentColor = MaterialTheme.colorScheme.onBackground
                )
            )
        },
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0)
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            content = content
        )
    }
}

@Composable
private fun StatusBanner(
    title: String,
    description: String,
    color: Color,
    contentColor: Color
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp)),
        color = color,
        tonalElevation = 0.dp
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 22.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Filled.Info,
                contentDescription = "Info",
                tint = contentColor,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.width(24.dp))
            Column {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    color = contentColor,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = contentColor
                )
            }
        }
    }
}

@Composable
private fun SystemCard(deviceInfo: DeviceInfo) {
    InfoCard("System") {
        InfoLine("Device", "${value(deviceInfo.manufacturer)} ${value(deviceInfo.model)}")
        InfoLine("Android Version", value(deviceInfo.androidVersion))
        InfoLine("SDK", deviceInfo.sdk.toString())
        InfoLine("Kernel Version", value(deviceInfo.kernelVersion))
        InfoLine("App Version", value(deviceInfo.appVersion))
    }
}

@Composable
private fun IdentityCard(result: DeviceCheckResult) {
    InfoCard("Identity") {
        InfoLine("Nonce", value(result.displayNonce))
        InfoLine("Device ID", value(result.displayDeviceId))
        InfoLine("Cluster ID", value(result.displayClusterId))
        InfoLine("Known Device", yesNo(result.isKnownDevice))
    }
}

@Composable
private fun SupportCard() {
    val uriHandler = LocalUriHandler.current

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp)),
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 1.dp
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = "Support Us",
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                IconButton(onClick = { uriHandler.openUri("https://github.com/reveny") }) {
                    Icon(
                        imageVector = TablerIcons.Filled.BrandGithub,
                        contentDescription = "GitHub",
                        tint = MaterialTheme.colorScheme.onSurface
                    )
                }
                IconButton(onClick = { uriHandler.openUri("https://patreon.com/Reveny") }) {
                    Icon(
                        imageVector = TablerIcons.Filled.BrandPatreon,
                        contentDescription = "Patreon",
                        tint = MaterialTheme.colorScheme.onSurface
                    )
                }
                IconButton(onClick = { uriHandler.openUri("https://t.me/reveny1") }) {
                    Icon(
                        imageVector = TablerIcons.Outline.BrandTelegram,
                        contentDescription = "Telegram",
                        tint = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}

@Composable
private fun InfoCard(title: String, content: @Composable ColumnScope.() -> Unit) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp)),
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 1.dp
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "$title :",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(8.dp))
            content()
        }
    }
}

@Composable
private fun InfoLine(label: String, value: String, monospace: Boolean = false) {
    SelectionContainer {
        Text(
            text = "$label: ${value(value)}",
            modifier = Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
            fontFamily = if (monospace) FontFamily.Monospace else FontFamily.Default,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis
        )
    }
    Spacer(modifier = Modifier.height(4.dp))
}

@Composable
private fun DeviceCheckTheme(content: @Composable () -> Unit) {
    val darkTheme = isSystemInDarkTheme()
    val colorScheme = deviceCheckColorScheme(darkTheme)

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}

private fun deviceCheckColorScheme(darkTheme: Boolean): ColorScheme {
    return if (darkTheme) {
        darkColorScheme(
            primary = Color(0xFFB9CA77),
            onPrimary = Color(0xFF273500),
            background = Color(0xFF13150E),
            onBackground = Color(0xFFE7E4D8),
            surface = Color(0xFF1E2117),
            onSurface = Color(0xFFE7E4D8),
            error = Color(0xFFFFB4AB),
            onError = Color(0xFF690005)
        )
    } else {
        lightColorScheme(
            primary = Color(0xFF52691E),
            onPrimary = Color.White,
            background = Color(0xFFFBFAEF),
            onBackground = Color(0xFF191C13),
            surface = Color(0xFFF5F3E8),
            onSurface = Color(0xFF191C13),
            error = Color(0xFFBA1A1A),
            onError = Color.White
        )
    }
}

private fun yesNo(value: Boolean): String {
    return if (value) "Yes" else "No"
}

private fun checkErrorMessage(error: Exception): String {
    return when (error) {
        is UnknownHostException -> "Server host could not be reached."
        is SocketTimeoutException -> "Server did not respond in time."
        else -> error.message?.takeIf { it.isNotBlank() } ?: "Server request failed."
    }
}

private fun value(value: String?): String {
    return if (value.isNullOrBlank()) "Unavailable" else value
}

private const val kPrefsName = "device_check_app"
private const val kPrivacyAccepted = "privacy_accepted"
private const val kPrivacyPolicyUrl = "https://github.com/reveny/Android-Device-Trust/blob/main/PRIVACY.md"
