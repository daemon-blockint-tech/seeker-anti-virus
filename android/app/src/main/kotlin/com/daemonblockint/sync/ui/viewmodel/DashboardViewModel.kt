package com.daemonblockint.sync.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.daemonblockint.sync.engine.ScanTarget
import com.daemonblockint.sync.engine.integrated.IntegratedScanner
import com.daemonblockint.sync.engine.integrated.ScanResult
import com.daemonblockint.sync.engine.monitor.Monitor
import com.daemonblockint.sync.engine.monitor.ThreatAlert
import com.daemonblockint.sync.engine.threatdb.ThreatStore
import com.daemonblockint.sync.yara.NativeYaraBridge
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class DashboardState(
    val isProtected: Boolean = true,
    val threatCount: Int = 0,
    val lastScanScore: Int = 0,
    val lastScanSeverity: String = "LOW",
    val yaraNativeActive: Boolean = false,
    val threatDbSize: Int = 0,
    val recentAlerts: List<ThreatAlert> = emptyList(),
    val isScanning: Boolean = false,
    val lastScanResult: ScanResult? = null,
)

@HiltViewModel
class DashboardViewModel @Inject constructor(
    private val scanner: IntegratedScanner,
    private val threatStore: ThreatStore,
    private val yaraBridge: NativeYaraBridge,
) : ViewModel() {

    private val _state = MutableStateFlow(DashboardState())
    val state: StateFlow<DashboardState> = _state.asStateFlow()

    private val monitor = Monitor(scanner)
    private val alerts = mutableListOf<ThreatAlert>()

    init {
        monitor.onAlert { alert ->
            alerts.add(0, alert)
            if (alerts.size > 50) alerts.removeAt(alerts.lastIndex)
            _state.value = _state.value.copy(
                recentAlerts = alerts.toList(),
                threatCount = alerts.size,
            )
        }
        refreshStatus()
    }

    fun refreshStatus() {
        _state.value = _state.value.copy(
            yaraNativeActive = yaraBridge.isNativeActive,
            threatDbSize = threatStore.size,
        )
    }

    fun scanText(text: String, label: String? = null) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isScanning = true)
            try {
                val target = ScanTarget(
                    id = "text-blob",
                    kind = ScanTarget.Kind.APP,
                    label = label ?: "Text scan",
                    text = text,
                )
                val result = scanner.scan(target)
                _state.value = _state.value.copy(
                    lastScanResult = result,
                    lastScanScore = result.score,
                    lastScanSeverity = result.severity.name,
                    isScanning = false,
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(isScanning = false)
            }
        }
    }

    fun scanApp(packageName: String, label: String?, permissions: List<String> = emptyList()) {
        viewModelScope.launch {
            _state.value = _state.value.copy(isScanning = true)
            try {
                val target = ScanTarget(
                    id = packageName,
                    kind = ScanTarget.Kind.APP,
                    label = label ?: packageName,
                    permissions = permissions.mapNotNull { name ->
                        runCatching {
                            com.daemonblockint.sync.engine.DangerousPermission.valueOf(name)
                        }.getOrNull()
                    },
                )
                val result = scanner.scan(target)
                _state.value = _state.value.copy(
                    lastScanResult = result,
                    lastScanScore = result.score,
                    lastScanSeverity = result.severity.name,
                    isScanning = false,
                )
            } catch (e: Exception) {
                _state.value = _state.value.copy(isScanning = false)
            }
        }
    }
}
