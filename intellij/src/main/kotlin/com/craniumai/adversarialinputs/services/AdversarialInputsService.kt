package com.craniumai.adversarialinputs.services

import com.craniumai.adversarialinputs.detector.AdversarialInputsDetector
import com.craniumai.adversarialinputs.detector.DetectionResult
import com.craniumai.adversarialinputs.settings.AdversarialInputsSettings
import com.intellij.openapi.components.Service
import com.intellij.openapi.project.Project
import java.util.concurrent.ConcurrentHashMap

/**
 * Project-level service that manages the detector and scan results
 */
@Service(Service.Level.PROJECT)
class AdversarialInputsService(private val project: Project) {

    private val detector: AdversarialInputsDetector
    private val scanResults = ConcurrentHashMap<String, DetectionResult>()

    init {
        val settings = AdversarialInputsSettings.getInstance(project)
        detector = AdversarialInputsDetector(
            targetFolders = settings.targetFolders,
            specialAgentFiles = settings.agentFiles
        )
        detector.setEndpointAllowlist(settings.endpointAllowlist)
    }

    /**
     * Get the detector instance
     */
    fun getDetector(): AdversarialInputsDetector = detector

    /**
     * Update detector settings
     */
    fun updateSettings() {
        val settings = AdversarialInputsSettings.getInstance(project)
        detector.setEndpointAllowlist(settings.endpointAllowlist)
    }

    /**
     * Store scan result for a file
     */
    fun storeScanResult(filePath: String, result: DetectionResult) {
        scanResults[filePath] = result
    }

    /**
     * Get scan result for a file
     */
    fun getScanResult(filePath: String): DetectionResult? {
        return scanResults[filePath]
    }

    /**
     * Get all scan results
     */
    fun getAllScanResults(): Map<String, DetectionResult> {
        return scanResults.toMap()
    }

    /**
     * Clear all scan results
     */
    fun clearScanResults() {
        scanResults.clear()
    }

    /**
     * Get count of files with threats above threshold
     */
    fun getThreatCount(): Int {
        val settings = AdversarialInputsSettings.getInstance(project)
        return scanResults.values.count { it.verdict.ordinal >= settings.minVulnLevel.ordinal }
    }

    /**
     * Check if there are any critical threats
     */
    fun hasCriticalThreats(): Boolean {
        return scanResults.values.any { it.verdict.name == "CRITICAL" }
    }

    companion object {
        fun getInstance(project: Project): AdversarialInputsService {
            return project.getService(AdversarialInputsService::class.java)
        }
    }
}
