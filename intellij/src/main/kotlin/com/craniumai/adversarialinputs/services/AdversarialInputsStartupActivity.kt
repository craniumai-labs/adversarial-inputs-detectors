package com.craniumai.adversarialinputs.services

import com.craniumai.adversarialinputs.actions.ScanProjectAction
import com.craniumai.adversarialinputs.settings.AdversarialInputsSettings
import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity

/**
 * Startup activity that runs when a project is opened
 */
class AdversarialInputsStartupActivity : ProjectActivity {

    override suspend fun execute(project: Project) {
        println("Adversarial Inputs Detector is now active for project: ${project.name}")

        val settings = AdversarialInputsSettings.getInstance(project)

        // Auto-scan on startup if enabled
        if (settings.autoScanOnOpen) {
            println("Auto-scan enabled. Triggering workspace scan...")
            // Use the scan action to trigger a scan
            val scanAction = ScanProjectAction()
            scanAction.scanProject(project)
        }
    }
}
