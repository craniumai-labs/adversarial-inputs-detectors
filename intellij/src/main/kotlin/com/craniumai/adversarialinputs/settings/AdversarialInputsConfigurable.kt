package com.craniumai.adversarialinputs.settings

import com.craniumai.adversarialinputs.detector.Severity
import com.craniumai.adversarialinputs.services.AdversarialInputsService
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBCheckBox
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBTextArea
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import javax.swing.*

/**
 * Settings UI for Adversarial Inputs Detector
 */
class AdversarialInputsConfigurable(private val project: Project) : Configurable {

    private var autoScanCheckBox: JBCheckBox? = null
    private var minVulnLevelComboBox: JComboBox<Severity>? = null
    private var endpointAllowlistTextArea: JBTextArea? = null
    private var targetFoldersTextArea: JBTextArea? = null
    private var agentFilesTextArea: JBTextArea? = null

    override fun getDisplayName(): String = "Adversarial Inputs Detector"

    override fun createComponent(): JComponent {
        val settings = AdversarialInputsSettings.getInstance(project)

        // Auto-scan checkbox
        autoScanCheckBox = JBCheckBox("Automatically scan project when opened", settings.autoScanOnOpen)

        // Minimum vulnerability level dropdown
        minVulnLevelComboBox = JComboBox(Severity.values())
        minVulnLevelComboBox?.selectedItem = settings.minVulnLevel

        // Endpoint allowlist text area
        endpointAllowlistTextArea = JBTextArea(10, 40)
        endpointAllowlistTextArea?.text = settings.endpointAllowlist.joinToString("\n")
        endpointAllowlistTextArea?.lineWrap = true
        val endpointAllowlistScrollPane = JScrollPane(endpointAllowlistTextArea)
        endpointAllowlistScrollPane.preferredSize = JBUI.size(400, 120)

        // Target folders text area
        targetFoldersTextArea = JBTextArea(5, 40)
        targetFoldersTextArea?.text = settings.targetFolders.joinToString("\n")
        targetFoldersTextArea?.lineWrap = true
        val targetFoldersScrollPane = JScrollPane(targetFoldersTextArea)
        targetFoldersScrollPane.preferredSize = JBUI.size(400, 80)

        // Agent files text area
        agentFilesTextArea = JBTextArea(3, 40)
        agentFilesTextArea?.text = settings.agentFiles.joinToString("\n")
        agentFilesTextArea?.lineWrap = true
        val agentFilesScrollPane = JScrollPane(agentFilesTextArea)
        agentFilesScrollPane.preferredSize = JBUI.size(400, 60)

        return FormBuilder.createFormBuilder()
            .addComponent(JBLabel("<html><h2>Adversarial Inputs Detector Settings</h2></html>"))
            .addVerticalGap(10)
            .addComponent(autoScanCheckBox!!)
            .addVerticalGap(10)
            .addLabeledComponent("Minimum vulnerability level:", minVulnLevelComboBox!!)
            .addVerticalGap(10)
            .addComponent(JBLabel("<html><b>Endpoint Allowlist</b><br/>List of endpoint patterns to exclude from detection (one per line, supports wildcards: *, ?)<br/>Example: https://github.com/*, https://*.example.com/*</html>"))
            .addComponent(endpointAllowlistScrollPane)
            .addVerticalGap(10)
            .addComponent(JBLabel("<html><b>Target Folders</b><br/>Trusted folders that may indicate self-propagation attempts (one per line)</html>"))
            .addComponent(targetFoldersScrollPane)
            .addVerticalGap(10)
            .addComponent(JBLabel("<html><b>Agent Files</b><br/>Special agent configuration files (one per line)</html>"))
            .addComponent(agentFilesScrollPane)
            .addComponentFillVertically(JPanel(), 0)
            .panel
    }

    override fun isModified(): Boolean {
        val settings = AdversarialInputsSettings.getInstance(project)

        return autoScanCheckBox?.isSelected != settings.autoScanOnOpen ||
                minVulnLevelComboBox?.selectedItem != settings.minVulnLevel ||
                parseLines(endpointAllowlistTextArea?.text ?: "") != settings.endpointAllowlist ||
                parseLines(targetFoldersTextArea?.text ?: "") != settings.targetFolders ||
                parseLines(agentFilesTextArea?.text ?: "") != settings.agentFiles
    }

    override fun apply() {
        val settings = AdversarialInputsSettings.getInstance(project)

        settings.autoScanOnOpen = autoScanCheckBox?.isSelected ?: true
        settings.minVulnLevel = minVulnLevelComboBox?.selectedItem as? Severity ?: Severity.HIGH
        settings.endpointAllowlist = parseLines(endpointAllowlistTextArea?.text ?: "").toMutableList()
        settings.targetFolders = parseLines(targetFoldersTextArea?.text ?: "").toMutableList()
        settings.agentFiles = parseLines(agentFilesTextArea?.text ?: "").toMutableList()

        // Update the service with new settings immediately
        val service = AdversarialInputsService.getInstance(project)
        service.updateSettings()
    }

    override fun reset() {
        val settings = AdversarialInputsSettings.getInstance(project)

        autoScanCheckBox?.isSelected = settings.autoScanOnOpen
        minVulnLevelComboBox?.selectedItem = settings.minVulnLevel
        endpointAllowlistTextArea?.text = settings.endpointAllowlist.joinToString("\n")
        targetFoldersTextArea?.text = settings.targetFolders.joinToString("\n")
        agentFilesTextArea?.text = settings.agentFiles.joinToString("\n")
    }

    private fun parseLines(text: String): List<String> {
        return text.split("\n")
            .map { it.trim() }
            .filter { it.isNotEmpty() }
    }
}
