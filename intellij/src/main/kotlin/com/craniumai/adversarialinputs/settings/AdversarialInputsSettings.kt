package com.craniumai.adversarialinputs.settings

import com.craniumai.adversarialinputs.detector.Severity
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.project.Project
import com.intellij.util.xmlb.XmlSerializerUtil

/**
 * Persistent settings for the Adversarial Inputs Detector plugin
 */
@State(
    name = "AdversarialInputsSettings",
    storages = [Storage("adversarial-inputs-detector.xml")]
)
class AdversarialInputsSettings : PersistentStateComponent<AdversarialInputsSettings> {

    var autoScanOnOpen: Boolean = true
    var minVulnLevel: Severity = Severity.HIGH
    var endpointAllowlist: MutableList<String> = mutableListOf("*")
    var targetFolders: MutableList<String> = mutableListOf(
        ".windsurf/workflows",
        ".cursor/commands",
        ".github",
        ".github/instructions"
    )
    var agentFiles: MutableList<String> = mutableListOf(
        "agents.md",
        "claude.md",
        "gemini.md"
    )

    override fun getState(): AdversarialInputsSettings = this

    override fun loadState(state: AdversarialInputsSettings) {
        XmlSerializerUtil.copyBean(state, this)
    }

    companion object {
        fun getInstance(project: Project): AdversarialInputsSettings {
            return project.getService(AdversarialInputsSettings::class.java)
        }
    }
}
