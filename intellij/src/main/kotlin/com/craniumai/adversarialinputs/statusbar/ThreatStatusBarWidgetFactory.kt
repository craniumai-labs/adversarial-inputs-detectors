package com.craniumai.adversarialinputs.statusbar

import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory

/**
 * Factory for creating the threat status bar widget
 */
class ThreatStatusBarWidgetFactory : StatusBarWidgetFactory {

    override fun getId(): String = ThreatStatusBarWidget.ID

    override fun getDisplayName(): String = "Adversarial Inputs Threats"

    override fun isAvailable(project: Project): Boolean = true

    override fun createWidget(project: Project): StatusBarWidget {
        return ThreatStatusBarWidget(project)
    }

    override fun disposeWidget(widget: StatusBarWidget) {
        // Cleanup if needed
    }

    override fun canBeEnabledOn(statusBar: StatusBar): Boolean = true
}
