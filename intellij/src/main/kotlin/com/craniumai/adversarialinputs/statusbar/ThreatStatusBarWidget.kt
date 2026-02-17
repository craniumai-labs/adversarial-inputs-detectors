package com.craniumai.adversarialinputs.statusbar

import com.craniumai.adversarialinputs.services.AdversarialInputsService
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.popup.JBPopupFactory
import com.intellij.openapi.ui.popup.ListPopup
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.impl.status.EditorBasedWidget
import com.intellij.ui.awt.RelativePoint
import java.awt.event.MouseEvent
import javax.swing.JComponent

/**
 * Status bar widget that displays threat count
 */
class ThreatStatusBarWidget(project: Project) : EditorBasedWidget(project), StatusBarWidget.MultipleTextValuesPresentation {

    companion object {
        const val ID = "AdversarialInputsStatusBar"
    }

    override fun ID(): String = ID

    override fun getTooltipText(): String {
        val service = AdversarialInputsService.getInstance(project)
        val threatCount = service.getThreatCount()

        return if (threatCount > 0) {
            "$threatCount adversarial input threat${if (threatCount > 1) "s" else ""} detected. Click for details."
        } else {
            "No threats detected"
        }
    }

    override fun getSelectedValue(): String {
        val service = AdversarialInputsService.getInstance(project)
        val threatCount = service.getThreatCount()

        return if (threatCount > 0) {
            val icon = if (service.hasCriticalThreats()) "🚨" else "⚠️"
            "$icon $threatCount Threat${if (threatCount > 1) "s" else ""}"
        } else {
            ""
        }
    }

    override fun getClickConsumer(): com.intellij.util.Consumer<MouseEvent>? {
        return com.intellij.util.Consumer { e ->
            if (e.component is JComponent) {
                showPopup(e.component as JComponent)
            }
        }
    }

    private fun showPopup(component: JComponent) {
        val service = AdversarialInputsService.getInstance(project)
        val results = service.getAllScanResults()

        if (results.isEmpty()) {
            return
        }

        val message = buildString {
            append("Detected threats:\n")
            results.forEach { (path, result) ->
                append("• ${path.substringAfterLast("/")}: ${result.verdict} (${result.score}/100)\n")
            }
        }

        JBPopupFactory.getInstance()
            .createMessage(message)
            .show(RelativePoint.getSouthWestOf(component))
    }

    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this
}
