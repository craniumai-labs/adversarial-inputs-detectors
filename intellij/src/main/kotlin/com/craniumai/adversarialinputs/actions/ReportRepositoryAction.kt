package com.craniumai.adversarialinputs.actions

import com.intellij.ide.BrowserUtil
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent

/**
 * Action to report a repository containing adversarial inputs
 */
class ReportRepositoryAction : AnAction() {

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return

        val notificationGroup = NotificationGroupManager.getInstance()
            .getNotificationGroup("Adversarial Inputs Detector")

        notificationGroup.createNotification(
            "Report Repository",
            "Coming soon! You'll be able to report malicious repos to help protect the community.",
            NotificationType.INFORMATION
        ).addAction(object : com.intellij.notification.NotificationAction("Learn More") {
            override fun actionPerformed(e: AnActionEvent, notification: com.intellij.notification.Notification) {
                BrowserUtil.browse("https://cranium.ai")
                notification.expire()
            }
        }).notify(project)
    }
}
