package com.craniumai.adversarialinputs.actions

import com.craniumai.adversarialinputs.detector.DetectionResult
import com.craniumai.adversarialinputs.detector.Severity
import com.craniumai.adversarialinputs.services.AdversarialInputsService
import com.craniumai.adversarialinputs.settings.AdversarialInputsSettings
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.PsiManager
import com.intellij.psi.search.FileTypeIndex
import com.intellij.psi.search.GlobalSearchScope

/**
 * Action to scan the entire project for adversarial inputs
 */
class ScanProjectAction : AnAction() {

    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        scanProject(project)
    }

    fun scanProject(project: Project) {
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "Scanning for Adversarial Inputs", false) {
            override fun run(indicator: ProgressIndicator) {
                indicator.isIndeterminate = false
                indicator.text = "Finding files..."

                val service = AdversarialInputsService.getInstance(project)
                val detector = service.getDetector()
                val settings = AdversarialInputsSettings.getInstance(project)

                // Clear previous results
                service.clearScanResults()

                // Get all text files in the project
                val allFiles = mutableListOf<VirtualFile>()
                ApplicationManager.getApplication().runReadAction {
                    // Use project base directory to scan all files
                    val baseDir = project.basePath?.let { LocalFileSystem.getInstance().findFileByPath(it) }
                    if (baseDir != null) {
                        collectTextFiles(arrayOf(baseDir), allFiles, project)
                    }
                }

                val totalFiles = allFiles.size
                println("Found $totalFiles potential text files")

                var scannedFiles = 0
                val threats = mutableListOf<Pair<String, DetectionResult>>()

                // Scan each file
                for (file in allFiles) {
                    if (indicator.isCanceled) break

                    indicator.fraction = scannedFiles.toDouble() / totalFiles
                    indicator.text = "Scanning ${file.name} ($scannedFiles/$totalFiles)..."

                    ApplicationManager.getApplication().runReadAction {
                        try {
                            val document = FileDocumentManager.getInstance().getDocument(file)
                            val content = document?.text ?: ""

                            if (content.isNotEmpty()) {
                                val result = detector.analyzeFile(file.path, content)
                                service.storeScanResult(file.path, result)

                                if (result.verdict.ordinal >= settings.minVulnLevel.ordinal) {
                                    threats.add(file.name to result)
                                }
                            }
                        } catch (ex: Exception) {
                            println("Error scanning file ${file.path}: ${ex.message}")
                        }
                    }

                    scannedFiles++
                }

                // Show results
                ApplicationManager.getApplication().invokeLater {
                    showScanResults(project, totalFiles, threats)

                    // Refresh the tool window to show updated results
                    com.craniumai.adversarialinputs.toolwindow.AdversarialInputsToolWindowContent.getInstance(project)?.refreshData()
                }
            }
        })
    }

    private fun collectTextFiles(files: Array<VirtualFile>, result: MutableList<VirtualFile>, project: Project) {
        for (file in files) {
            if (file.isDirectory) {
                // Skip common binary/build directories
                if (file.name in setOf("node_modules", ".git", "dist", "build", "out", "coverage", "__pycache__", "target", "bin", "obj")) {
                    continue
                }
                collectTextFiles(file.children, result, project)
            } else {
                // Check if it's a text file
                if (isTextFile(file)) {
                    result.add(file)
                }
            }
        }
    }

    private fun isTextFile(file: VirtualFile): Boolean {
        val textExtensions = setOf(
            "md", "txt", "rst", "adoc", "org", "html", "htm", "xml", "json", "yaml", "yml",
            "toml", "ini", "cfg", "conf", "properties", "ts", "tsx", "js", "jsx", "py", "java",
            "kt", "kts", "go", "rs", "c", "cpp", "h", "hpp", "cs", "rb", "php", "sh", "bash"
        )
        return file.extension?.lowercase() in textExtensions
    }

    private fun showScanResults(project: Project, totalFiles: Int, threats: List<Pair<String, DetectionResult>>) {
        val notificationGroup = NotificationGroupManager.getInstance()
            .getNotificationGroup("Adversarial Inputs Detector")

        if (threats.isEmpty()) {
            notificationGroup.createNotification(
                "Scan Complete",
                "Scanned $totalFiles files. No adversarial input threats detected.",
                NotificationType.INFORMATION
            ).notify(project)
        } else {
            val criticalCount = threats.count { it.second.verdict == Severity.CRITICAL }
            val highCount = threats.count { it.second.verdict == Severity.HIGH }
            val mediumCount = threats.count { it.second.verdict == Severity.MEDIUM }
            val lowCount = threats.count { it.second.verdict == Severity.LOW }

            val message = buildString {
                append("Scanned $totalFiles files\n")
                append("Found ${threats.size} potential threat(s):\n")
                if (criticalCount > 0) append("🚨 CRITICAL: $criticalCount file(s)\n")
                if (highCount > 0) append("⚠️ HIGH: $highCount file(s)\n")
                if (mediumCount > 0) append("⚡ MEDIUM: $mediumCount file(s)\n")
                if (lowCount > 0) append("ℹ️ LOW: $lowCount file(s)")
            }

            val notificationType = if (criticalCount > 0) {
                NotificationType.ERROR
            } else {
                NotificationType.WARNING
            }

            notificationGroup.createNotification(
                "Scan Complete - Threats Detected",
                message,
                notificationType
            ).notify(project)
        }
    }
}
