package com.craniumai.adversarialinputs.toolwindow

import com.craniumai.adversarialinputs.detector.DetectionResult
import com.craniumai.adversarialinputs.services.AdversarialInputsService
import com.craniumai.adversarialinputs.settings.AdversarialInputsSettings
import com.intellij.openapi.project.Project
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.table.JBTable
import javax.swing.JPanel
import javax.swing.table.DefaultTableModel
import java.awt.BorderLayout

/**
 * Factory for creating the Adversarial Inputs tool window
 */
class AdversarialInputsToolWindowFactory : ToolWindowFactory {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val toolWindowContent = AdversarialInputsToolWindowContent(project)
        val content = ContentFactory.getInstance().createContent(toolWindowContent.contentPanel, "", false)
        toolWindow.contentManager.addContent(content)
    }

    override fun shouldBeAvailable(project: Project): Boolean = true
}

/**
 * Content for the Adversarial Inputs tool window
 */
class AdversarialInputsToolWindowContent(private val project: Project) {

    val contentPanel: JPanel = JPanel(BorderLayout())
    private val tableModel: DefaultTableModel
    private val table: JBTable

    companion object {
        private val instances = mutableMapOf<Project, AdversarialInputsToolWindowContent>()

        fun getInstance(project: Project): AdversarialInputsToolWindowContent? {
            return instances[project]
        }
    }

    init {
        // Store this instance
        instances[project] = this
        // Create table model
        tableModel = DefaultTableModel(
            arrayOf("File", "Severity", "Score", "Evidence Count"),
            0
        )

        // Create table
        table = JBTable(tableModel)
        table.setShowGrid(true)

        // Add table to scroll pane
        val scrollPane = JBScrollPane(table)
        contentPanel.add(scrollPane, BorderLayout.CENTER)

        // Load initial data
        refreshData()
    }

    fun refreshData() {
        val service = AdversarialInputsService.getInstance(project)
        val settings = AdversarialInputsSettings.getInstance(project)
        val results = service.getAllScanResults()

        // Get project base path for relative path calculation
        val basePath = project.basePath ?: ""

        // Filter by minimum vulnerability level, then sort by score from highest to lowest
        val filteredResults = results.entries
            .filter { it.value.verdict.ordinal >= settings.minVulnLevel.ordinal }
            .sortedByDescending { it.value.score }

        // Prepare all rows first
        val rows = filteredResults.map { (filePath, result) ->
            // Show path relative to project root
            val relativePath = if (basePath.isNotEmpty() && filePath.startsWith(basePath)) {
                filePath.substring(basePath.length).trimStart('/')
            } else {
                filePath
            }

            // Count only patterns that meet the minimum vulnerability threshold
            val evidenceCount = result.detectedPatterns.count { pattern ->
                pattern.verdict.ordinal >= settings.minVulnLevel.ordinal
            }

            arrayOf(
                relativePath,
                result.verdict.toString(),
                "${result.score}/100",
                evidenceCount
            )
        }

        // Clear and add all rows at once
        tableModel.setRowCount(0)
        rows.forEach { row ->
            tableModel.addRow(row)
        }

        // Force table to repaint
        table.revalidate()
        table.repaint()
    }
}
