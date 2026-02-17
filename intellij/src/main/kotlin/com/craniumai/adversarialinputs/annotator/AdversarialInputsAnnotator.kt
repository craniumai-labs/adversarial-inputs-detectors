package com.craniumai.adversarialinputs.annotator

import com.craniumai.adversarialinputs.detector.DetectionResult
import com.craniumai.adversarialinputs.detector.Severity
import com.craniumai.adversarialinputs.services.AdversarialInputsService
import com.craniumai.adversarialinputs.settings.AdversarialInputsSettings
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.editor.Document
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile

/**
 * External annotator that provides real-time diagnostics for adversarial inputs
 */
class AdversarialInputsAnnotator : ExternalAnnotator<PsiFile, DetectionResult>() {

    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): PsiFile? {
        // Skip injected language fragments to avoid duplicate annotations
        if (file.context != null) {
            return null
        }

        // Only process files that are the base language view
        val basePsi = file.viewProvider.getPsi(file.viewProvider.baseLanguage)
        if (file != basePsi) {
            return null
        }

        return file
    }

    override fun doAnnotate(file: PsiFile?): DetectionResult? {
        if (file == null) return null

        val project = file.project
        val service = AdversarialInputsService.getInstance(project)
        val detector = service.getDetector()

        // Get file content
        val content = file.text ?: return null
        val filePath = file.virtualFile?.path ?: return null

        // Run detection
        val result = detector.analyzeFile(filePath, content)

        // Store result in service
        service.storeScanResult(filePath, result)

        return result
    }

    override fun apply(file: PsiFile, annotationResult: DetectionResult?, holder: AnnotationHolder) {
        if (annotationResult == null) return

        val project = file.project
        val settings = AdversarialInputsSettings.getInstance(project)
        val document = file.viewProvider.document ?: return

        // Check if result exceeds minimum threshold
        if (annotationResult.verdict.ordinal < settings.minVulnLevel.ordinal) {
            return
        }

        // Deduplicate patterns by line, column, and type to avoid duplicate annotations
        val uniquePatterns = annotationResult.detectedPatterns.distinctBy {
            Triple(it.line, it.column, it.type)
        }

        // Add annotations for each detected pattern
        for (pattern in uniquePatterns) {
            // Skip patterns below threshold
            if (pattern.verdict.ordinal < settings.minVulnLevel.ordinal) {
                continue
            }

            // Validate line number
            if (pattern.line < 1 || pattern.line > document.lineCount) {
                continue
            }

            val lineIndex = pattern.line - 1
            val lineStartOffset = document.getLineStartOffset(lineIndex)
            val lineEndOffset = document.getLineEndOffset(lineIndex)
            val lineLength = lineEndOffset - lineStartOffset

            // Calculate range
            val startOffset = lineStartOffset + pattern.column.coerceIn(0, lineLength)
            val endOffset = (startOffset + pattern.match.length).coerceIn(startOffset, lineEndOffset)

            // For invisible characters, highlight the entire line for visibility
            val range = if (pattern.type == "Invisible Unicode Characters") {
                TextRange(lineStartOffset, lineEndOffset.coerceAtLeast(lineStartOffset + 1))
            } else {
                TextRange(startOffset, endOffset.coerceAtLeast(startOffset + 1))
            }

            // Determine severity
            val severity = when (pattern.verdict) {
                Severity.CRITICAL, Severity.HIGH -> HighlightSeverity.ERROR
                Severity.MEDIUM, Severity.LOW -> HighlightSeverity.WARNING
            }

            // Create annotation
            val message = buildString {
                append("Severity: [${pattern.verdict}]\n")
                append("Score: ${pattern.score}\n")
                append("Type: ${pattern.type}\n")
                append("Evidence: \"${pattern.match}\"")
            }

            holder.newAnnotation(severity, message)
                .range(range)
                .create()
        }

        // Add file-level summary annotation at the top
        if (annotationResult.detectedPatterns.isNotEmpty()) {
            val firstLineRange = TextRange(0, 0)

            // Count evidence by type
            val evidenceCount = mutableMapOf<String, Int>()
            for (pattern in annotationResult.detectedPatterns) {
                if (pattern.verdict.ordinal >= settings.minVulnLevel.ordinal) {
                    evidenceCount[pattern.type] = (evidenceCount[pattern.type] ?: 0) + 1
                }
            }

            val evidenceList = evidenceCount.entries
                .mapIndexed { index, (type, count) -> "${index + 1}. $type ($count)" }
                .joinToString("\n")

            val summaryMessage = buildString {
                append("⚠️ Summary of Potential Malicious Contents\n")
                append("Risk Score: ${annotationResult.score}/100\n")
                append("Severity: (${annotationResult.verdict})\n")
                append("Evidence:\n$evidenceList")
            }

            val summarySeverity = when (annotationResult.verdict) {
                Severity.CRITICAL, Severity.HIGH -> HighlightSeverity.ERROR
                Severity.MEDIUM, Severity.LOW -> HighlightSeverity.WARNING
            }

            holder.newAnnotation(summarySeverity, summaryMessage)
                .range(firstLineRange)
                .create()
        }
    }
}
