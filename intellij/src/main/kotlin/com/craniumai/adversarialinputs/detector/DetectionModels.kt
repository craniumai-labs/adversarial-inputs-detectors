package com.craniumai.adversarialinputs.detector

/**
 * Severity levels for detected threats
 */
enum class Severity {
    LOW, MEDIUM, HIGH, CRITICAL
}

/**
 * Result of analyzing a single file
 */
data class DetectionResult(
    val filePath: String,
    val score: Int,
    val verdict: Severity,
    val evidence: List<String>,
    val detectedPatterns: List<DetectedPattern>
)

/**
 * A single detected pattern within a file
 */
data class DetectedPattern(
    val type: String,
    val match: String,
    val line: Int,
    val column: Int,
    val score: Int,
    val verdict: Severity
)

/**
 * Invisible content detected in a line
 */
data class InvisibleContent(
    val content: String,
    val lineNumber: Int,
    val charCount: Int
)

/**
 * Result of checking if a character is invisible
 */
data class InvisibleCharResult(
    val isInvisible: Boolean,
    val decoded: String
)
