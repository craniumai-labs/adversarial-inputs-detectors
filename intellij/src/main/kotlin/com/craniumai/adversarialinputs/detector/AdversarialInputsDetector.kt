package com.craniumai.adversarialinputs.detector

import kotlin.math.max
import kotlin.math.min

/**
 * Adversarial Inputs Detection Engine
 * Detects adversarial inputs in documentation files that can hijack AI coding agents
 */
class AdversarialInputsDetector(
    targetFolders: List<String>? = null,
    specialAgentFiles: List<String>? = null
) {
    // Endpoint allowlist (set via setEndpointAllowlist method)
    private var endpointAllowlist: List<String> = DEFAULT_ALLOW_LIST_PATTERNS

    // Target folders for self-propagation detection (configurable)
    private val targetFolders: List<String> = targetFolders ?: DEFAULT_TARGET_FOLDERS

    // Special agent files for self-propagation detection (configurable)
    private val specialAgentFiles: List<String> = specialAgentFiles ?: DEFAULT_AGENT_FILES

    companion object {
        // Default allowlist patterns
        val DEFAULT_ALLOW_LIST_PATTERNS = listOf(
            "*",
        )
        
        // Default target folders
        val DEFAULT_TARGET_FOLDERS = listOf(
            ".windsurf/workflows",
            ".cursor/commands",
            ".github",
            ".github/instructions"
        )

        // Default special agent files
        val DEFAULT_AGENT_FILES = listOf(
            "agents.md",
            "claude.md",
            "gemini.md"
        )

        // Invisible character mappings
        val DANGEROUS_CHARS = mapOf(
            0x200B to "[⎵]", // Zero Width Space
            0x200C to "[⎵]", // Zero Width Non-Joiner
            0x200D to "[⎵]", // Zero Width Joiner
            0xFEFF to "[⎵]", // Zero Width No-Break Space / BOM
            0x202E to "[⥴]", // Right-to-Left Override
            0x202D to "[⥱]", // Left-to-Right Override
            0x2060 to "[⎵]", // Word Joiner
            0x180E to "[⎵]", // Mongolian Vowel Separator
            0x2061 to "[∘]", // Function Application
            0x2062 to "[×]", // Invisible Times
            0x2063 to "[｜]", // Invisible Separator
            0x2064 to "[+]"  // Invisible Plus
        )

        // Local endpoint pattern
        val LOCAL_ENDPOINT_PATTERN = Regex(
            """^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1]?)(:\d+)?(/|\?|$)""",
            RegexOption.IGNORE_CASE
        )

        // Endpoint scoring rules
        data class ScoringRule(val pattern: Regex, val score: Int, val description: String)

        val ENDPOINT_SCORING_RULES = listOf(
            ScoringRule(Regex("^data:", RegexOption.IGNORE_CASE), 70, "Data URI"),
            ScoringRule(Regex("""[?&](?:token|auth|access_token|api_key|key|sig)""", RegexOption.IGNORE_CASE), 60, "Token parameter"),
            ScoringRule(Regex("""[a-zA-Z0-9_-]{32,}\."""), 40, "Long/base64-like domain"),
            ScoringRule(Regex("""\b(bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|buff\.ly)\b"""), 30, "URL shortener"),
            ScoringRule(Regex("""^https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1]?)(.*)""", RegexOption.IGNORE_CASE), 30, "External URL"),
            ScoringRule(Regex("""\{\{.*?}}|\{[\w:-]+}|:[A-Za-z_]+"""), 25, "Template placeholder"),
            ScoringRule(Regex("^mailto:", RegexOption.IGNORE_CASE), 20, "Mailto link")
        )

        // Common file extensions to filter out
        val COMMON_FILE_EXTENSIONS = setOf(
            ".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".java", ".c", ".cpp", ".h", ".hpp",
            ".rs", ".rb", ".php", ".cs", ".swift", ".kt", ".m", ".mm",
            ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
            ".md", ".txt", ".rst", ".adoc",
            ".html", ".htm", ".css", ".scss", ".sass", ".less",
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".webp",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
            ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
            ".so", ".dll", ".dylib", ".exe", ".app",
            ".lock", ".sum", ".mod"
        )
    }

    /**
     * Set the endpoint allowlist for filtering out legitimate URLs
     */
    fun setEndpointAllowlist(allowlist: List<String>) {
        this.endpointAllowlist = allowlist
        println("[Allowlist] Endpoint allowlist updated: ${allowlist.size} patterns")
    }

    /**
     * Check if an endpoint matches any pattern in the allowlist
     * Supports wildcards: * (any characters) and ? (single character)
     */
    private fun isAllowlisted(endpoint: String): Boolean {
        val lowerEndpoint = endpoint.lowercase()

        for (pattern in endpointAllowlist) {
            val lowerPattern = pattern.lowercase()

            // Convert wildcard pattern to regex
            val regexPattern = lowerPattern
                .replace(Regex("[.+^\${}()|\\[\\]\\\\]")) { "\\${it.value}" }  // Escape special chars
                .replace("*", ".*")                                    // * becomes .*
                .replace("?", ".")                                     // ? becomes .

            val regex = Regex("^$regexPattern$")

            if (regex.matches(lowerEndpoint)) {
                println("  [Allowlist] Skipping allowlisted endpoint: $endpoint")
                return true
            }
        }

        return false
    }

    /**
     * Analyze a file for adversarial patterns using stealth-first hierarchy
     */
    fun analyzeFile(filePath: String, content: String): DetectionResult {
        println("\n=== ANALYZING FILE: $filePath ===")
        println("Content length (original): ${content.length} characters")

        // Normalize line endings to handle Windows/Unix differences
        var normalizedContent = content.replace("\r\n", "\n")
        if (content.length != normalizedContent.length) {
            println("Line endings normalized: Windows → Unix")
            println("Content length (normalized): ${normalizedContent.length} characters")
        }

        var riskScore = 0
        val evidence = mutableListOf<String>()
        val detectedPatterns = mutableListOf<DetectedPattern>()

        // Check for invisible content (unicode-based stealth)
        println("\nChecking for invisible Unicode characters...")
        val invisibleContent = extractInvisibleContent(normalizedContent)
        println("Lines with invisible characters: ${invisibleContent.size}")

        // Count total invisible characters
        val totalInvisibleChars = invisibleContent.sumOf { it.charCount }

        // Handle invisible content scoring
        if (invisibleContent.isNotEmpty()) {
            println("\n[INVISIBLE CHARACTER ANALYSIS]")
            println("  Total invisible characters: $totalInvisibleChars")

            when {
                totalInvisibleChars >= 100 -> println("  ⚠️ CRITICAL: 100+ invisible characters detected")
                totalInvisibleChars >= 50 -> println("  ⚠️ HIGH: 50-99 invisible characters detected")
                totalInvisibleChars >= 20 -> println("  ⚠️ MEDIUM: 20-49 invisible characters detected")
                else -> println("  ⚠️ LOW: 1-19 invisible characters detected")
            }

            riskScore = max(totalInvisibleChars, riskScore)
            evidence.add("Invisible Unicode characters detected ($totalInvisibleChars)")

            // Add invisible character patterns with decoded lines
            for (inv in invisibleContent) {
                val patternScore = inv.charCount
                detectedPatterns.add(
                    DetectedPattern(
                        type = "Invisible Unicode Characters",
                        match = inv.content,
                        line = inv.lineNumber,
                        column = 0,
                        score = patternScore,
                        verdict = calculateVerdict(patternScore)
                    )
                )
            }
        }

        // Check for exfiltration endpoints
        println("\nChecking for exfiltration endpoints")
        val exfilResults = detectExfilEndpoints(normalizedContent)
        println("Exfiltration endpoints found: ${exfilResults.size}")
        if (exfilResults.isNotEmpty()) {
            println("✓ Exfiltration endpoints detected")
            exfilResults.forEachIndexed { index, result ->
                println("  ${index + 1}. \"${result.match}\" at line ${result.line}, col ${result.column} (score: ${result.score}, verdict: ${result.verdict})")
            }
            val maxScore = exfilResults.maxOf { it.score }
            riskScore = max(maxScore, riskScore)
            evidence.add("Potential exfiltration endpoints detected (${exfilResults.size})")
            detectedPatterns.addAll(exfilResults)
        } else {
            println("❌ No exfiltration endpoints found")
        }

        // Check for self-propagation patterns
        println("\nChecking for self-propagation patterns")
        val selfPropResults = detectSelfPropagation(normalizedContent)
        println("Self-propagation patterns found: ${selfPropResults.size}")
        if (selfPropResults.isNotEmpty()) {
            println("✓ Self-propagation patterns detected (+80 points)")
            selfPropResults.forEachIndexed { index, result ->
                println("  ${index + 1}. \"${result.match}\" at line ${result.line}, col ${result.column} (score: ${result.score}, verdict: ${result.verdict})")
            }
            riskScore = max(80, riskScore)
            evidence.add("Potential self-propagation patterns detected (${selfPropResults.size})")
            detectedPatterns.addAll(selfPropResults)
        } else {
            println("❌ No self-propagation patterns found")
        }

        // Calculate verdict based on thresholds
        val verdict = calculateVerdict(riskScore)

        println("\n[FINAL RESULTS]")
        println("Final score: $riskScore / 100")
        println("Verdict: $verdict")
        println("Total evidence: ${evidence.size}")
        println("All evidence: $evidence")
        println("Total detected patterns: ${detectedPatterns.size}")
        println("=== END ANALYSIS ===\n")

        return DetectionResult(
            filePath = filePath,
            score = min(riskScore, 100),
            verdict = verdict,
            evidence = evidence,
            detectedPatterns = detectedPatterns
        )
    }

    /**
     * Extract invisible/non-printable Unicode characters that may hide malicious instructions
     */
    private fun extractInvisibleContent(content: String): List<InvisibleContent> {
        println("  [extractInvisibleContent] Starting extraction...")
        println("  [extractInvisibleContent] Content length: ${content.length}")

        val invisibleBlocks = mutableListOf<InvisibleContent>()
        val lines = content.split('\n')

        for ((i, line) in lines.withIndex()) {
            val lineNumber = i + 1
            var hasInvisible = false
            val decodedLine = StringBuilder()
            var charCount = 0

            val runes = line.toList()
            var j = 0

            while (j < runes.size) {
                val codePoint = line.codePointAt(j)
                val invisibleResult = isInvisibleChar(codePoint)

                if (invisibleResult.isInvisible) {
                    // Check for consecutive variation selectors
                    if (isVariationSelector(codePoint)) {
                        var consecutiveVS = 1
                        var k = j + 1

                        while (k < runes.size) {
                            val nextCodePoint = line.codePointAt(k)
                            if (isVariationSelector(nextCodePoint)) {
                                consecutiveVS++
                                k++
                            } else {
                                break
                            }
                        }

                        // Only flag if 2+ consecutive variation selectors
                        if (consecutiveVS >= 2) {
                            for (m in j until k) {
                                val cp = line.codePointAt(m)
                                val decoded = isInvisibleChar(cp).decoded
                                decodedLine.append(decoded)
                                charCount++
                            }
                            hasInvisible = true
                            j = k
                            continue
                        } else {
                            decodedLine.append(runes[j])
                        }
                    } else {
                        decodedLine.append(invisibleResult.decoded)
                        charCount++
                        hasInvisible = true
                    }
                } else {
                    decodedLine.append(runes[j])
                }
                j++
            }

            if (hasInvisible) {
                val securityNote = categorizeInvisibleChars(line)

                println("  [INVISIBLE] Line $lineNumber:")
                println("    - Invisible characters: $charCount")
                println("    - Security note: $securityNote")
                val preview = decodedLine.toString().take(80)
                println("    - Decoded: \"$preview${if (decodedLine.length > 80) "..." else ""}\"")

                invisibleBlocks.add(
                    InvisibleContent(
                        content = decodedLine.toString(),
                        lineNumber = lineNumber,
                        charCount = charCount
                    )
                )
            }
        }

        println("\n[INVISIBLE SUMMARY]")
        println("  Total lines with invisible characters: ${invisibleBlocks.size}")

        return invisibleBlocks
    }

    /**
     * Check if a Unicode code point is an invisible/non-printable character
     */
    private fun isInvisibleChar(codePoint: Int): InvisibleCharResult {
        // Unicode tag characters (U+E0000-U+E007F)
        if (codePoint in 0xE0020..0xE007E) {
            val asciiValue = codePoint - 0xE0000
            // Only decode if the ASCII character is printable (0x20-0x7E)
            if (asciiValue in 0x20..0x7E) {
                val asciiChar = String(intArrayOf(asciiValue), 0, 1)
                return InvisibleCharResult(true, asciiChar)
            }
            // Skip non-printable ASCII (control characters)
            return InvisibleCharResult(false, "")
        }
        if (codePoint in 0xE0000..0xE007F) {
            // Skip other tag characters that don't map to printable ASCII
            return InvisibleCharResult(false, "")
        }

        // Variation Selectors (VS1-VS16: U+FE00 to U+FE0F)
        if (codePoint in 0xFE00..0xFE0F) {
            return InvisibleCharResult(true, "[VS${codePoint - 0xFE00 + 1}]")
        }

        // Variation Selectors Supplement (VS17-VS256: U+E0100 to U+E01EF)
        if (codePoint in 0xE0100..0xE01EF) {
            return InvisibleCharResult(true, "[VS${codePoint - 0xE0100 + 17}]")
        }

        // Specific dangerous characters with symbols
        if (codePoint in DANGEROUS_CHARS) {
            return InvisibleCharResult(true, DANGEROUS_CHARS[codePoint]!!)
        }

        // Check Unicode categories
        val categories = getUnicodeCategory(codePoint)

        // Format characters (Cf) - mostly invisible
        if ("Cf" in categories) {
            return InvisibleCharResult(true, "[U+${codePoint.toString(16).uppercase().padStart(4, '0')}]")
        }

        // Control characters (Cc) except printable whitespace
        if ("Cc" in categories && codePoint !in listOf(0x0A, 0x0D, 0x09)) {
            return InvisibleCharResult(true, "[U+${codePoint.toString(16).uppercase().padStart(4, '0')}]")
        }

        // Private use characters (Co) - often used for steganography
        if ("Co" in categories) {
            return InvisibleCharResult(true, "[U+${codePoint.toString(16).uppercase().padStart(4, '0')}]")
        }

        return InvisibleCharResult(false, "")
    }

    /**
     * Check if a code point is a variation selector
     */
    private fun isVariationSelector(codePoint: Int): Boolean {
        return codePoint in 0xFE00..0xFE0F || codePoint in 0xE0100..0xE01EF
    }

    /**
     * Check if a code point is a Unicode tag character
     */
    private fun isTagCharacter(codePoint: Int): Boolean {
        return codePoint in 0xE0000..0xE007F
    }

    /**
     * Get Unicode category for a code point (simplified)
     */
    private fun getUnicodeCategory(codePoint: Int): List<String> {
        val categories = mutableListOf<String>()

        // Format characters (Cf)
        if (codePoint in 0x00AD..0x00AD || codePoint in 0x0600..0x0605 ||
            codePoint in 0x061C..0x061C || codePoint in 0x06DD..0x06DD ||
            codePoint in 0x070F..0x070F || codePoint in 0x180E..0x180E ||
            codePoint in 0x200B..0x200F || codePoint in 0x202A..0x202E ||
            codePoint in 0x2060..0x2064 || codePoint in 0x2066..0x206F ||
            codePoint in 0xFEFF..0xFEFF || codePoint in 0xFFF9..0xFFFB
        ) {
            categories.add("Cf")
        }

        // Control characters (Cc)
        if (codePoint in 0x0000..0x001F || codePoint in 0x007F..0x009F) {
            categories.add("Cc")
        }

        // Private use characters (Co)
        if (codePoint in 0xE000..0xF8FF || codePoint in 0xF0000..0xFFFFD ||
            codePoint in 0x100000..0x10FFFD
        ) {
            categories.add("Co")
        }

        return categories
    }

    /**
     * Categorize invisible characters and return a security note
     */
    private fun categorizeInvisibleChars(line: String): String {
        var hasTagChars = false
        var hasVariationSelectors = false
        var hasZeroWidth = false
        var hasBidiOverride = false
        var hasOther = false

        for (char in line) {
            val codePoint = char.code
            val invisResult = isInvisibleChar(codePoint)

            if (invisResult.isInvisible) {
                when {
                    isTagCharacter(codePoint) -> hasTagChars = true
                    isVariationSelector(codePoint) -> hasVariationSelectors = true
                    codePoint in listOf(0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060) -> hasZeroWidth = true
                    codePoint in listOf(0x202E, 0x202D) -> hasBidiOverride = true
                    else -> hasOther = true
                }
            }
        }

        val notes = mutableListOf<String>()

        if (hasTagChars) {
            notes.add("Unicode Tag characters may hide invisible instructions or exfiltrate data")
        }
        if (hasVariationSelectors) {
            notes.add("Consecutive Unicode Variation Selectors may be used for steganography")
        }
        if (hasZeroWidth) {
            notes.add("Zero-width characters can hide data, create homograph attacks, or bypass filters")
        }
        if (hasBidiOverride) {
            notes.add("Bidirectional Override characters can disguise malicious content")
        }
        if (hasOther) {
            notes.add("Other invisible characters may be used for steganography or obfuscation")
        }

        return if (notes.isEmpty()) {
            "Invisible characters may be used for hiding instructions or exfiltrating data"
        } else {
            notes.joinToString("; ")
        }
    }

    /**
     * Detect exfiltration endpoints in entire file content
     */
    private fun detectExfilEndpoints(content: String): List<DetectedPattern> {
        val results = mutableListOf<DetectedPattern>()

        // Regex patterns for endpoint detection
        val urlRe = Regex("""\b(?:https?|wss?|ftp)://[^\s)>\]]+""", RegexOption.IGNORE_CASE)
        val dataUriRe = Regex("""\bdata:(?:image|application)/[^\s;,]+;base64,[A-Za-z0-9+/=]{1,20}""", RegexOption.IGNORE_CASE)
        val mailtoRe = Regex("""\bmailto:[^\s)>\]]+""", RegexOption.IGNORE_CASE)

        val lines = content.split('\n')

        lines.forEachIndexed { index, line ->
            val lineNumber = index + 1

            // Detect URLs
            urlRe.findAll(line).forEach { match ->
                val url = match.value
                if (!isAllowlisted(url) && !hasCommonFileExtension(url)) {
                    val patternScore = calculateEndpointScore(url)
                    results.add(
                        DetectedPattern(
                            type = "Potential Exfiltration Endpoint: URL",
                            match = url,
                            line = lineNumber,
                            column = match.range.first,
                            score = patternScore,
                            verdict = calculateVerdict(patternScore)
                        )
                    )
                }
            }

            // Detect data URIs
            dataUriRe.findAll(line).forEach { match ->
                val dataUri = match.value
                if (!isAllowlisted(dataUri)) {
                    val patternScore = calculateEndpointScore(dataUri)
                    results.add(
                        DetectedPattern(
                            type = "Potential Exfiltration Endpoint: Data URI",
                            match = "$dataUri...",
                            line = lineNumber,
                            column = match.range.first,
                            score = patternScore,
                            verdict = calculateVerdict(patternScore)
                        )
                    )
                }
            }

            // Detect mailto links
            mailtoRe.findAll(line).forEach { match ->
                val mailto = match.value
                if (!isAllowlisted(mailto)) {
                    val patternScore = calculateEndpointScore(mailto)
                    results.add(
                        DetectedPattern(
                            type = "Potential Exfiltration Endpoint: Mailto",
                            match = mailto,
                            line = lineNumber,
                            column = match.range.first,
                            score = patternScore,
                            verdict = calculateVerdict(patternScore)
                        )
                    )
                }
            }
        }

        return results
    }

    /**
     * Detect self-propagation patterns in entire file content
     */
    private fun detectSelfPropagation(content: String): List<DetectedPattern> {
        val results = mutableListOf<DetectedPattern>()
        val lines = content.split('\n')

        lines.forEachIndexed { index, line ->
            val lineNumber = index + 1

            // Check for target folder references
            results.addAll(
                detectPatternMatches(
                    line,
                    lineNumber,
                    targetFolders,
                    "Potential Self-Propagation Target: Trusted Folder",
                    """(^|\s|/|'|")(PATTERN)(?:\s|$|/|'|"(?:\s|$))"""
                )
            )

            // Check for special agent file references
            results.addAll(
                detectPatternMatches(
                    line,
                    lineNumber,
                    specialAgentFiles,
                    "Potential Self-Propagation Target: Agent File",
                    """(^|\s)(PATTERN)(\s|$)"""
                )
            )
        }

        return results
    }

    /**
     * Helper to detect pattern matches and add to results
     */
    private fun detectPatternMatches(
        originalLine: String,
        lineNumber: Int,
        patterns: List<String>,
        detectionType: String,
        regexTemplate: String
    ): List<DetectedPattern> {
        val lowerLine = originalLine.lowercase()
        val results = mutableListOf<DetectedPattern>()

        for (pattern in patterns) {
            val escapedPattern = Regex.escape(pattern)
            val regexStr = regexTemplate.replace("PATTERN", escapedPattern)
            val regex = Regex(regexStr, RegexOption.IGNORE_CASE)

            regex.findAll(lowerLine).forEach { match ->
                val patternScore = 80 // High score for self-propagation
                val matchStart = match.range.first + match.groupValues[1].length
                results.add(
                    DetectedPattern(
                        type = detectionType,
                        match = originalLine.substring(matchStart, matchStart + pattern.length),
                        line = lineNumber,
                        column = matchStart,
                        score = patternScore,
                        verdict = calculateVerdict(patternScore)
                    )
                )
            }
        }

        return results
    }

    /**
     * Calculate endpoint score based on heuristics
     */
    private fun calculateEndpointScore(endpoint: String): Int {
        val lowerEndpoint = endpoint.lowercase()

        // Local endpoints are safe (0 points)
        if (LOCAL_ENDPOINT_PATTERN.matches(lowerEndpoint)) {
            return 0
        }

        var score = 0

        // Apply all scoring rules
        for (rule in ENDPOINT_SCORING_RULES) {
            if (rule.pattern.containsMatchIn(lowerEndpoint)) {
                score += rule.score
            }
        }

        return min(score, 100)
    }

    /**
     * Check if path has a common file extension
     */
    private fun hasCommonFileExtension(path: String): Boolean {
        val lowerPath = path.lowercase()
        return COMMON_FILE_EXTENSIONS.any { lowerPath.endsWith(it) }
    }

    /**
     * Calculate verdict based on score thresholds
     */
    private fun calculateVerdict(score: Int): Severity {
        return when {
            score >= 80 -> Severity.CRITICAL
            score >= 50 -> Severity.HIGH
            score >= 30 -> Severity.MEDIUM
            else -> Severity.LOW
        }
    }
}
