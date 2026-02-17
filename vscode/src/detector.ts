/**
 * Adversarial Inputs Detection Engine
 * Detects adversarial inputs in documentation files that can hijack AI coding agents
 * 
 *   Copyright (C) 2026  Cranium AI
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// One per file
export interface DetectionResult {
    filePath: string;
    score: number;
    verdict: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    evidence: string[];
    detectedPatterns: DetectedPattern[];
}

// One per pattern
export interface DetectedPattern {
    type: string;
    match: string;
    line: number;
    column: number;  // Character position within the line
    score: number;
    verdict: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export class PromptInjectionDetector {

    // Endpoint allowlist (set via setEndpointAllowlist method)
    private endpointAllowlist: string[] = [];

    // Target folders for self-propagation detection (configurable)
    private targetFolders: string[];

    // Special agent files for self-propagation detection (configurable)
    private specialAgentFiles: string[];

    // Default target folders
    private static readonly DEFAULT_TARGET_FOLDERS = [
        '.windsurf/workflows',
        '.cursor/commands',
        '.github',
        '.github/instructions'
    ];

    // Default special agent files
    private static readonly DEFAULT_AGENT_FILES = [
        'agents.md',
        'claude.md',
        'gemini.md'
    ];

    // Invisible character mappings
    private static readonly DANGEROUS_CHARS: { [key: number]: string } = {
        0x200B: '[⎵]', // Zero Width Space
        0x200C: '[⎵]', // Zero Width Non-Joiner
        0x200D: '[⎵]', // Zero Width Joiner
        0xFEFF: '[⎵]', // Zero Width No-Break Space / BOM
        0x202E: '[⥴]', // Right-to-Left Override
        0x202D: '[⥱]', // Left-to-Right Override
        0x2060: '[⎵]', // Word Joiner
        0x180E: '[⎵]', // Mongolian Vowel Separator
        0x2061: '[∘]', // Function Application
        0x2062: '[×]', // Invisible Times
        0x2063: '[｜]', // Invisible Separator
        0x2064: '[+]', // Invisible Plus
    };

    // Local endpoint pattern
    private static readonly LOCAL_ENDPOINT_PATTERN = /^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(:\d+)?(\/|\?|$)/i;

    // Endpoint scoring rules (pattern -> score)
    private static readonly ENDPOINT_SCORING_RULES = [
        { pattern: /^data:/i, score: 70, description: 'Data URI' },
        { pattern: /[?&](?:token|auth|access_token|api_key|key|sig)/i, score: 60, description: 'Token parameter' },
        { pattern: /[a-zA-Z0-9_-]{32,}\./, score: 40, description: 'Long/base64-like domain' },
        { pattern: /\b(bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|buff\.ly)\b/, score: 30, description: 'URL shortener' },
        { pattern: /^https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[?::1\]?)(.*)/i, score: 30, description: 'External URL' },
        { pattern: /\{\{.*?\}\}|\{[\w:-]+\}|:[A-Za-z_]+/, score: 25, description: 'Template placeholder' },
        { pattern: /^mailto:/i, score: 20, description: 'Mailto link' },
    ];

    constructor(targetFolders?: string[], specialAgentFiles?: string[]) {
        this.targetFolders = targetFolders || PromptInjectionDetector.DEFAULT_TARGET_FOLDERS;
        this.specialAgentFiles = specialAgentFiles || PromptInjectionDetector.DEFAULT_AGENT_FILES;
    }

    // Common file extensions to filter out (not exfil endpoints)
    private readonly commonFileExtensions = [
        '.ts', '.tsx', '.js', '.jsx', '.py', '.go', '.java', '.c', '.cpp', '.h', '.hpp',
        '.rs', '.rb', '.php', '.cs', '.swift', '.kt', '.m', '.mm',
        '.json', '.xml', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf',
        '.md', '.txt', '.rst', '.adoc',
        '.html', '.htm', '.css', '.scss', '.sass', '.less',
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
        '.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv',
        '.so', '.dll', '.dylib', '.exe', '.app',
        '.lock', '.sum', '.mod'
    ];

    /**
     * Set the endpoint allowlist for filtering out legitimate URLs
     */
    public setEndpointAllowlist(allowlist: string[]): void {
        this.endpointAllowlist = allowlist;
        console.log(`[Allowlist] Endpoint allowlist updated: ${allowlist.length} patterns`);
    }

    /**
     * Check if an endpoint matches any pattern in the allowlist
     * Supports wildcards: * (any characters) and ? (single character)
     */
    private isAllowlisted(endpoint: string): boolean {
        const lowerEndpoint = endpoint.toLowerCase();
        
        for (const pattern of this.endpointAllowlist) {
            const lowerPattern = pattern.toLowerCase();
            
            // Convert wildcard pattern to regex
            // Escape special regex chars except * and ?
            const regexPattern = lowerPattern
                .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // Escape special chars
                .replace(/\*/g, '.*')                   // * becomes .*
                .replace(/\?/g, '.');                   // ? becomes .
            
            const regex = new RegExp(`^${regexPattern}$`);
            
            if (regex.test(lowerEndpoint)) {
                console.log(`  [Allowlist] Skipping allowlisted endpoint: ${endpoint}`);
                return true;
            }
        }
        
        return false;
    }

    /**
     * Analyze a file for adversarial patterns using stealth-first hierarchy
     */
    public analyzeFile(filePath: string, content: string): DetectionResult {
        console.log('\n=== ANALYZING FILE:', filePath, '===');
        console.log('Content length (original):', content.length, 'characters');

        // Normalize line endings to handle Windows/Unix differences
        const originalLength = content.length;
        content = content.replace(/\r\n/g, '\n');
        if (originalLength !== content.length) {
            console.log('Line endings normalized: Windows → Unix');
            console.log('Content length (normalized):', content.length, 'characters');
        }

        let riskScore = 0;
        const evidence: string[] = [];
        const detectedPatterns: DetectedPattern[] = [];

        // Check for invisible content (unicode-based stealth)
        console.log('\nChecking for invisible Unicode characters...');
        const invisibleContent = this.extractInvisibleContent(content);
        console.log('Lines with invisible characters:', invisibleContent.length);

        // Count total invisible characters
        let totalInvisibleChars = 0;
        if (invisibleContent.length > 0) {
            invisibleContent.forEach((inv) => {
                totalInvisibleChars += inv.charCount;
            });
        }

        // Handle invisible content scoring (separate from comments)
        if (invisibleContent.length > 0) {
            console.log(`\n[INVISIBLE CHARACTER ANALYSIS]`);
            console.log(`  Total invisible characters: ${totalInvisibleChars}`);
            
            if (totalInvisibleChars >= 100) {
                console.log('  ⚠️ CRITICAL: 100+ invisible characters detected');
            } else if (totalInvisibleChars >= 50) {
                console.log('  ⚠️ HIGH: 50-99 invisible characters detected');
            } else if (totalInvisibleChars >= 20) {
                console.log('  ⚠️ MEDIUM: 20-49 invisible characters detected');
            } else {
                console.log('  ⚠️ LOW: 1-19 invisible characters detected');
            }

            riskScore = Math.max(totalInvisibleChars, riskScore);
            evidence.push(`Invisible Unicode characters detected (${totalInvisibleChars})`);

            // Add invisible character patterns with decoded lines
            for (const inv of invisibleContent) {
                const patternScore = inv.charCount; // Score based on number of invisible chars
                detectedPatterns.push({
                    type: 'Invisible Unicode Characters',
                    match: inv.content, // Show decoded line
                    line: inv.lineNumber,
                    column: 0,
                    score: patternScore,
                    verdict: this.calculateVerdict(patternScore)
                });
            }
        }

        // Continue with full file analysis for endpoints and self-propagation
        // Check for exfiltration endpoints
        console.log('\nChecking for exfiltration endpoints');
        const exfilResults = this.detectExfilEndpoints(content);
        console.log('Exfiltration endpoints found:', exfilResults.length);
        if (exfilResults.length > 0) {
            console.log('✓ Exfiltration endpoints detected');
            exfilResults.forEach((result, index) => {
                console.log(`  ${index + 1}. "${result.match}" at line ${result.line}, col ${result.column} (score: ${result.score}, verdict: ${result.verdict})`);
            });
            // Score based on highest individual endpoint score
            const maxScore = Math.max(...exfilResults.map(r => r.score));
            riskScore = Math.max(maxScore, riskScore);
            evidence.push(`Potential exfiltration endpoints detected (${exfilResults.length})`);
            detectedPatterns.push(...exfilResults);
        } else {
            console.log('❌ No exfiltration endpoints found');
        }

        // Check for self-propagation patterns
        console.log('\nChecking for self-propagation patterns');
        const selfPropResults = this.detectSelfPropagation(content);
        console.log('Self-propagation patterns found:', selfPropResults.length);
        if (selfPropResults.length > 0) {
            console.log('✓ Self-propagation patterns detected (+80 points)');
            selfPropResults.forEach((result, index) => {
                console.log(`  ${index + 1}. "${result.match}" at line ${result.line}, col ${result.column} (score: ${result.score}, verdict: ${result.verdict})`);
            });
            riskScore = Math.max(80, riskScore); // High default score for self-propagation
            evidence.push(`Potential self-propagation patterns detected (${selfPropResults.length})`);
            detectedPatterns.push(...selfPropResults);
        } else {
            console.log('❌ No self-propagation patterns found');
        }

        // Calculate verdict based on new thresholds
        const verdict = this.calculateVerdict(riskScore);

        console.log('\n[FINAL RESULTS]');
        console.log('Final score:', riskScore, '/ 100');
        console.log('Verdict:', verdict);
        console.log('Total evidence:', evidence.length);
        console.log('All evidence:', evidence);
        console.log('Total detected patterns:', detectedPatterns.length);
        console.log('=== END ANALYSIS ===\n');

        return {
            filePath: filePath,
            score: Math.min(riskScore, 100),
            verdict,
            evidence,
            detectedPatterns
        };
    }

    /**
     * Extract invisible/non-printable Unicode characters that may hide malicious instructions
     */
    private extractInvisibleContent(content: string): Array<{content: string, lineNumber: number, charCount: number}> {
        console.log('  [extractInvisibleContent] Starting extraction...');
        console.log('  [extractInvisibleContent] Content length:', content.length);

        const invisibleBlocks: Array<{content: string, lineNumber: number, charCount: number}> = [];
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const lineNumber = i + 1;
            
            let hasInvisible = false;
            let decodedLine = '';
            let charCount = 0;
            
            const runes = Array.from(line); // Split into Unicode code points
            let j = 0;
            
            while (j < runes.length) {
                const r = runes[j];
                const codePoint = r.codePointAt(0) || 0;
                const invisibleResult = this.isInvisibleChar(codePoint);
                
                if (invisibleResult.isInvisible) {
                    // Check for consecutive variation selectors (VS)
                    if (this.isVariationSelector(codePoint)) {
                        let consecutiveVS = 1;
                        let k = j + 1;
                        
                        // Count consecutive variation selectors
                        while (k < runes.length) {
                            const nextCodePoint = runes[k].codePointAt(0) || 0;
                            if (this.isVariationSelector(nextCodePoint)) {
                                consecutiveVS++;
                                k++;
                            } else {
                                break;
                            }
                        }
                        
                        // Only flag if 2+ consecutive variation selectors
                        if (consecutiveVS >= 2) {
                            for (let m = j; m < k; m++) {
                                const cp = runes[m].codePointAt(0) || 0;
                                const decoded = this.isInvisibleChar(cp).decoded;
                                decodedLine += decoded;
                                charCount++;
                            }
                            hasInvisible = true;
                            j = k; // Skip processed variation selectors
                            continue;
                        } else {
                            // Single variation selector - pass through normally
                            decodedLine += r;
                        }
                    } else {
                        // Non-VS invisible char - always flag
                        decodedLine += invisibleResult.decoded;
                        charCount++;
                        hasInvisible = true;
                    }
                } else {
                    decodedLine += r;
                }
                j++;
            }
            
            if (hasInvisible) {
                const securityNote = this.categorizeInvisibleChars(line);
                
                console.log(`  [INVISIBLE] Line ${lineNumber}:`);
                console.log(`    - Invisible characters: ${charCount}`);
                console.log(`    - Security note: ${securityNote}`);
                console.log(`    - Decoded: "${decodedLine.substring(0, 80)}${decodedLine.length > 80 ? '...' : ''}"`);
                
                invisibleBlocks.push({
                    content: decodedLine,
                    lineNumber: lineNumber,
                    charCount: charCount
                });
            }
        }

        console.log(`\n[INVISIBLE SUMMARY]`);
        console.log(`  Total lines with invisible characters: ${invisibleBlocks.length}`);

        return invisibleBlocks;
    }

    /**
     * Check if a Unicode code point is an invisible/non-printable character
     * Returns: { isInvisible: boolean, decoded: string }
     */
    private isInvisibleChar(codePoint: number): { isInvisible: boolean, decoded: string } {
        // Unicode tag characters (U+E0000-U+E007F)
        if (codePoint >= 0xE0020 && codePoint <= 0xE007E) {
            // Tag characters map to ASCII 0x20-0x7E
            const asciiChar = String.fromCodePoint(codePoint - 0xE0000);
            return { isInvisible: true, decoded: asciiChar };
        }
        if (codePoint >= 0xE0000 && codePoint <= 0xE007F) {
            return { isInvisible: true, decoded: `[U+${codePoint.toString(16).toUpperCase().padStart(5, '0')}]` };
        }

        // Variation Selectors (VS1-VS16: U+FE00 to U+FE0F)
        if (codePoint >= 0xFE00 && codePoint <= 0xFE0F) {
            return { isInvisible: true, decoded: `[VS${codePoint - 0xFE00 + 1}]` };
        }

        // Variation Selectors Supplement (VS17-VS256: U+E0100 to U+E01EF)
        if (codePoint >= 0xE0100 && codePoint <= 0xE01EF) {
            return { isInvisible: true, decoded: `[VS${codePoint - 0xE0100 + 17}]` };
        }

        // Specific dangerous characters with symbols
        if (codePoint in PromptInjectionDetector.DANGEROUS_CHARS) {
            return { isInvisible: true, decoded: PromptInjectionDetector.DANGEROUS_CHARS[codePoint] };
        }

        // Check Unicode categories
        const char = String.fromCodePoint(codePoint);
        const categories = this.getUnicodeCategory(codePoint);

        // Format characters (Cf) - mostly invisible
        if (categories.includes('Cf')) {
            return { isInvisible: true, decoded: `[U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}]` };
        }

        // Control characters (Cc) except printable whitespace
        if (categories.includes('Cc') && codePoint !== 0x0A && codePoint !== 0x0D && codePoint !== 0x09) {
            return { isInvisible: true, decoded: `[U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}]` };
        }

        // Private use characters (Co) - often used for steganography
        if (categories.includes('Co')) {
            return { isInvisible: true, decoded: `[U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}]` };
        }

        return { isInvisible: false, decoded: '' };
    }

    /**
     * Check if a code point is a variation selector
     */
    private isVariationSelector(codePoint: number): boolean {
        return (codePoint >= 0xFE00 && codePoint <= 0xFE0F) || 
               (codePoint >= 0xE0100 && codePoint <= 0xE01EF);
    }

    /**
     * Check if a code point is a Unicode tag character
     */
    private isTagCharacter(codePoint: number): boolean {
        return codePoint >= 0xE0000 && codePoint <= 0xE007F;
    }

    /**
     * Get Unicode category for a code point (simplified)
     */
    private getUnicodeCategory(codePoint: number): string[] {
        const categories: string[] = [];

        // Format characters (Cf)
        if ((codePoint >= 0x00AD && codePoint <= 0x00AD) || // Soft Hyphen
            (codePoint >= 0x0600 && codePoint <= 0x0605) ||
            (codePoint >= 0x061C && codePoint <= 0x061C) ||
            (codePoint >= 0x06DD && codePoint <= 0x06DD) ||
            (codePoint >= 0x070F && codePoint <= 0x070F) ||
            (codePoint >= 0x180E && codePoint <= 0x180E) ||
            (codePoint >= 0x200B && codePoint <= 0x200F) ||
            (codePoint >= 0x202A && codePoint <= 0x202E) ||
            (codePoint >= 0x2060 && codePoint <= 0x2064) ||
            (codePoint >= 0x2066 && codePoint <= 0x206F) ||
            (codePoint >= 0xFEFF && codePoint <= 0xFEFF) ||
            (codePoint >= 0xFFF9 && codePoint <= 0xFFFB)) {
            categories.push('Cf');
        }

        // Control characters (Cc)
        if ((codePoint >= 0x0000 && codePoint <= 0x001F) ||
            (codePoint >= 0x007F && codePoint <= 0x009F)) {
            categories.push('Cc');
        }

        // Private use characters (Co)
        if ((codePoint >= 0xE000 && codePoint <= 0xF8FF) ||
            (codePoint >= 0xF0000 && codePoint <= 0xFFFFD) ||
            (codePoint >= 0x100000 && codePoint <= 0x10FFFD)) {
            categories.push('Co');
        }

        return categories;
    }

    /**
     * Categorize invisible characters and return a security note
     */
    private categorizeInvisibleChars(line: string): string {
        let hasTagChars = false;
        let hasVariationSelectors = false;
        let hasZeroWidth = false;
        let hasBidiOverride = false;
        let hasOther = false;

        const runes = Array.from(line);
        for (const r of runes) {
            const codePoint = r.codePointAt(0) || 0;
            const invisResult = this.isInvisibleChar(codePoint);

            if (invisResult.isInvisible) {
                if (this.isTagCharacter(codePoint)) {
                    hasTagChars = true;
                } else if (this.isVariationSelector(codePoint)) {
                    hasVariationSelectors = true;
                } else if ([0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060].includes(codePoint)) {
                    hasZeroWidth = true;
                } else if ([0x202E, 0x202D].includes(codePoint)) {
                    hasBidiOverride = true;
                } else {
                    hasOther = true;
                }
            }
        }

        const notes: string[] = [];

        if (hasTagChars) {
            notes.push('Unicode Tag characters may hide invisible instructions or exfiltrate data');
        }
        if (hasVariationSelectors) {
            notes.push('Consecutive Unicode Variation Selectors may be used for steganography');
        }
        if (hasZeroWidth) {
            notes.push('Zero-width characters can hide data, create homograph attacks, or bypass filters');
        }
        if (hasBidiOverride) {
            notes.push('Bidirectional Override characters can disguise malicious content');
        }
        if (hasOther) {
            notes.push('Other invisible characters may be used for steganography or obfuscation');
        }

        if (notes.length === 0) {
            return 'Invisible characters may be used for hiding instructions or exfiltrating data';
        }

        return notes.join('; ');
    }

    /**
     * Detect exfiltration endpoints in entire file content
     */
    private detectExfilEndpoints(content: string): DetectedPattern[] {
        const results: DetectedPattern[] = [];

        // Regex patterns for endpoint detection
        const urlRe = /\b(?:https?|wss?|ftp):\/\/[^\s)>\]]+/gi;
        const dataUriRe = /\bdata:(?:image|application)\/[^\s;,]+;base64,[A-Za-z0-9+/=]{1,20}/gi;
        const pathRe = /(^|[\s`'"@])(\/[^/\s][A-Za-z0-9_\-./:{}\[\]\(\)%@,+~]+)/gm;
        const mailtoRe = /\bmailto:[^\s)>\]]+/gi;

        const lines = content.split('\n');

        lines.forEach((line, index) => {
            const lineNumber = index + 1;

            // Detect URLs
            const urlMatches = line.matchAll(urlRe);
            for (const match of urlMatches) {
                const url = match[0];
                // Skip if allowlisted or has common file extension
                if (!this.isAllowlisted(url) && !this.hasCommonFileExtension(url)) {
                    const patternScore = this.calculateEndpointScore(url);
                    results.push({
                        type: 'Potential Exfiltration Endpoint: URL',
                        match: url,
                        line: lineNumber,
                        column: match.index || 0,
                        score: patternScore,
                        verdict: this.calculateVerdict(patternScore)
                    });
                }
            }

            // Detect data URIs
            const dataUriMatches = line.matchAll(dataUriRe);
            for (const match of dataUriMatches) {
                const dataUri = match[0];
                // Skip if allowlisted
                if (!this.isAllowlisted(dataUri)) {
                    const patternScore = this.calculateEndpointScore(dataUri);
                    results.push({
                        type: 'Potential Exfiltration Endpoint: Data URI',
                        match: dataUri + '...',
                        line: lineNumber,
                        column: match.index || 0,
                        score: patternScore,
                        verdict: this.calculateVerdict(patternScore)
                    });
                }
            }

            // Detect mailto links
            const mailtoMatches = line.matchAll(mailtoRe);
            for (const match of mailtoMatches) {
                const mailto = match[0];
                // Skip if allowlisted
                if (!this.isAllowlisted(mailto)) {
                    const patternScore = this.calculateEndpointScore(mailto);
                    results.push({
                        type: 'Potential Exfiltration Endpoint: Mailto',
                        match: mailto,
                        line: lineNumber,
                        column: match.index || 0,
                        score: patternScore,
                        verdict: this.calculateVerdict(patternScore)
                    });
                }
            }
        });

        return results;
    }

    /**
     * Detect self-propagation patterns in entire file content
     */
    private detectSelfPropagation(content: string): DetectedPattern[] {
        const results: DetectedPattern[] = [];
        const lines = content.split('\n');

        lines.forEach((line, index) => {
            const lineNumber = index + 1;

            // Check for target folder references
            results.push(...this.detectPatternMatches(
                line,
                lineNumber,
                this.targetFolders,
                'Potential Self-Propagation Target: Trusted Folder',
                /(^|\s|\/|'|")(PATTERN)(?:\s|$|\/|'|"(?:\s|$))/gi,
            ));

            // Check for special agent file references
            results.push(...this.detectPatternMatches(
                line,
                lineNumber,
                this.specialAgentFiles,
                'Potential Self-Propagation Target: Agent File',
                /(^|\s)(PATTERN)(\s|$)/gi,
            ));
        });

        return results;
    }

    /**
     * Helper to detect pattern matches and add to results
     */
    private detectPatternMatches(
        originalLine: string,
        lineNumber: number,
        patterns: string[],
        detectionType: string,
        regexTemplate: RegExp,
    ): DetectedPattern[] {
        const lowerLine = originalLine.toLowerCase();
        let results: DetectedPattern[] = [];

        for (const pattern of patterns) {
            const escapedPattern = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            const regexStr = regexTemplate.source.replace('PATTERN', escapedPattern);
            const regex = new RegExp(regexStr, regexTemplate.flags);
            
            const matches = lowerLine.matchAll(regex);
            for (const match of matches) {
                const patternScore = 80; // High score for self-propagation
                const matchStart = match.index! + match[1].length; // Skip the prefix
                results.push({
                    type: detectionType,
                    match: originalLine.substring(matchStart, matchStart + pattern.length),
                    line: lineNumber,
                    column: matchStart,
                    score: patternScore,
                    verdict: this.calculateVerdict(patternScore)
                });
            }
        }

        return results;
    }

    /**
     * Calculate endpoint score based on heuristics
     */
    private calculateEndpointScore(endpoint: string): number {
        const lowerEndpoint = endpoint.toLowerCase();

        // Local endpoints are safe (0 points)
        if (PromptInjectionDetector.LOCAL_ENDPOINT_PATTERN.test(lowerEndpoint)) {
            return 0;
        }

        let score = 0;

        // Apply all scoring rules
        for (const rule of PromptInjectionDetector.ENDPOINT_SCORING_RULES) {
            if (rule.pattern.test(lowerEndpoint)) {
                score += rule.score;
            }
        }

        return Math.min(score, 100);
    }

    /**
     * Check if path has a common file extension
     */
    private hasCommonFileExtension(path: string): boolean {
        const lowerPath = path.toLowerCase();
        return this.commonFileExtensions.some(ext => lowerPath.endsWith(ext));
    }

    private getLineNumber(content: string, index: number): number {
        return content.substring(0, index).split('\n').length;
    }

    private calculateVerdict(score: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' {
        if (score >= 80) return 'CRITICAL';
        if (score >= 50) return 'HIGH';
        if (score >= 30) return 'MEDIUM';
        return 'LOW';
    }
}
