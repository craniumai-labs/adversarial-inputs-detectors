/**
 * Adversarial Inputs Detection VS Code Extension
 * A VS Code extension that scans workspaces for adversarial inputs that could hijack AI coding assistants
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

import * as vscode from 'vscode';
import * as path from 'path';
import { PromptInjectionDetector, DetectionResult } from './detector';

let diagnosticCollection: vscode.DiagnosticCollection;
let detector: PromptInjectionDetector;
let statusBarItem: vscode.StatusBarItem;
let outputChannel: vscode.OutputChannel;

/**
 * Extension activation
 */
export function activate(context: vscode.ExtensionContext) {
    console.log('Adversarial Inputs Detector is now active');

    // Initialize detector with user settings
    const config = vscode.workspace.getConfiguration('promptInjectionDetector');
    const targetFolders = config.get<string[]>('targetFolders');
    const agentFiles = config.get<string[]>('agentFiles');
    
    detector = new PromptInjectionDetector(targetFolders, agentFiles);
    diagnosticCollection = vscode.languages.createDiagnosticCollection('promptInjection');
    context.subscriptions.push(diagnosticCollection);

    // Create output channel for detailed scan results
    outputChannel = vscode.window.createOutputChannel('Adversarial Inputs Detector');
    context.subscriptions.push(outputChannel);

    // Load endpoint allowlist from settings
    updateDetectorSettings(config);

    // Create status bar item
    statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
    statusBarItem.command = 'promptInjectionDetector.reportRepo';
    context.subscriptions.push(statusBarItem);

    // Register scan command
    const scanCommand = vscode.commands.registerCommand(
        'promptInjectionDetector.scanWorkspace',
        () => scanWorkspace()
    );
    context.subscriptions.push(scanCommand);

    // Register report repo command
    const reportCommand = vscode.commands.registerCommand(
        'promptInjectionDetector.reportRepo',
        () => handleReportRepo()
    );
    context.subscriptions.push(reportCommand);

    // Listen for configuration changes
    context.subscriptions.push(
        vscode.workspace.onDidChangeConfiguration(e => {
            if (e.affectsConfiguration('promptInjectionDetector')) {
                const newConfig = vscode.workspace.getConfiguration('promptInjectionDetector');
                updateDetectorSettings(newConfig);
                // Re-scan workspace with new settings
                scanWorkspace();
            }
        })
    );

    // Auto-scan on startup if enabled
    if (config.get('autoScanOnOpen', true)) {
        scanWorkspace();
    }

    // Watch for file changes in all text files
    // Note: We use a broad pattern here; scanFile will handle text detection gracefully
    const fileWatcher = vscode.workspace.createFileSystemWatcher('**/*');
    fileWatcher.onDidChange(async uri => {
        // Only scan if it's a text file
        if (await isTextFile(uri)) {
            scanFile(uri);
        }
    });
    fileWatcher.onDidCreate(async uri => {
        // Only scan if it's a text file
        if (await isTextFile(uri)) {
            scanFile(uri);
        }
    });
    context.subscriptions.push(fileWatcher);
}

/**
 * Update detector settings from VS Code configuration
 */
function updateDetectorSettings(config: vscode.WorkspaceConfiguration) {
    const allowlist = config.get<string[]>('endpointAllowlist', []);
    detector.setEndpointAllowlist(allowlist);
    console.log(`[Settings] Loaded endpoint allowlist: ${allowlist.length} patterns`);
}

// File type detection constants
const TEXT_EXTENSIONS = new Set([
    // Docs / markup
    '.md', '.mdx', '.txt', '.rst', '.adoc', '.org', '.textile', '.tex', '.sty', '.cls', '.bib', '.wiki',
    // Web / styles / vector
    '.html', '.htm', '.xhtml', '.css', '.scss', '.sass', '.less', '.svg', '.xml', '.rss', '.atom',
    // Data / configs
    '.json', '.json5', '.jsonc', '.jsonl', '.ndjson', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.properties',
    '.hcl', '.tf', '.tfvars', '.cue', '.reg', '.plist',
    // Code – mainstream
    '.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx', '.m', '.mm',
    '.cs', '.java', '.scala', '.sbt', '.kt', '.kts', '.groovy', '.go', '.rs', '.swift', '.dart', '.zig',
    '.py', '.pyi', '.pyw', '.rb', '.php', '.ps1', '.psm1', '.psd1',
    '.sh', '.bash', '.zsh', '.ksh', '.mksh', '.fish', '.cmd', '.bat',
    '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.r', '.jl', '.lua', '.pl', '.pm', '.t', '.awk', '.sed',
    // Code – functional / scientific / legacy
    '.hs', '.lhs', '.cabal', '.ml', '.mli', '.re', '.rei', '.eliom', '.eliomi',
    '.erl', '.hrl', '.ex', '.exs', '.clj', '.cljs', '.cljc', '.edn', '.fs', '.fsi', '.fsx',
    '.f', '.for', '.f90', '.f95', '.f03', '.f08', '.cob', '.cbl', '.cpy', '.nim',
    // DB / query / schema
    '.sql', '.graphql', '.gql', '.proto',
    // Build systems / meta
    '.gradle', '.gradle.kts', '.make', '.mk', '.gn', '.gni', '.ninja', '.meson', '.bazel', '.bzl', '.qmake', '.pro',
    // Templates
    '.mustache', '.handlebars', '.hbs', '.ejs', '.erb', '.jinja', '.jinja2', '.njk', '.pug', '.jade', '.liquid',
    // Misc dev text
    '.dockerfile', '.dotenv', '.env.example', '.ipynb', '.rego', '.nix',
    // Others
    '.lock'
]);

const TEXT_BASENAMES = new Set([
    'readme', 'license', 'copying', 'notice', 'changelog', 'changes', 'history',
    'contributing', 'code_of_conduct', 'security', 'support', 'authors', 'contributors',
    'makefile', 'gnumakefile', 'cmakelists.txt', 'dockerfile', 'vagrantfile',
    'rakefile', 'gemfile', 'procfile', 'jenkinsfile',
    '.gitignore', '.gitattributes', '.editorconfig', '.dockerignore', '.npmignore',
]);

const BINARY_EXTENSIONS = new Set([
    // Images (raster)
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.tif', '.tiff', '.webp', '.heic', '.heif', '.avif',
    // Documents / office
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.odt', '.ods', '.odp',
    // Archives & compressed
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar', '.iso', '.apk', '.deb', '.rpm',
    // Executables & libraries
    '.exe', '.dll', '.so', '.dylib', '.bin', '.msi', '.class', '.pyc', '.wasm',
    // Fonts
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    // Audio/Video
    '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.flac', '.wav',
    // Database & serialized
    '.sqlite', '.db', '.pkl', '.parquet',
    // Misc
    '.lockb', '.DS_Store', '.Thumbs.db',
]);

/**
 * Detect if a file is text-based by analyzing its content
 */
async function isTextFile(uri: vscode.Uri): Promise<boolean> {
    const ext = path.extname(uri.fsPath).toLowerCase();
    const basename = path.basename(uri.fsPath).toLowerCase();
    
    // Fast path: known extensions and basenames
    if (TEXT_EXTENSIONS.has(ext) || TEXT_BASENAMES.has(basename) || basename.startsWith('.env')) {
        return true;
    }
    if (BINARY_EXTENSIONS.has(ext)) {
        return false;
    }
    
    // Deep inspection for unknown files
    return await inspectFileContent(uri);
}

/**
 * Inspect file content to determine if it's text or binary
 */
async function inspectFileContent(uri: vscode.Uri): Promise<boolean> {
    try {
        const bytes = await vscode.workspace.fs.readFile(uri);
        if (bytes.length === 0) return true; // Empty files are considered text
        
        const sample = bytes.subarray(0, Math.min(bytes.length, 8192)); // Sample a few bytes to check for binary patterns
        
        // Check for null bytes (strong binary indicator, except for UTF-16 files)
        if (sample.includes(0)) {
            return isUTF16Text(sample);
        }
        
        // Try UTF-8 decoding
        return isValidUTF8Text(sample);
    } catch (err) {
        console.warn(`Could not read file ${uri.fsPath} for text detection:`, err);
        return false;
    }
}

/**
 * Check if content follows UTF-16 encoding pattern
 */
function isUTF16Text(sample: Uint8Array): boolean {
    // UTF-16 uses null bytes at either even or odd positions but not both
    let evenNulls = 0, oddNulls = 0;
    for (let i = 0; i < sample.length; i++) {
        if (sample[i] === 0) {
            i % 2 === 0 ? evenNulls++ : oddNulls++;
        }
    }
    const totalNulls = evenNulls + oddNulls;
    if (totalNulls === 0) return false;
    
    const ratio = Math.abs(evenNulls - oddNulls) / totalNulls;
    return ratio > 0.8 && totalNulls > sample.length * 0.1; // text file indicator
}

/**
 * Check if content is valid UTF-8 text
 */
function isValidUTF8Text(sample: Uint8Array): boolean {
    try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(sample);
        let controlChars = 0;
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i);
            if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
                controlChars++;
            }
        }
        return text.length === 0 || (controlChars / text.length) < 0.3; // text file indicator
    } catch {
        return false;
    }
}

/**
 * Count detection types across all scan results
 */
function countDetectionTypes(allResults: Array<{name: string, result: any}>) {
    const stats = {
        selfPropagation: { count: 0, fileCount: 0 },
        exfiltration: { count: 0, fileCount: 0 },
        invisibleChars: { count: 0, fileCount: 0 }
    };

    // Each item represents detection for a file
    for (const item of allResults) {
        if (!shouldAlert(item.result.verdict)) {
            continue;
        }

        const detectedTypes = new Set<string>();
        
        for (const pattern of item.result.detectedPatterns) {
            if (pattern.type.includes('Self-Propagation')) {
                stats.selfPropagation.count++;
                detectedTypes.add('selfPropagation');
            } else if (pattern.type.includes('Exfiltration')) {
                stats.exfiltration.count++;
                detectedTypes.add('exfiltration');
            } else if (pattern.type.includes('Invisible Unicode')) {
                stats.invisibleChars.count += pattern.score;
                detectedTypes.add('invisibleChars');
            }
        }

        // Count unique files for each detection type
        if (detectedTypes.has('selfPropagation')) stats.selfPropagation.fileCount++;
        if (detectedTypes.has('exfiltration')) stats.exfiltration.fileCount++;
        if (detectedTypes.has('invisibleChars')) stats.invisibleChars.fileCount++;
    }

    return stats;
}

/**
 * Build formatted scan summary message
 */
function buildScanSummaryMessage(
    totalFiles: number,
    detectionStats: ReturnType<typeof countDetectionTypes>,
    criticalFiles: Array<any>,
    highFiles: Array<any>,
    mediumFiles: Array<any>,
    lowFiles: Array<any>
): string {
    let message = ``;

    // Severity breakdown
    message += `⚠️ SEVERITY BREAKDOWN:\n`;
    
    const severityLevels = [
        { files: criticalFiles, icon: '🚨', label: 'CRITICAL' },
        { files: highFiles, icon: '⚠️', label: 'HIGH' },
        { files: mediumFiles, icon: '⚡', label: 'MEDIUM' },
        { files: lowFiles, icon: 'ℹ️', label: 'LOW' }
    ];

    for (const { files, icon, label } of severityLevels) {
        if (files.length > 0) {
            message += `  ${icon} ${label}: ${files.length} file${files.length > 1 ? 's' : ''}\n`;
        }
    }
    message += '\n';

    // Detection type breakdown
    const hasDetections = detectionStats.selfPropagation.count > 0 
        || detectionStats.exfiltration.count > 0 
        || detectionStats.invisibleChars.count > 0;

    if (hasDetections) {
        message += `📊 DETECTION BREAKDOWN:\n`;
        
        if (detectionStats.selfPropagation.count > 0) {
            const { count, fileCount } = detectionStats.selfPropagation;
            message += `  🔄 Potential Self-Propagation Patterns Detected: ${count} in ${fileCount} file${fileCount > 1 ? 's' : ''}\n`;
        }
        if (detectionStats.exfiltration.count > 0) {
            const { count, fileCount } = detectionStats.exfiltration;
            message += `  📡 Potential Exfiltration Endpoints Detected: ${count} in ${fileCount} file${fileCount > 1 ? 's' : ''}\n`;
        }
        if (detectionStats.invisibleChars.count > 0) {
            const { count, fileCount } = detectionStats.invisibleChars;
            message += `  🔍 Invisible Unicode Characters Detected: ${count} in ${fileCount} file${fileCount > 1 ? 's' : ''}\n`;
        }
        message += '\n';
    }

    const cleanFiles = totalFiles - criticalFiles.length - highFiles.length - mediumFiles.length - lowFiles.length;
    if (cleanFiles > 0) {
        message = `⚠️ SCAN COMPLETE\n\nScanned ${totalFiles} files\n\n✅ CLEAN: ${cleanFiles} files\n\n` + message;
    } else {
        message = `⚠️ SCAN COMPLETE\n\nScanned ${totalFiles} files\n\n` + message;
    }

    return message;
}

/**
 * Scan entire workspace for adversarial inputs
 */
async function scanWorkspace() {
    const workspaceFolders = vscode.workspace.workspaceFolders;
    if (!workspaceFolders) {
        vscode.window.showWarningMessage('No workspace folder open');
        return;
    }

    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: "Scanning for adversarial inputs...",
        cancellable: false
    }, async (progress) => {
        // Clear previous diagnostics
        diagnosticCollection.clear();

        let totalFiles = 0;
        let threatsFound = 0;
        const criticalFiles: Array<{name: string, score: number, evidence: string[]}> = [];
        const highFiles: Array<{name: string, score: number, evidence: string[]}> = [];
        const mediumFiles: Array<{name: string, score: number, evidence: string[]}> = [];
        const lowFiles: Array<{name: string, score: number, evidence: string[]}> = [];
        const allResults: Array<{name: string, result: any}> = [];

        // Find ALL files, excluding common binary/build directories
        console.log('Finding all files in workspace...');
        progress.report({ message: 'Finding files...' });
        
        const allFiles = await vscode.workspace.findFiles(
            '**/*',
            '{**/node_modules/**,**/.git/**,**/dist/**,**/build/**,**/out/**,**/coverage/**,**/__pycache__/**,**/target/**,**/bin/**,**/obj/**}'
        );

        console.log(`Found ${allFiles.length} potential files`);
        
        // Filter to text-based files only
        progress.report({ message: `Detecting text files (${allFiles.length} candidates)...` });
        const textFiles: vscode.Uri[] = [];
        
        for (let i = 0; i < allFiles.length; i++) {
            if (i % 50 === 0) {
                progress.report({ 
                    message: `Detecting text files (${i}/${allFiles.length})...`,
                    increment: (50 / allFiles.length) * 100
                });
            }
            
            if (await isTextFile(allFiles[i])) {
                textFiles.push(allFiles[i]);
            }
        }

        const files = textFiles;
        console.log(`Filtered to ${files.length} text-based files`);
        console.log(`Sample files:`, files.slice(0, 20).map(f => path.basename(f.fsPath)));

        totalFiles = files.length;
        progress.report({ message: `Scanning ${totalFiles} text files...` });

        // Scan ALL files completely
        for (let i = 0; i < files.length; i++) {
            const fileUri = files[i];
            progress.report({
                message: `Scanning ${i + 1}/${totalFiles}: ${path.basename(fileUri.fsPath)}...`,
                increment: (100 / totalFiles)
            });

            const result = await scanFile(fileUri);

            if (result) {
                allResults.push({
                    name: path.basename(fileUri.fsPath),
                    result: result
                });

                if (shouldAlert(result.verdict)) {
                    threatsFound++;
                    if (result.verdict === 'CRITICAL') {
                        criticalFiles.push({
                            name: path.basename(fileUri.fsPath),
                            score: result.score,
                            evidence: result.evidence
                        });
                    } else if (result.verdict === 'HIGH') {
                        highFiles.push({
                            name: path.basename(fileUri.fsPath),
                            score: result.score,
                            evidence: result.evidence
                        });
                    } else if (result.verdict === 'MEDIUM') {
                        mediumFiles.push({
                            name: path.basename(fileUri.fsPath),
                            score: result.score,
                            evidence: result.evidence
                        });
                    } else if (result.verdict === 'LOW') {
                        lowFiles.push({
                            name: path.basename(fileUri.fsPath),
                            score: result.score,
                            evidence: result.evidence
                        });
                    }
                }
            }
        }
        console.log(`Critical files: ${criticalFiles.length}`);
        console.log(`High files: ${highFiles.length}`);
        console.log(`Medium files: ${mediumFiles.length}`);
        console.log(`Low files: ${lowFiles.length}`);

        // Show detailed summary
        if (threatsFound > 0) {
            // Update status bar
            updateStatusBar(threatsFound, criticalFiles.length > 0);

            // Count detection types across all files
            const detectionStats = countDetectionTypes(allResults);

            // Build detailed message
            const detailedMessage = buildScanSummaryMessage(
                totalFiles,
                detectionStats,
                criticalFiles,
                highFiles,
                mediumFiles,
                lowFiles
            );

            // Show appropriate alert based on severity
            const message = criticalFiles.length > 0
                ? `🚨 CRITICAL: Found ${criticalFiles.length} critical threat(s) in ${totalFiles} files`
                : `⚠️ Found ${threatsFound} potential threat(s) in ${totalFiles} files`;
            
            const showMessage = criticalFiles.length > 0 
                ? vscode.window.showErrorMessage 
                : vscode.window.showWarningMessage;

            showMessage(
                message,
                'Show Details',
                'Show Problems',
                'Report This Repo'
            ).then(selection => {
                if (selection === 'Show Details') {
                    outputChannel.clear();
                    outputChannel.appendLine(detailedMessage);
                    outputChannel.show(true);
                } else if (selection === 'Show Problems') {
                    vscode.commands.executeCommand('workbench.actions.view.problems');
                } else if (selection === 'Report This Repo') {
                    handleReportRepo();
                }
            });

            // Log scan summary to console
            console.log('=== SCAN SUMMARY ===');
            console.log(`Total files scanned: ${totalFiles}`);
            console.log(`Threats found: ${threatsFound}`);
            console.log('\nDetailed results:');
            for (const item of allResults) {
                if (item.result.score > 0) {
                    console.log(`  ${item.name}: ${item.result.verdict} (${item.result.score}/100)`);
                    console.log(`    Evidence: ${item.result.evidence.join(', ')}`);
                }
            }
        } else {
            // Hide status bar when no threats
            statusBarItem.hide();
            vscode.window.showInformationMessage(
                `✓ Scanned ${totalFiles} files. No adversarial input threats detected.`
            );
        }
    });
}

/**
 * Update status bar to show threat status
 */
function updateStatusBar(threatCount: number, hasCritical: boolean) {
    const icon = hasCritical ? '🚨' : '⚠️';
    statusBarItem.text = `${icon} Threats Detected - Report Repo`;
    statusBarItem.tooltip = `${threatCount} adversarial input threat${threatCount > 1 ? 's' : ''} detected. Click to report this repository.`;
    statusBarItem.backgroundColor = hasCritical
        ? new vscode.ThemeColor('statusBarItem.errorBackground')
        : new vscode.ThemeColor('statusBarItem.warningBackground');
    statusBarItem.show();
}

/**
 * Handle "Report This Repo" button click
 */
function handleReportRepo() {
    vscode.window.showInformationMessage(
        '🚀 Coming soon! You\'ll be able to report malicious repos to help protect the community.',
        'Learn More'
    ).then(selection => {
        if (selection === 'Learn More') {
            vscode.env.openExternal(vscode.Uri.parse('https://cranium.ai'));
        }
    });
}

/**
 * Scan a single file
 */
async function scanFile(uri: vscode.Uri): Promise<DetectionResult | null> {
    try {
        const document = await vscode.workspace.openTextDocument(uri);
        const content = document.getText();

        // Run detection
        const result = detector.analyzeFile(uri.fsPath, content);

        // Create diagnostics if file-level threats exceed the threshold
        if (shouldAlert(result.verdict)) {
            createDiagnostics(document, result);
        } else {
            // Clear diagnostics for this file if no threats
            diagnosticCollection.delete(uri);
        }

        return result;
    } catch (error) {
        console.error(`Error scanning file ${uri.fsPath}:`, error);
        return null;
    }
}

/**
 * Check if verdict should trigger an alert based on config
 */
function shouldAlert(verdict: string): boolean {
    const config = vscode.workspace.getConfiguration('promptInjectionDetector');
    const minLevel = config.get<string>('minVulnLevel', 'HIGH');
    console.log(`Minimum vulnerability level: ${minLevel}`);

    const levels: { [key: string]: number } = {
        'LOW': 0,
        'MEDIUM': 1,
        'HIGH': 2,
        'CRITICAL': 3
    };

    return levels[verdict] >= levels[minLevel];
}

/**
 * Create VS Code diagnostics (squiggly lines and problem panel entries)
 */
function createDiagnostics(document: vscode.TextDocument, result: DetectionResult) {
    const diagnostics: vscode.Diagnostic[] = [];

    // Create a diagnostic for each detected pattern
    for (const pattern of result.detectedPatterns) {
        // Skip if pattern verdict does not exceed the threshold
        if (!shouldAlert(pattern.verdict)) {
            continue;
        }

        const lineIndex = Math.max(0, pattern.line - 1);

        // Validate line number is within document bounds
        if (lineIndex >= document.lineCount) {
            console.warn(`Pattern at line ${pattern.line} is beyond document bounds (${document.lineCount} lines)`);
            continue;
        }

        const line = document.lineAt(lineIndex);

        // Use exact column position from detector
        const startPos = pattern.column;
        let endPos = pattern.column + pattern.match.length;
        
        // For invisible characters, ensure minimum visible width by NOT clamping
        let safeStartPos: number;
        let safeEndPos: number;
        
        if (pattern.type === 'Invisible Unicode Characters') {
            // Don't clamp - extend to at least 10 chars to make it visible
            const minWidth = 10;
            safeStartPos = 0;
            safeEndPos = Math.max(minWidth, line.text.length, 1); // At least 1, preferably 10
        } else {
            // Normal clamping for other pattern types
            safeStartPos = Math.max(0, Math.min(startPos, line.text.length));
            safeEndPos = Math.max(safeStartPos, Math.min(endPos, line.text.length));
        }

        const range = new vscode.Range(
            lineIndex,
            safeStartPos,
            lineIndex,
            safeEndPos
        );

        const severity = pattern.verdict === 'CRITICAL' || pattern.verdict === 'HIGH'
            ? vscode.DiagnosticSeverity.Error
            : vscode.DiagnosticSeverity.Warning;

        const diagnostic = new vscode.Diagnostic(
            range,
            `Severity: [${pattern.verdict}]\nScore: ${pattern.score}\nType: ${pattern.type}\nEvidence: "${pattern.match}"`,
            severity
        );

        diagnostic.code = pattern.type.toLowerCase().includes('exfiltration')
            ? 'exfiltration'
            : pattern.type.toLowerCase().includes('self-propagation')
            ? 'self-propagation'
            : 'invisible-text';
        diagnostic.source = 'Cranium AI';
        diagnostics.push(diagnostic);
    }

    // Add a summary diagnostic at the top of the file
    if (diagnostics.length > 0) {
        // Count evidence by pattern type (only for patterns meeting severity threshold)
        const evidenceCount = new Map<string, number>();
        
        for (const pattern of result.detectedPatterns) {
            if (shouldAlert(pattern.verdict)) {
                const count = evidenceCount.get(pattern.type) || 0;
                evidenceCount.set(pattern.type, count + 1);
            }
        }

        // Build evidence list with counts
        const relevantEvidence = Array.from(evidenceCount.entries())
            .map(([type, count]) => `${type} (${count})`);

        const summaryRange = new vscode.Range(0, 0, 0, 0);
        const summaryDiagnostic = new vscode.Diagnostic(
            summaryRange,
            `⚠️ Summary of Potential Malicious Contents\nRisk Score: ${result.score}/100\nSeverity: (${result.verdict})\nEvidence:\n${relevantEvidence.map((item, index) => `${index + 1}. ${item}`).join('\n')}`,
            result.verdict === 'CRITICAL' || result.verdict === 'HIGH' ? vscode.DiagnosticSeverity.Error : vscode.DiagnosticSeverity.Warning
        );
        summaryDiagnostic.code = 'summary';
        summaryDiagnostic.source = 'Cranium AI';
        diagnostics.unshift(summaryDiagnostic);
    }

    diagnosticCollection.set(document.uri, diagnostics);
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.dispose();
    }
    if (statusBarItem) {
        statusBarItem.dispose();
    }
}
