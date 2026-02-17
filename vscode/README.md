# Adversarial Inputs Detector - VS Code Extension

A VS Code extension that detects malicious content in documentation and code files that can exploit AI coding assistants.

## Support IDEs Based on VS Code
- VS Code
- Cursor
- Windsurf

## What It Does

Protects developers from malicious repositories by detecting three categories of threats:

1. **🔍 Invisible Unicode Characters** - Hidden instructions using zero-width characters, bidirectional overrides, and Unicode steganography
2. **📡 Exfiltration Endpoints** - External URLs, data URIs, and API endpoints that could leak sensitive data
3. **🔄 Self-Propagation Patterns** - References to trusted folders (e.g., `.cursor/commands`, `.windsurf/workflows`, `.github`) and agent files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`) that contains automation mechanisms, which could enable malware to spread

## Key Features

✅ **Auto-scan on workspace open** - Immediate protection  
✅ **Real-time file monitoring** - Detects changes as you work  
✅ **Smart severity scoring** - CRITICAL (80+), HIGH (50-79), MEDIUM (30-49), LOW (0-29)  
✅ **Configurable allowlist and trusted folders** - Reduce false positives for known safe domains and extensible to additional trust mechanisms  
✅ **Status bar integration** - Shows threat count and "Report Repo" button  
✅ **Comprehensive coverage** - Scans all text-based files that could contain prompt injection

## Quick Start

1. **Configure extension** - Create allowlist for legitimate domains, threshold for alerts, and additional trust folders for detecting self-propagation patterns  
2. **Open any workspace** - Auto-scan runs on startup
3. **View threats** in the Problems panel

## Configuration

Customize behavior in `.vscode/settings.json` within the root directory of the workspace:

- **`autoScanOnOpen`** - Automatically scan files when workspace opens (True, False)
- **`minVulnLevel`** - Minimum severity required to trigger alerts (LOW, MEDIUM, HIGH, CRITICAL)
- **`endpointAllowlist`** - URLs/domains to exclude from detection (supports wildcards). By default, `*` is used to allow all domains (i.e., turn-off endpoint detection). Setting an empty array will enable endpoint detection.
- **`targetFolders`** - Trusted folders that contain automation mechanisms (e.g., workflows, LLM instructions) that AI assistants read. Malicious code attempting to write to these folders may be trying to inject instructions that will be executed by the AI on future runs to self propagate.
- **`agentFiles`** - Special configuration files (e.g., `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`) that AI coding assistants read for project-specific instructions. Attempts to write to these files may indicate self-propagation, where malicious instructions try to persist by modifying the files that guide AI behavior.

Example:  
```json
{
  "promptInjectionDetector.autoScanOnOpen": true,
  "promptInjectionDetector.minVulnLevel": "HIGH",
  "promptInjectionDetector.endpointAllowlist": [
    "https://github.com/*",
    "https://*.example.com/*"
  ],
  "promptInjectionDetector.targetFolders": [
    ".windsurf/workflows",
    ".cursor/commands",
    ".github",
    ".github/instructions"
  ],
  "promptInjectionDetector.agentFiles": [
    "agents.md",
    "claude.md",
    "gemini.md"
  ]
}
```

## Additional Documentation

- **ENDPOINT_ALLOWLIST.md** - How to configure endpoint allowlist with wildcards

## Commands

- `Scan Workspace for Adversarial Inputs` - Manually trigger a full workspace scan

## Output & Results

The detector provides multiple ways to view scan results:

### 1. **Problems Panel** (`View` → `Problems`)
Shows all detected threats as warnings/errors with:
- **File summary at line 1**: Overall risk score, severity, and aggregated evidence counts
  ```
  ⚠️ Summary of Potential Malicious Contents
  Risk Score: 80/100
  Severity: (CRITICAL)
  Evidence:
  1. Potential Self-Propagation Target: Trusted Folder (3)
  2. Potential Exfiltration Endpoint: URL (2)
  ```
- **Individual detections**: Each pattern with its line number, score, verdict, and matched content
  ```
  Line 42: Severity: [HIGH]
  Score: 60
  Type: Potential Exfiltration Endpoint: URL
  Evidence: "https://evil.com?token=abc"
  ```

### 2. **In-Editor Diagnostics** (underlines/squiggles)
- **Red underlines**: CRITICAL or HIGH severity patterns
- **Yellow underlines**: MEDIUM or LOW severity patterns
- **Hover** over underlined text to see detailed information about the detection

### 3. **Output Channel** (`View` → `Output` → select "Adversarial Inputs Detector")
When you click "Show Details" in notification popups, see a comprehensive scan summary:
```
⚠️ SCAN COMPLETE

Scanned 250 files

📊 DETECTION BREAKDOWN:
  🔄 Potential Self-Propagation Patterns Detected: 3 in 2 files
  📡 Potential Exfiltration Endpoints Detected: 5 in 3 files
  🔍 Invisible Unicode Characters Detected: 15 in 1 file

⚠️ SEVERITY BREAKDOWN:
  🚨 CRITICAL: 2 files
  ⚠️ HIGH: 3 files
  ⚡ MEDIUM: 5 files
✅ CLEAN (240): No threats detected
```

### 4. **Status Bar** (bottom left)
- Shows threat count and "Report Repo" button when threats are detected
- **Red background**: Critical threats present
- **Yellow background**: High/Medium threats present

### 5. **Debug Console** (development mode)
Detailed logging of detection process including:
- Files scanned
- Pattern matching details
- Score calculations
- Individual pattern verdicts

## Scoring System

The detector analyzes files and assigns a vulnerability score based on the **highest scoring pattern found**:

1. **Invisible Unicode Characters**: Score = number of invisible characters detected, capped at 100.
2. **Exfiltration Endpoints**: Score = 0-100 points based on multiple factors:
   - **Data URIs: +70 points**  
     _Explanation_: Data URIs can embed malicious or exfiltrated content directly within files, making them hard to spot and easy to execute.  
     _Examples_:  
       - `data:text/plain;base64,SGVsbG8=`  
       - `data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL...`

   - **Token parameters (`token`, `api_key`, etc.): +60 points**  
     _Explanation_: Direct inclusion of tokens or API keys as parameters in URLs can allow easy credential theft or exfiltration.  
     _Examples_:  
       - `https://evil.com/?token=abc123`  
       - `https://api.site.com/data?api_key=SECRETXYZ`

   - **Long/suspicious domain labels: +40 points**  
     _Explanation_: Attackers often use unusually long or randomized domains to evade detection or to register disposable endpoints for malicious use.  
     _Examples_:  
       - `https://super-long-domain-with-random-characters-abcdef.com`  
       - `https://1234567890abcdef.yoursite.com`

   - **External HTTP/HTTPS URLs: +30 points**  
     _Explanation_: Outbound requests to untrusted or external domains can signal attempted data exfiltration or C2 (Command and Control) communications.  
     _Examples_:  
       - `https://unknownsite.com/data`  
       - `http://external-attacker.org/path`

   - **URL shorteners: +30 points**  
     _Explanation_: URL shorteners are often used to obscure the final destination, making it easier to hide malicious links.

   - **Template placeholders: +25 points**  
     _Explanation_: Template placeholders like `{{token}}` can signal dynamically generated endpoints used for injection or exfiltration, indicating tampering opportunities.  
     _Examples_:  
       - `https://api.example.com/{{token}}/get`  
       - `https://{{host}}/download`

   - **Mailto links: +20 points**  
     _Explanation_: `mailto:` links can be used for social engineering or to silently send stolen information by crafting automated emails.  
     _Examples_:  
       - `mailto:steal@badmail.com`  
       - `mailto:fakeuser@example.com`
3. **Self-Propagation Patterns**: 80 points (default targets `.cursor/commands`, `.windsurf/workflows`, `.github`, `.github/instructions`, agent files)

**File Score Calculation:**
```
file_score = MAX(invisible_chars_score, exfil_endpoint_max_score, self_propagation_score)
```

**Individual Pattern Scores:**
Each detected pattern also receives its own individual score and verdict, allowing you to see the vulnerability level of specific detections within a file.

**Severity Thresholds:**
- CRITICAL: 80+ points
- HIGH: 50-79 points
- MEDIUM: 30-49 points
- LOW: 0-29 points

## Example Detections

**Invisible Unicode Characters:**
```
Line 42
Pattern Score: 15/100
Pattern Severity: LOW
Type: Invisible Unicode Characters
Evidence: "[⎵][⎵][⎵]curl"
```

**Exfiltration Endpoint with Token:**
```
Line 58
Pattern Score: 90/100
Pattern Severity: CRITICAL
Type: Potential Exfiltration Endpoint: URL
Evidence: "https://attacker.com?token=abc123"
```

**Exfiltration Endpoint (Simple URL):**
```
Line 64
Pattern Score: 30/100
Pattern Severity: MEDIUM
Type: Potential Exfiltration Endpoint: URL
Evidence: "https://docs.microsoft.com/azure"
```

**Exfiltration Endpoint (WSS or FTP):**
```
Line 71
Pattern Score: 30/100
Pattern Severity: HIGH
Type: Potential Exfiltration Endpoint: URL
Evidence: "wss://malicious.example.com/chat"
```
or
```
Line 75
Pattern Score: 30/100
Pattern Severity: HIGH
Type: Potential Exfiltration Endpoint: URL
Evidence: "ftp://attacker.fileserver.com/upload"
```


**Self-Propagation Pattern:**
```
Line 103
Pattern Score: 80/100
Pattern Verdict: CRITICAL
Type: Potential Self-Propagation Target: Trusted Folder
Evidence: ".cursor/commands"
```

## Support

For issues, questions, or contributions, contact Cranium AI.

---

**Developed by Cranium AI** - Protecting developers from attacks against AI.

