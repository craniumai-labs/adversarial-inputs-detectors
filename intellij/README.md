# Adversarial Inputs Detector - JetBrains Plugin

A JetBrains IDE plugin that detects malicious content in documentation and code files that can exploit AI coding assistants.

## Supported IDEs

- IntelliJ IDEA (Community & Ultimate)
- PyCharm
- WebStorm
- Android Studio
- CLion
- Rider
- GoLand
- PhpStorm
- RubyMine
- All JetBrains IDEs based on IntelliJ Platform 2023.1+

## What It Does

Protects developers from malicious repositories by detecting three categories of threats:

1. **🔍 Invisible Unicode Characters** - Hidden instructions using zero-width characters, bidirectional overrides, and Unicode steganography
2. **📡 Exfiltration Endpoints** - External URLs, data URIs, and API endpoints that could leak sensitive data
3. **🔄 Self-Propagation Patterns** - References to trusted folders (e.g., `.cursor/commands`, `.windsurf/workflows`, `.github`) and agent files (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`) that contains automation mechanisms, which could enable malware to spread

## Key Features

✅ **Auto-scan on project open** - Immediate protection
✅ **Real-time file monitoring** - Detects changes as you work
✅ **Smart severity scoring** - CRITICAL (80+), HIGH (50-79), MEDIUM (30-49), LOW (0-29)
✅ **Configurable allowlist and trusted folders** - Reduce false positives for known safe domains and extensible to additional trust mechanisms
✅ **Status bar integration** - Shows threat count with clickable popup
✅ **Tool window with sortable table** - Detailed scan results view
✅ **In-editor annotations** - Real-time highlighting of threats with hover tooltips
✅ **Comprehensive coverage** - Scans all text-based files that could contain prompt injection

## Quick Start

1. **Configure plugin** - Go to **Settings → Tools → Adversarial Inputs Detector** to create allowlist for legitimate domains, threshold for alerts, and additional trust folders for detecting self-propagation patterns
2. **Open any project** - Auto-scan runs on startup if enabled
3. **View threats** in multiple locations (see Output & Results section below)

## Configuration

Access settings via **Settings → Tools → Adversarial Inputs Detector**:

- **Auto-scan on project open** - Automatically scan files when project opens (True, False)
- **Minimum vulnerability level** - Minimum severity required to trigger alerts (LOW, MEDIUM, HIGH, CRITICAL)
- **Endpoint Allowlist** - URLs/domains to exclude from detection (supports wildcards). By default, `*` is used to allow all domains (i.e., turn-off endpoint detection). Setting an empty array will enable endpoint detection.
- **Target Folders** - Trusted folders that contain automation mechanisms (e.g., workflows, LLM instructions) that AI assistants read. Malicious code attempting to write to these folders may be trying to inject instructions that will be executed by the AI on future runs to self propagate.
- **Agent Files** - Special configuration files (e.g., `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`) that AI coding assistants read for project-specific instructions. Attempts to write to these files may indicate self-propagation, where malicious instructions try to persist by modifying the files that guide AI behavior.

### Example Configuration

**Endpoint Allowlist:**
```
https://github.com/*
https://*.example.com/*
localhost:*
```

**Target Folders:**
```
.windsurf/workflows
.cursor/commands
.github
.github/instructions
```

**Agent Files:**
```
agents.md
claude.md
gemini.md
```

## Additional Documentation

- **ENDPOINT_ALLOWLIST.md** - How to configure endpoint allowlist with wildcards

## Commands

- **Tools → Scan Project for Adversarial Inputs** - Manually trigger a full project scan
- **Tools → Report This Repository** - Report a repository containing adversarial inputs (coming soon)

## Output & Results

The JetBrains plugin provides multiple ways to view scan results:

### 1. **Adversarial Inputs Tool Window** (`View` → `Tool Windows` → `Adversarial Inputs`)
Shows a sortable table with all detected threats:
- **File**: Relative path from project root
- **Severity**: CRITICAL, HIGH, MEDIUM, or LOW
- **Score**: Risk score out of 100
- **Evidence Count**: Number of detected patterns in the file

The table automatically sorts by score (highest to lowest) and filters based on your configured minimum vulnerability level. Click **Tools → Scan Project for Adversarial Inputs** to manually refresh the data.

### 2. **In-Editor Annotations** (underlines/squiggles)
- **Red underlines**: CRITICAL or HIGH severity patterns
- **Yellow underlines**: MEDIUM or LOW severity patterns
- **Hover** over underlined text to see detailed information about the detection including:
  - Pattern type
  - Severity level
  - Score
  - Matched evidence

### 3. **Status Bar Widget** (bottom right)
- Shows threat count with icon: "🚨 X Threats" or "⚠️ X Threats"
- **Red icon (🚨)**: Critical threats present
- **Yellow icon (⚠️)**: High/Medium threats present
- **Click** the widget to see a popup with a quick summary of detected threats
- **Empty**: No threats detected

### 4. **Notification Popups**
When a scan completes, you'll see a notification with:
```
⚠️ Scan Complete - Threats Detected

Scanned 250 files
Found 5 potential threat(s):
🚨 CRITICAL: 2 file(s)
⚠️ HIGH: 3 file(s)
```

For clean scans:
```
✅ Scan Complete

Scanned 250 files. No adversarial input threats detected.
```

### 5. **Console Output** (development/debug mode)
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

## Using the JetBrains Plugin

### Manual Rescanning

There are several ways to manually trigger a scan:

1. **Via Tools Menu**: Go to **Tools → Scan Project for Adversarial Inputs**
2. **Via Find Action**: Press `Ctrl+Shift+A` (Windows/Linux) or `Cmd+Shift+A` (Mac), type "Scan Project", and select the action
3. **After Configuration Changes**: After updating your allowlist or other settings, run a manual scan to see updated results

The scan will run in the background with a progress indicator. When complete, you'll see a notification with the summary.

### Using the Adversarial Inputs Table

The tool window table provides a comprehensive overview of all detected threats:

1. **Opening the Table**: Go to **View → Tool Windows → Adversarial Inputs** or click the "Adversarial Inputs" tab (usually on the bottom or side of the IDE)

2. **Table Columns**:
   - **File**: Click to jump to the file in the editor
   - **Severity**: Color-coded severity level (CRITICAL/HIGH/MEDIUM/LOW)
   - **Score**: Numerical risk score out of 100
   - **Evidence Count**: Number of detections in the file (filtered by your minimum vulnerability level)

3. **Sorting**: Click any column header to sort by that column. By default, files are sorted by score (highest first)

4. **Filtering**: The table automatically filters results based on your **Minimum vulnerability level** setting. To see all detections, set it to LOW in settings.

5. **Navigation**: Click on any file path to open it in the editor and see the in-editor annotations

### Interpreting In-Editor Annotations

When you open a file with detected threats:

1. **Look for Underlines**:
   - Red squiggles indicate CRITICAL or HIGH severity patterns
   - Yellow squiggles indicate MEDIUM or LOW severity patterns

2. **Hover for Details**: Place your cursor over any underlined text to see:
   - Detection type (Invisible Unicode, Exfiltration Endpoint, Self-Propagation)
   - Severity level
   - Score
   - The exact matched content

3. **Multiple Detections**: A single file may have multiple underlined sections if it contains multiple patterns

### Monitoring via Status Bar

The status bar widget (bottom right) provides at-a-glance monitoring:

- **No threats**: Widget is hidden
- **Threats detected**: Shows threat count with icon (🚨 for CRITICAL, ⚠️ for HIGH/MEDIUM)
- **Click for details**: Click the widget to see a popup with file names, severities, and scores
- **Auto-updates**: The widget automatically updates after each scan

## Troubleshooting

### Plugin doesn't load
- Check IDE version compatibility (IntelliJ Platform 2023.1+)
- Review **Help → Show Log in Finder/Explorer** for errors
- Verify plugin is enabled in **Settings → Plugins**
- Try restarting the IDE after installation

### Scans not running automatically
- Check auto-scan setting is enabled: **Settings → Tools → Adversarial Inputs Detector → Auto-scan on project open**
- Verify the project has been fully indexed (wait for indexing to complete)
- Manually trigger: **Tools → Scan Project for Adversarial Inputs**

### Too many false positives
- Adjust **Minimum vulnerability level** to HIGH or CRITICAL
- Add legitimate domains to **Endpoint Allowlist** (e.g., `https://github.com/*`, `https://*.company.com/*`)
- By default, endpoint detection is disabled (allowlist contains `*`). To enable it, remove `*` from the allowlist
- Configure **Target Folders** and **Agent Files** to match your project structure

### Tool window not showing results
- Ensure you've run at least one scan: **Tools → Scan Project for Adversarial Inputs**
- Check that your **Minimum vulnerability level** isn't too restrictive (try setting to LOW temporarily)
- Open the tool window: **View → Tool Windows → Adversarial Inputs**

### In-editor annotations not appearing
- Annotations only appear for files that are currently open in the editor
- Try closing and reopening the file
- Verify the file was scanned (check the tool window table)

## Support

For issues, questions, or contributions, contact Cranium AI.

---

**Developed by Cranium AI** - Protecting developers from attacks against AI.
