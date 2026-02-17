# Endpoint Allowlist Configuration

The Adversarial Inputs Detector allows you to configure an allowlist of endpoints that should be excluded from detection. This is useful for legitimate company URLs, documentation sites, or known safe endpoints.

## Configuration

Add patterns to your VS Code settings (`.vscode/settings.json` or User Settings):

```json
{
  "promptInjectionDetector.endpointAllowlist": [
    "https://docs.company.com/*",
    "https://github.com/*",
    "https://api.internal.com/*",
    "localhost:*",
    "mailto:support@company.com"
  ]
}
```

## Wildcard Support

The allowlist supports wildcards for flexible pattern matching:

- `*` - Matches any characters (including none)
- `?` - Matches exactly one character

### Examples

| Pattern | Matches | Doesn't Match |
|---------|---------|---------------|
| `https://github.com/*` | `https://github.com/repo`, `https://github.com/user/project` | `https://gitlab.com` |
| `https://api.*.com` | `https://api.internal.com`, `https://api.external.com` | `https://api.example.org` |
| `localhost:*` | `localhost:3000`, `localhost:8080` | `127.0.0.1:3000` |
| `mailto:*@company.com` | `mailto:user@company.com`, `mailto:admin@company.com` | `mailto:user@other.com` |
| `https://docs.company.com/v?` | `https://docs.company.com/v1`, `https://docs.company.com/v2` | `https://docs.company.com/v10` |

## What Gets Filtered

The allowlist applies to:
- ✅ HTTP/HTTPS URLs
- ✅ FTP URLs
- ✅ WebSocket URLs (ws://, wss://)
- ✅ Data URIs
- ✅ Mailto links

## Dynamic Updates

Changes to the allowlist are automatically detected:
1. The detector reloads the settings
2. The workspace is re-scanned with the new allowlist
3. Diagnostics are updated in real-time

## Best Practices

1. **Be Specific**: Use specific patterns rather than overly broad ones
   - ❌ Bad: `*` (allows everything)
   - ✅ Good: `https://docs.company.com/*`

2. **Company Domains**: Allowlist your organization's legitimate domains
   ```json
   "promptInjectionDetector.endpointAllowlist": [
     "https://*.company.com/*",
     "https://company.io/*"
   ]
   ```

3. **Common Documentation Sites**: Consider allowlisting well-known documentation sites
   ```json
   "promptInjectionDetector.endpointAllowlist": [
     "https://docs.python.org/*",
     "https://developer.mozilla.org/*",
     "https://stackoverflow.com/*"
   ]
   ```

4. **Development Endpoints**: Allowlist local development servers
   ```json
   "promptInjectionDetector.endpointAllowlist": [
     "http://localhost:*",
     "http://127.0.0.1:*",
     "http://*.local/*"
   ]
   ```

## Checking Current Configuration

To view your current allowlist:
1. Open VS Code Settings (Cmd/Ctrl + ,)
2. Search for "Adversarial Inputs Detector"
3. Look for "Endpoint Allowlist"

Or check the Debug Console (View > Debug Console) when the extension activates:
```
[Settings] Loaded endpoint allowlist: 5 patterns
```

## Example Configuration

Here's a complete example for a typical corporate environment:

```json
{
  "promptInjectionDetector.endpointAllowlist": [
    // Company domains
    "https://*.company.com/*",
    "https://company.io/*",
    
    // Documentation sites
    "https://docs.python.org/*",
    "https://developer.mozilla.org/*",
    "https://nodejs.org/*",
    
    // Development
    "http://localhost:*",
    "http://127.0.0.1:*",
    
    // Internal APIs
    "https://api.internal.company.com/*",
    
    // Support
    "mailto:support@company.com",
    "mailto:security@company.com"
  ],
  
  "promptInjectionDetector.minVulnLevel": "HIGH",
  "promptInjectionDetector.autoScanOnOpen": true
}
```

## Troubleshooting

**Q: My allowlisted URLs are still being flagged**
- Check the pattern syntax (wildcards must be `*` or `?`)
- Ensure the pattern matches the entire URL (use `*` at the end)
- Check the Debug Console for allowlist load messages

**Q: Too many false positives**
- Add specific patterns to the allowlist
- Consider raising `minVulnLevel` to reduce alerts

**Q: Changes not taking effect**
- Save the settings file
- The workspace will automatically re-scan
- If not, run "Scan Workspace for Adversarial Inputs" command

