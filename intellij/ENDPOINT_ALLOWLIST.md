# Endpoint Allowlist Configuration

The Adversarial Inputs Detector allows you to configure an allowlist of endpoints that should be excluded from detection. This is useful for legitimate company URLs, documentation sites, or known safe endpoints.

## Configuration

Configure the allowlist in your JetBrains IDE settings:

1. Open **Settings → Tools → Adversarial Inputs Detector**
2. In the **Endpoint Allowlist** section, add one pattern per line:

```
https://docs.company.com/*
https://github.com/*
https://api.internal.com/*
localhost:*
mailto:support@company.com
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

Changes to the allowlist require a manual rescan:
1. Update your settings in **Settings → Tools → Adversarial Inputs Detector**
2. Run **Tools → Scan Project for Adversarial Inputs** to rescan with the new allowlist
3. The tool window and in-editor annotations will update with the new results

## Best Practices

1. **Be Specific**: Use specific patterns rather than overly broad ones
   - ❌ Bad: `*` (allows everything)
   - ✅ Good: `https://docs.company.com/*`

2. **Company Domains**: Allowlist your organization's legitimate domains
   ```
   https://*.company.com/*
   https://company.io/*
   ```

3. **Common Documentation Sites**: Consider allowlisting well-known documentation sites
   ```
   https://docs.python.org/*
   https://developer.mozilla.org/*
   https://stackoverflow.com/*
   ```

4. **Development Endpoints**: Allowlist local development servers
   ```
   http://localhost:*
   http://127.0.0.1:*
   http://*.local/*
   ```

## Checking Current Configuration

To view your current allowlist:
1. Open **Settings** (`Ctrl+Alt+S` on Windows/Linux, `Cmd+,` on Mac)
2. Navigate to **Tools → Adversarial Inputs Detector**
3. View the **Endpoint Allowlist** field

The IDE console may also show allowlist information during scanning.

## Example Configuration

Here's a complete example for a typical corporate environment.

In **Settings → Tools → Adversarial Inputs Detector**, configure:

**Endpoint Allowlist** (one pattern per line):
```
https://*.company.com/*
https://company.io/*
https://docs.python.org/*
https://developer.mozilla.org/*
https://nodejs.org/*
http://localhost:*
http://127.0.0.1:*
https://api.internal.company.com/*
mailto:support@company.com
mailto:security@company.com
```

**Minimum vulnerability level**: HIGH
**Auto-scan on project open**: Enabled

## Troubleshooting

**Q: My allowlisted URLs are still being flagged**
- Check the pattern syntax (wildcards must be `*` or `?`)
- Ensure the pattern matches the entire URL (use `*` at the end)
- Verify each pattern is on a separate line in the settings
- After updating settings, run **Tools → Scan Project for Adversarial Inputs**

**Q: Too many false positives**
- Add specific patterns to the allowlist
- Consider raising **Minimum vulnerability level** to HIGH or CRITICAL
- Review the tool window to identify which URLs are being flagged

**Q: Changes not taking effect**
- Click **Apply** or **OK** to save settings changes
- Manually trigger a rescan: **Tools → Scan Project for Adversarial Inputs**
- Check the tool window to verify updated results

