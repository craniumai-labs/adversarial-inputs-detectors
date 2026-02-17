# Changelog

All notable changes to this project will be documented in this file.

## [1.0.1] - 2026-01-29

### Changed
- Changed the default value for `endpointAllowlist` to `["*"]`. This effectively disables endpoint detection by default to prevent false positives on new installations. To enable endpoint detection, set this value to an empty array (`[]`) or provide a specific list of allowed domains.
