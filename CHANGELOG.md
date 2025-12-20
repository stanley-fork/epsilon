# Changelog

All notable changes to this project will be documented in this file.

## [0.0.3] - 2025-12-20

- **API Changes**: `ExperimentalFeatures` has been replaced by `Config`, and `Runtime.WithFeatures` has been renamed to `WithConfig` (#28).
- `Config` now allows configuring pre-allocated cache sizes and the maximum call stack depth. It also retains support for enabling experimental features like `ExperimentalMultipleMemories` (#28).
- Major performance improvements (#25, #28, #30).

## [0.0.2] - 2025-12-14

- Major, multiple performance improvements (#21, #22, #24)
- Introduced a simple CLI (#19, #20)
- Added hello world example (#10 @deadprogram)
- Fixed malloc crash on Fedora when parsing invalid custom sections
- Fixed bounds check on amd64 (#13, #14)

## [0.0.1] - 2025-12-07

Initial release.