# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Types of changes

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.

## [Unreleased]

### Fixed
- Template for binary files

## [0.3.1] - 2025-11-15

### Changed
- Bump release
- Merge pull request #2 from Gosayram/fix/dependency_updates
- Merge pull request #3 from Gosayram/fix/goreleaser

### Fixed
- Hardcoded update-deps script for each package and repo
- Package name conflicts

## [0.3.0] - 2025-11-15

### Added
- Bump release version and start phase 3
- Implement 2 phase: enhanced feature implementation with architecture plan
- Implement etcd storage backend
- Initial commit

### Changed
- Added auto-tag and push
- Added changelog automation script and generate first CHANGELOG.md
- Added release version and phase validation via arch-plan
- Added script for updating all packages in Go
- Improve  changelog logic
- Merge pull request #1 from Gosayram/feature/arch

### Fixed
- Changelog mechanism for autogen


[Unreleased]: https://github.com/Gosayram/openkms/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/Gosayram/openkms/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Gosayram/openkms/compare/f505492a3c537cde34bba2964cffa56855efb52d...v0.3.0
