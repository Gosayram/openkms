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

### Added
- SPIFFE auth integration; (#53)

### Changed
- Bump actions/checkout from 5.0.0 to 5.0.1
- Bump actions/checkout from 5.0.1 to 6.0.0
- Bump actions/checkout from 6.0.0 to 6.0.2 (#47)
- Bump actions/setup-go from 6.0.0 to 6.1.0
- Bump actions/setup-go from 6.1.0 to 6.2.0 (#44)
- Bump docker/build-push-action from 6.18.0 to 6.19.1 (#51)
- Bump docker/login-action from 3.6.0 to 3.7.0 (#50)
- Bump docker/setup-buildx-action from 3.11.1 to 3.12.0 (#42)
- Bump github.com/coreos/go-oidc/v3 from 3.16.0 to 3.17.0
- Bump github.com/sigstore/sigstore
- Bump gitignore with cache and build dirs
- Bump go.uber.org/zap from 1.27.0 to 1.27.1
- Bump golang from 1.25 to 1.26 in /deploy (#52)
- Bump golang.org/x/crypto from 0.44.0 to 0.45.0
- Linter config, refactor OIDC caching, and improve TLS handling
- Merge pull request #29 from Gosayram/dependabot/github_actions/actions/checkout-5.0.1
- Merge pull request #30 from Gosayram/dependabot/go_modules/github.com/sigstore/sigstore-1.10.0
- Merge pull request #31 from Gosayram/dependabot/go_modules/golang.org/x/crypto-0.45.0
- Merge pull request #32 from Gosayram/dependabot/github_actions/actions/setup-go-6.1.0
- Merge pull request #33 from Gosayram/dependabot/github_actions/actions/checkout-6.0.0
- Merge pull request #34 from Gosayram/dependabot/go_modules/go.uber.org/zap-1.27.1
- Merge pull request #35 from Gosayram/dependabot/go_modules/github.com/coreos/go-oidc/v3-3.17.0

### Security
- Add security policy and readme reference; (#54)

## [0.3.6] - 2025-11-15

### Added
- Add ABAC support for authorization #16
- Add CI/CD integration examples for artifact signing
- Add PKCS#11 and TPM 2.0 support for master key providers
- Add multi-tenant policies support
- Add verification utilities for Cosign signatures
- Implement Cosign v3+ compatible artifact signing
- Implement artifact signature format for Cosign v3
- Implement policy inheritance for RBAC and ABAC

### Changed
- Bump README
- Bump release
- Merge pull request #11 from Gosayram/fix/announce_description
- Merge pull request #14 from Gosayram/feature/phase_3_3
- Merge pull request #20 from Gosayram/feature/phase_3_4
- Merge pull request #26 from Gosayram/feature/phase_3_5
- Merge pull request #27 from Gosayram/fix/release_v0_3_6
- Merge pull request #28 from Gosayram/fix/tpm_args

### Fixed
- Pkgs url for announce description
- Replace tpmutil.OpenTPM with os.OpenFile for device path support
- Specific CGO=1 for C required libs

## [0.3.5] - 2025-11-15

### Added
- Added cosign public key for release artifacts validation
- Implement high availability support with leader election

### Changed
- Added logo and minimal improve README
- Bump release
- Merge pull request #10 from Gosayram/feature/telegram_announce
- Merge pull request #7 from Gosayram/fix/cosign_key
- Merge pull request #8 from Gosayram/docs/logo
- Merge pull request #9 from Gosayram/feature/phase_3_2

### Fixed
- Exclude logo folder for checking  copyright scripts

## [0.3.4] - 2025-11-15

### Changed
- Bump release
- Merge pull request #6 from Gosayram/fix/builds

### Fixed
- Metadata into cli for containers and added server slim version

## [0.3.3] - 2025-11-15

### Changed
- Bump release
- Merge pull request #5 from Gosayram/fix/ci

### Fixed
- Signature params for goreleaser

## [0.3.2] - 2025-11-15

### Changed
- Bump release
- Merge pull request #4 from Gosayram/fix/minor_bugs

### Fixed
- Changelog generation exclude rules
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


[Unreleased]: https://github.com/Gosayram/openkms/compare/v0.3.6...HEAD
[0.3.6]: https://github.com/Gosayram/openkms/compare/v0.3.5...v0.3.6
[0.3.5]: https://github.com/Gosayram/openkms/compare/v0.3.4...v0.3.5
[0.3.4]: https://github.com/Gosayram/openkms/compare/v0.3.3...v0.3.4
[0.3.3]: https://github.com/Gosayram/openkms/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Gosayram/openkms/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Gosayram/openkms/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Gosayram/openkms/compare/f505492a3c537cde34bba2964cffa56855efb52d...v0.3.0
