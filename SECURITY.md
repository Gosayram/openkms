# Security Policy

Thank you for helping keep OpenKMS and its users secure.

## Supported Versions

We provide security fixes for the latest release line and the default development branch.

| Version | Supported |
| --- | --- |
| `main` | :white_check_mark: |
| `0.3.x` | :white_check_mark: |
| `< 0.3.0` | :x: |

## Reporting a Vulnerability

Please do **not** report security vulnerabilities in public GitHub issues, discussions, or pull requests.

Preferred reporting channel:

- GitHub Private Vulnerability Reporting: `https://github.com/Gosayram/openkms/security/advisories/new`

If private reporting is unavailable, open a minimal issue asking maintainers for a secure contact channel without sharing sensitive details.

### What to Include

To help maintainers triage quickly, include:

- Affected version, commit, or branch
- Impact and attack scenario
- Clear reproduction steps / proof of concept
- Environment details and required configuration
- Suggested remediation (optional)

## Response and Disclosure Process

- **Acknowledgement target:** within 72 hours
- **Initial triage target:** within 7 calendar days
- We follow coordinated disclosure and will work with reporters on fix timing and advisory publication.
- Credit is given in published advisories unless you request anonymity.

## Hardening Recommendations for Operators

For production deployments:

- Enable TLS and client certificate verification
- Prefer SPIFFE/mTLS and avoid static tokens where possible
- Use HSM/TPM-backed master key providers for higher assurance
- Keep dependencies and container images up to date

