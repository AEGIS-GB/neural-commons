# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | Yes (latest only)  |
| < 0.2   | No                 |

Only the most recent release receives security patches. Users should always
run the latest version.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Report vulnerabilities through one of the following channels:

- **Email:** [security@igentity.foundation](mailto:security@igentity.foundation)
- **GitHub:** Use [private vulnerability reporting](https://github.com/LCatGA12/neural-commons/security/advisories/new)

### What to Include

- A clear description of the vulnerability.
- Step-by-step instructions to reproduce the issue.
- An assessment of impact and severity (who is affected and how).
- Any relevant logs, screenshots, or proof-of-concept code.

### Response Timeline

- **Acknowledgement:** Within 48 hours of receipt.
- **Triage and assessment:** Within 7 days.
- **Fix for critical issues:** Within 14 days of confirmation.
- **Fix for non-critical issues:** Included in the next scheduled release.

We will coordinate disclosure timing with the reporter before any public
announcement.

## Scope

### In Scope

The following are considered security issues:

- Cryptographic weaknesses in signing, encryption, or key derivation.
- Evidence chain integrity bypass or tampering.
- Vault key leakage or unauthorized key extraction.
- Barrier policy bypass (circumventing configured access controls).
- Injection vulnerabilities in the proxy layer (header injection, request smuggling, etc.).
- Privilege escalation between agent sessions or trust boundaries.

### Out of Scope

The following are **not** treated as security issues in this project:

- Denial-of-service against the localhost proxy (local-only by design).
- Social engineering attacks against maintainers or users.
- Vulnerabilities in upstream dependencies -- please report those to the
  relevant upstream project directly.

## Credit

Reporters who disclose responsibly will be credited by name in the release
notes accompanying the fix, unless they request anonymity.

## License

This project is licensed under AGPL-3.0. See [LICENSE](LICENSE) for details.
