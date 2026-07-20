# Security Policy

## Status

ICARUS is Beta, source-available software (PolyForm Noncommercial 1.0.0). It is a
security-research tool that parses untrusted input (filesystem trees, archives, SQLite
databases, audit logs). Treat any database it produces as sensitive until it has passed
the HYGEIA sanitization phase.

## Supported versions

Only the latest released version receives security fixes. Pre-1.0 / beta releases do
not carry a backport guarantee.

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| older   | ❌        |

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue for
a security report.

- Use GitHub's **private vulnerability reporting** (the repository's *Security* tab →
  *Report a vulnerability*), or
- open a minimal public issue asking for a private contact channel, without disclosing
  details.

Include, where possible: affected version/commit, a description of the issue, and a
minimal reproduction. Please allow a reasonable window for a fix before any public
disclosure.

## Scope

In scope: memory-safety/DoS, path traversal or read-outside-source, sanitization
bypass (secrets surviving into a "sanitized" database), and injection through parsed
input. Out of scope: issues that require an already-privileged local attacker, or the
inherent behavior of the experimental entity resolver (excluded from the beta promise).
