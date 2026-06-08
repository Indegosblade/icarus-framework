# Validation Results

Test run data from actual pipeline executions.

## v3.0.0

**Source:** Windows user profile directory
**Parser:** Windows (auto-detected)

| Metric | Value |
|--------|------:|
| Files cataloged | 2,045,000 |
| Binaries detected | 29,427 |
| Frameworks | 25,078 |
| Total entities | 2,099,505 |
| Database size | 20.5 GB |
| PII findings pre-sanitize | 24,822 |
| PII findings post-sanitize | 0 |

---

## v2.0.0

4 datasets across Windows and Linux:

| Dataset | Platform | Entities | Source Size | Binaries | PII Post-Sanitize |
|---------|----------|------:|-----:|---------:|:---:|
| User profile | Windows | 116,002 | 244 GB | 399 PE | 0 |
| Python 3.12 | Windows | 55,346 | 2,079 MB | 150 PE | 0 |
| Chrome profile | Windows | 25,916 | 3,249 MB | 3 PE | 0 |
| Ubuntu /usr | Linux (WSL2) | 96,181 | 12,834 MB | 1,111 ELF | 0 |

---

## v1.2.0

| Dataset | Platform | Entities | Binaries | PII Post-Sanitize |
|---------|----------|------:|---------:|:---:|
| Python 3.12 | Windows | 55,346 | 150 PE | 0 |
| Chrome profile | Windows | 25,916 | 3 PE | 0 |
| Ubuntu /usr | Linux | 96,181 | 1,111 ELF | 0 |

---

## Definitions

- **Entities** — rows across all ontology tables (files, binaries, daemons, entitlements, frameworks, etc.)
- **PII Post-Sanitize** — HYGEIA `verify_clean()` findings after sanitization. 0 means the database contains no detected PII.
- **Binaries** — PE (Windows) or ELF (Linux) executables detected with architecture classification.
