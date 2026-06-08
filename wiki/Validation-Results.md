# Validation Results

Every number on this page comes from an actual pipeline run. No synthetic benchmarks.

## v3.0.0 — Full Machine Scan

**Source:** `C:\Users\Kevin` (complete Windows user profile)
**Parser:** Windows (production, specificity 20)
**Install:** Fresh `pip install` from GitHub (clean clone)

| Metric | Value |
|--------|------:|
| Files cataloged | **2,045,000** |
| Binaries detected | **29,427** |
| Frameworks | **25,078** |
| **Total entities** | **2,099,505** |
| Database size | **20.5 GB** |
| Schema version | v4 |

### HYGEIA Sanitization

| Phase | PII Findings |
|-------|:------------:|
| Pre-sanitize verify | **FAILED** (100+ patterns detected) |
| Sanitization pass | **24,822 entries redacted** |
| Post-sanitize verify | **PASSED** (0 findings) |

PII detected: email patterns in file paths (LMStudio extensions, application data), username references in directory paths. All redacted. Zero residual.

---

## v2.0.0 — Multi-Source Validation

4 real-world datasets across 2 platforms:

| Dataset | Platform | Entities | Source Size | Binaries | Runtime | PII | HYGEIA |
|---------|----------|------:|-----:|---------:|--------:|:---:|:------:|
| Full user profile | Windows | 116,002 | 244 GB | 399 PE | 49s | **0** | **PASS** |
| Python 3.12 | Windows | 55,346 | 2,079 MB | 150 PE | 25s | **0** | **PASS** |
| Chrome profile | Windows | 25,916 | 3,249 MB | 3 PE | 18s | **0** | **PASS** |
| Ubuntu /usr | Linux (WSL2) | 96,181 | 12,834 MB | 1,111 ELF | 52s | **0** | **PASS** |
| **Total** | | **293,445** | | **1,663** | | | |

---

## v1.2.0 — Cross-Platform Validation

| Dataset | Platform | Entities | Binaries | PII | HYGEIA |
|---------|----------|------:|---------:|:---:|:------:|
| Python 3.12 | Windows | 55,346 | 150 PE | **0** | **PASS** |
| Chrome profile | Windows | 25,916 | 3 PE | **0** | **PASS** |
| Ubuntu /usr | Linux | 96,181 | 1,111 ELF | **0** | **PASS** |
| **Total** | | **177,443** | **1,264** | | |

---

## Cumulative

| Version | Total Entities Validated | Datasets | Platforms | PII Residual |
|---------|------:|:---:|:---:|:---:|
| v3.0.0 | 2,099,505 | 1 | Windows | **0** |
| v2.0.0 | 293,445 | 4 | Windows + Linux | **0** |
| v1.2.0 | 177,443 | 3 | Windows + Linux | **0** |

## What the Numbers Mean

- **Entities** = rows inserted across all ontology tables (files + binaries + daemons + entitlements + frameworks + etc.)
- **PII** = HYGEIA `verify_clean()` findings post-sanitization. 0 means the database is safe to share.
- **HYGEIA PASS** = `verify_clean()` returned `{"passed": True, "findings": 0}`
- **Binaries** = PE (Windows) or ELF (Linux) executables detected and cataloged with architecture classification
