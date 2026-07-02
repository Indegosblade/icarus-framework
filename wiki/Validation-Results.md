# Validation Results

Test run data from actual pipeline executions against real directories and firmware images.

## v1.2.0 — iOS 27.0 daemon attack-surface map

First end-to-end run of the `macos` parser against a real Apple firmware image.

**Source:** `iPhone16,1_27.0_24A5370h_Restore.ipsw` (iOS 27.0, build 24A5370h, iPhone 15 Pro)
**Parser:** macos (auto-detected)
**Coverage:** base filesystem + SystemOS (sealed APFS) + AppOS cryptexes

| Metric | Value |
|--------|------:|
| Files cataloged | 252,434 |
| Binaries (Mach-O) | 3,763 |
| Daemons | 656 |
| &nbsp;&nbsp;— linked to executable | 647 (98.6%) |
| Mach services | 2,375 |
| Entitlements | 55,160 |
| &nbsp;&nbsp;— distinct keys | 5,129 |
| Frameworks | 3,438 |
| Kexts | 15 |
| Reachable + privileged (`v_sandbox_escape_surface`) | 588 |

Every launchable executable is captured with its entitlements — including the Safari/WebKit stack in the AppOS cryptex (`webpushd`, `webinspectord`, `browserkitd`). Top IPC-reachable, entitlement-bearing daemons: `SpringBoard` (527 entitlements), `assistantd`, `sharingd`, `locationd`, `CommCenter` (holds `com.apple.private.skywalk.register-kernel-pipe`). Most common entitlement keys: `security.exception.mach-lookup.global-name` (1,395), `private.tcc.allow` (671), `platform-application` (545).

Entitlements are parsed directly from each Mach-O code signature by `macho.py` (stdlib only, no `codesign`/`ldid`). The daemon → binary → entitlement chain populates `v_sandbox_escape_surface`; `mach_service_owners()` resolves any Mach service back to the daemon that vends it.

## v1.1.1

### Large-scale scan

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

### Cross-platform validation

4 datasets across Windows and Linux:

| Dataset | Platform | Entities | Source Size | Binaries | PII Post-Sanitize |
|---------|----------|------:|-----:|---------:|:---:|
| User profile | Windows | 116,002 | 244 GB | 399 PE | 0 |
| Python 3.12 | Windows | 55,346 | 2,079 MB | 150 PE | 0 |
| Chrome profile | Windows | 25,916 | 3,249 MB | 3 PE | 0 |
| Ubuntu /usr | Linux (WSL2) | 96,181 | 12,834 MB | 1,111 ELF | 0 |

---

## Definitions

- **Entities** — rows across all ontology tables (files, binaries, daemons, entitlements, frameworks, etc.)
- **PII Post-Sanitize** — HYGEIA `verify_clean()` findings after sanitization. 0 means the database contains no detected PII.
- **Binaries** — PE (Windows) or ELF (Linux) executables detected with architecture classification.
