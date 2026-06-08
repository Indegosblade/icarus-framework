# Parser Development Guide

## Built-In Parsers

ICARUS ships with two parsers, both validated against real-world data:

| Parser | Platform | Detects | Validated |
|--------|----------|---------|-----------|
| `windows` | Windows | PE binaries (x86/x64/arm64), DLLs, configs | 116,002 entities (6-source profile scan) |
| `linux` | Linux | ELF binaries (x86/x86_64/aarch64/arm/riscv), .so libs, systemd services | 96,181 files (Ubuntu 24.04) |

## Writing a Custom Parser

Every ICARUS parser implements `BaseParser` from `icarus/parsers/base.py`. The interface is minimal — four methods cover the full extraction lifecycle.

---

## Interface

```python
class BaseParser(ABC):

    @property
    def name(self) -> str:
        """Short identifier: 'windows', 'linux', 'android', 'network'"""

    @property
    def description(self) -> str:
        """One-line: 'Windows application directory analysis'"""

    def identify(self, source: Path) -> bool:
        """Can this parser handle this source? Check for markers."""

    def extract_entities(self, source: Path, db_path: Path) -> dict:
        """Main extraction — write entities to database tables."""

    def extract_relationships(self, source: Path, db_path: Path) -> dict:
        """Link entities together (runs after extract_entities)."""

    def verify(self, db_path: Path) -> dict:
        """Quality gates — assert expected state."""

    def get_required_tools(self) -> list:
        """External tool dependencies: ['readelf', 'aapt']"""
```

---

## Extraction Pattern

Every parser follows the same streaming pattern:

```python
import os

def extract_entities(self, source: Path, db_path: Path) -> dict:
    conn = sqlite3.connect(str(db_path))
    count = 0
    try:
        for dirpath, _dirs, files in os.walk(source, onerror=lambda e: None):
            for fname in files:
                path = Path(dirpath) / fname
                try:
                    entity = self._normalize(path, source)
                    self._insert(conn, entity)
                    count += 1
                except (PermissionError, OSError):
                    continue
                if count % 10000 == 0:
                    conn.commit()
        conn.commit()
    finally:
        conn.close()
    return {"entities": count}
```

Key rules:
- **Use `os.walk` with `onerror` callback, not `rglob`.** Broken symlinks, WSL artifacts, and inaccessible directories crash `pathlib.rglob()`. `os.walk(onerror=lambda e: None)` skips them.
- **Wrap connections in `try/finally`.** If extraction crashes mid-walk, the connection must close or subsequent runs hit "database is locked."
- **Never load the full source into RAM.** Iterate and commit in batches.
- **Use INSERT OR IGNORE** for idempotency (resume-safe).
- **Return stats** so the pipeline can report progress and finalize provenance.

---

## Schema Mapping

Map your source's concepts to ICARUS tables:

| ICARUS Table | Windows Maps To | Linux Maps To | Android Maps To | Network Maps To |
|-------------|-----------------|---------------|-----------------|-----------------|
| `files` | Filesystem | Filesystem | APK contents | — |
| `binaries` | PE executables | ELF binaries | DEX/native libs | — |
| `daemons` | Windows services | systemd units | Services in manifests | Listening services |
| `entitlements` | Permissions/ACLs | Linux capabilities | Android permissions | Port/protocol |
| `sandbox_profiles` | AppLocker policies | AppArmor profiles | SELinux policies | Firewall rules |
| `sandbox_rules` | Policy rules | AppArmor rules | SELinux allow rules | iptables entries |
| `kexts` | Kernel drivers | .ko modules | Kernel modules | — |
| `frameworks` | DLLs | .so libraries | JARs/AARs | — |

Not every table needs data for every source type. A network scan has no `files` table — that's fine. Use what applies.

---

## Registration

Add your parser to `icarus/parsers/__init__.py`:

```python
from icarus.parsers.my_parser import MyParser
PARSERS["my_parser"] = MyParser
```

The parser is immediately available via CLI (`--parser my_parser`) and API (`parser_name="my_parser"`).

---

## Parser Ideas

| Source | identify() checks | What you'd extract |
|--------|------------------|-------------------|
| Android OTA | `META-INF/`, `system/app/` | APKs, permissions, intents, receivers, SELinux |
| Docker image | `manifest.json`, layers | Layer contents, ENV vars, exposed ports, users |
| Network scan | Nmap XML format | Hosts, ports, banners, OS fingerprints, certs |
| Kubernetes | YAML manifests | Pods, RBAC, network policies, secrets refs |
| API spec | OpenAPI/Swagger JSON | Endpoints, auth requirements, schemas |
| Cloud IAM | AWS/GCP policy JSON | Roles, permissions, trust relationships |

The framework handles storage, querying, diffing, and sanitization. Your parser just needs to extract and normalize.
