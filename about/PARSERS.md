# Parser Development Guide

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
def extract_entities(self, source: Path, db_path: Path) -> dict:
    conn = sqlite3.connect(str(db_path))
    count = 0

    for item in self._walk_source(source):     # Iterate your source
        entity = self._normalize(item)          # Normalize to schema
        self._insert(conn, entity)              # Write to database
        count += 1

        if count % 10000 == 0:                  # Batch commits
            conn.commit()

    conn.commit()
    conn.close()
    return {"entities": count}
```

Key rules:
- **Never load the full source into RAM.** Iterate and commit in batches.
- **Use INSERT OR IGNORE** for idempotency (resume-safe).
- **Return stats** so the pipeline can report progress.

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
from icarus.parsers.windows import WindowsParser
from icarus.parsers.linux import LinuxParser  # Your new parser

PARSERS = {
    "windows": WindowsParser,
    "linux": LinuxParser,
}

def get_parser(name: str) -> BaseParser:
    if name not in PARSERS:
        raise ValueError(f"Unknown parser: {name}. Available: {list(PARSERS.keys())}")
    return PARSERS[name]()
```

---

## Parser Ideas

| Source | identify() checks | What you'd extract |
|--------|------------------|-------------------|
| Linux rootfs | `/etc/passwd`, `/usr/bin` | ELF binaries, systemd services, capabilities, AppArmor |
| Android OTA | `META-INF/`, `system/app/` | APKs, permissions, intents, receivers, SELinux |
| Docker image | `manifest.json`, layers | Layer contents, ENV vars, exposed ports, users |
| Network scan | Nmap XML format | Hosts, ports, banners, OS fingerprints, certs |
| Kubernetes | YAML manifests | Pods, RBAC, network policies, secrets refs |
| API spec | OpenAPI/Swagger JSON | Endpoints, auth requirements, schemas |
| Cloud IAM | AWS/GCP policy JSON | Roles, permissions, trust relationships |

The framework handles storage, querying, diffing, and sanitization. Your parser just needs to extract and normalize.
