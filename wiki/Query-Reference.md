# Query Reference

## Intelligence Views

Pre-built queries via `IcarusQuery`:

```python
from icarus.core.query import IcarusQuery

with IcarusQuery("intel.db") as q:
    # Services running as root with no sandbox profile
    q.root_daemons()

    # Service -> binary -> permission map
    q.service_map()

    # Kernel-reachable entry points from userland
    q.kernel_surface()

    # Test/debug binaries left in production
    q.test_binaries()

    # High-privilege entities reachable from low-privilege
    q.escape_surface()

    # Permission/entitlement distribution across binaries
    q.privileged_entitlements()
```

## Full-Text Search

FTS5 indexes on files, daemons, and atoms. Available via CLI or API.

```bash
# Search files
icarus query intel.db --search "config"

# Search daemons
icarus query intel.db --search "nginx" --table daemons
```

```python
with IcarusQuery("intel.db") as q:
    results = q.search("nginx", table="daemons")
    print(results.to_markdown())
```

## Raw SQL

```bash
icarus query intel.db --sql "SELECT filename, size FROM files WHERE size > 100000000 ORDER BY size DESC LIMIT 10"
```

```python
with IcarusQuery("intel.db") as q:
    results = q.execute("SELECT COUNT(*) as cnt, arch FROM binaries GROUP BY arch ORDER BY cnt DESC")
    print(results.to_markdown())
```

## Observation Queries

```python
with IcarusQuery("intel.db") as q:
    # All observations for a specific daemon
    q.observations_for("daemons", daemon_id)

    # Observations within a time window
    q.pattern_of_life("daemons", daemon_id, "2024-01-01", "2024-06-01")

    # First time an entity was observed
    q.first_seen("files", file_id)

    # Join ontology entities with their observations
    q.cross_graph_query("daemons", event_type="permission_change")

    # New observations between pipeline runs
    q.observation_diff(start_version_id=1, end_version_id=2)
```

## Stats

```bash
icarus query intel.db --stats
```

Output:
```
files: 2,045,000
binaries: 29,427
daemons: 0
entitlements: 0
frameworks: 25,078
observations: 0
```

## Common Patterns

**Largest files:**
```sql
SELECT path, size FROM files ORDER BY size DESC LIMIT 20
```

**Binary architecture distribution:**
```sql
SELECT arch, COUNT(*) as cnt FROM binaries GROUP BY arch ORDER BY cnt DESC
```

**Files by type:**
```sql
SELECT file_type, COUNT(*) as cnt FROM files GROUP BY file_type ORDER BY cnt DESC
```

**Daemons without sandbox:**
```sql
SELECT label, program, user_name FROM daemons WHERE sandbox_profile IS NULL AND user_name = 'root'
```

**Cross-version additions:**
```python
with IcarusDiffer("v1.db", "v2.db") as d:
    results = d.full_diff()
    for category, diff in results.items():
        if hasattr(diff, 'added') and diff.added:
            print(f"{category}: {len(diff.added)} added")
```
