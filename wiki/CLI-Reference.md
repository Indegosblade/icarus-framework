# CLI Reference

## `icarus build`

Build an intelligence database from a data source.

```bash
icarus build --source PATH --output PATH [--parser NAME] [--fresh] [--skip-hygeia]
```

| Flag | Description |
|------|-------------|
| `--source, -s` | Path to data source directory (required) |
| `--output, -o` | Output database path (required) |
| `--parser, -p` | Parser name (default: auto-detect from source contents) |
| `--fresh` | Ignore checkpoints, start from scratch |
| `--skip-hygeia` | Skip PII sanitization (output contains raw data) |

**Auto-detection:** When `--parser` is omitted, the registry runs each parser's `identify()` method against the source. The parser with the lowest specificity level wins. If no specific parser matches, a generic fallback catches it.

**Examples:**
```bash
icarus build -s "C:\Users\Kevin" -o full_scan.db
icarus build -s /var/log/cloudtrail -o trail.db --parser cloud/aws/cloudtrail
icarus build -s /usr -o linux.db --parser linux --fresh
```

---

## `icarus query`

Query an intelligence database.

```bash
icarus query DATABASE [--sql QUERY] [--search TERMS] [--table TABLE] [--stats]
```

| Flag | Description |
|------|-------------|
| `DATABASE` | Path to ICARUS database (positional) |
| `--sql` | Raw SQL query |
| `--search` | Full-text search query (FTS5) |
| `--table` | Table for FTS search (default: files) |
| `--stats` | Show table row counts |

**Examples:**
```bash
icarus query intel.db --stats
icarus query intel.db --search "nginx"
icarus query intel.db --search "systemd" --table daemons
icarus query intel.db --sql "SELECT path, size FROM files WHERE size > 100000000 ORDER BY size DESC LIMIT 20"
```

---

## `icarus diff`

Compare two intelligence databases.

```bash
icarus diff OLD NEW [--output PATH] [--stix PATH]
```

| Flag | Description |
|------|-------------|
| `OLD` | Path to older database (positional) |
| `NEW` | Path to newer database (positional) |
| `--output, -o` | Write markdown report to file (default: stdout) |
| `--stix` | Export diff as STIX 2.1 bundle JSON |

**Examples:**
```bash
icarus diff v1.db v2.db
icarus diff v1.db v2.db -o changes.md
icarus diff v1.db v2.db --stix bundle.json
```

---

## `icarus parser`

Parser management commands.

### `icarus parser list`

List all registered parsers with tier, version, specificity, and description.

```bash
icarus parser list
```

Output:
```
Name                 Tier         Version    Spec   Description
--------------------------------------------------------------------------------
cloud/aws/cloudtrail production   1.0.0      5      AWS CloudTrail JSON audit log parser
windows              production   1.0.0      20     Windows application directory or filesystem tree
linux                production   1.0.0      20     Linux filesystem rootfs
generic/json         production   1.0.0      100    Generic JSON file directory
generic/xml          production   1.0.0      100    Generic XML file directory
generic/sqlite       production   1.0.0      100    Generic SQLite database directory
generic/archive      production   1.0.0      100    Generic archive directory
generic/binary       production   1.0.0      100    Generic binary/unknown
```

### `icarus parser validate`

Validate a parser YAML manifest against the JSON Schema.

```bash
icarus parser validate PATH
```

### `icarus parser test`

Run the 4-gate test harness against a parser.

```bash
icarus parser test PARSER_NAME
```

Gates: golden output, idempotency, schema conformance, zero-PII.
