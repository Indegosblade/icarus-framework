# ICARUS — Contract-to-Test Matrix

Maps advertised contracts to test coverage. **Legend:** ✅ covered · ⚠️ shape-only
(proves structure, not behavior) · ❌ missing · 🔧 regression added in an audit PR.

## Packaging & installation
| Contract | Coverage | Note |
|---|---|---|
| Built wheel/sdist ship runtime data | 🔧 `tests/test_packaging.py` (PR #37) | builds artifacts, asserts 14 data files |
| Installed CLI works from the wheel | 🔧 CI `package` job (**#37 merged**) | installs the wheel, smoke-tests CLI off the source tree |
| `icarus parser test` fixtures ship | ❌ | fixtures in neither artifact (#32) |

## Schema, migrations, provenance, connections
| Contract | Coverage | Note |
|---|---|---|
| Fresh v6 init | ✅ `test_schema_init_and_fts` | |
| Fresh-vs-migrated parity (sqlite_master) | ❌ | no cross-check; divergence (#29/DM-06) |
| Forward-version refusal | 🔧 (#53) | refuses future/malformed/incomplete; 5 negative-path tests (#39) |
| Entity provenance populated | ⚠️→❌ | tests check columns exist, not that they're set (#40) |
| FK enforced on write paths | 🔧 (#54) | open_db on every write path + `foreign_key_check` gate; adversarial tests (#44) |
| FTS sync on update/delete | ⚠️ | `atoms` has no update trigger (#42/SAN-09) |
| Checkpoint resume identity | ⚠️ | `test_pipeline_checkpoint_resume` covers clear-on-success, not source-change (#45) |
| Existing-output semantics | ❌ | union/no-atomic (#36) |

## Parsers & hostile input
| Contract | Coverage | Note |
|---|---|---|
| Golden-output per parser | ✅ harness | but relationships phase not run (#27) |
| Symlink containment (all readers) | ❌ → 🔧 needed | readers follow links (#43) |
| FIFO/special files, non-UTF-8, deep JSON, zip bombs | ❌ | crash/hang/unbounded (#47) |
| IP validation | ❌ | accepts non-IPs (#47/PARSER-05) |
| Auto-detect specificity | ⚠️ | degrades when manifests missing (#32) |

## Diff
| Contract | Coverage | Note |
|---|---|---|
| add/remove/changed on natural keys | ✅ | correct |
| structural diff by natural key | 🔧 `test_diff_natural_keys.py` (PR #38) | 3 bug-encoding tests corrected |
| observation diff by natural key | 🔧 (#38) | resolves entity_id→natural key per table; insertion-order-skew test (#33) |
| `full_diff` covers documented tables | ❌ | omits most (#35) |
| report escapes hostile values | ❌ | (#35) |

## STIX
| Contract | Coverage | Note |
|---|---|---|
| Valid STIX 2.1 (entity + diff) | ⚠️ regex shape tests only | strict `stix2.parse` rejects 12/14 (#21) |
| Deterministic, non-colliding ids | ❌ | non-UUID, dangling, dup (#21) |

## Sanitization
| Contract | Coverage | Note |
|---|---|---|
| PII removed | ✅ (email/ssn/path) | but lowercase UUID (#22) |
| Secrets removed | ✅ | HYGEIA canonical + credential patterns (#41, merged #59) |
| Post-sanitize verification gate | ✅ | mandatory re-scan fails the build on residual (#42, merged #59) |
| All text tables covered | ✅ | `metadata` + FTS content scanned (#42, merged #59) |

## Resolver (experimental)
| Contract | Coverage | Note |
|---|---|---|
| Append-only event log | ⚠️ **false-positive test** | `test_event_log_append_only` passes despite rewrite (#46/ER-01) |
| Membership invariants / atomicity | ❌ | multi-bag atoms, non-atomic (#46) |
| Threshold bounds, candidate recall, cluster purity | ❌ | (#46) |

## Cross-cutting gaps to add (per accepted fix)
Clean wheel/sdist install; installed-artifact e2e; migration parity + forward refusal;
provenance on real output; FK-on assertions; resume identity; symlink containment;
oversized/special-file limits; randomized-insertion-order structural diff; strict STIX
validation + reference closure; resolver invariants + rollback + threshold bounds;
seeded-secret sanitization across every text table; doc/version consistency checks.

## Platform / environment axes
Tested here: Linux (WSL2) / Python 3.12 / SQLite 3.45.1 / FTS5. CI matrix advertises
3 OS × {3.10, 3.12, 3.13} but installs **editable only** and never the wheel (#49).
Windows/macOS behavior of the fixes (symlink semantics, FIFO) needs matrix coverage.
