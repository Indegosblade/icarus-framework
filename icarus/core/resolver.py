"""
ICARUS Entity Resolver — Atom/Bag/EventLog pattern for cross-source identity.

EXPERIMENTAL / UNWIRED: this subsystem is fully built but is intentionally NOT
part of ``create_default_pipeline`` — no ``resolve`` phase runs during a normal
``icarus build``. It is exposed only as an explicitly-experimental entry point:
construct ``EntityResolver(db_path, experimental=True)`` to acknowledge that the
API and resolution behavior are unstable and may change.

Entities from different sources may refer to the same real-world thing under
different identifiers. The resolver tracks immutable atoms (raw observations),
groups them into bags (resolved entities), and logs every resolution decision
in an append-only event log. Blocking is exact-key only (see ``resolve``).
"""

import json
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from icarus.core.schema import open_db

# Explicit experimental flag for the atom/bag/resolver subsystem: it is not
# wired into the default pipeline and its API/behavior are unstable.
__experimental__ = True


class EntityResolver:
    """Resolve entities across sources using the Atom/Bag/EventLog pattern.

    EXPERIMENTAL: not wired into ``create_default_pipeline``. Pass
    ``experimental=True`` to acknowledge the unstable API; omitting it emits a
    warning rather than failing, so existing callers keep working.
    """

    def __init__(self, db_path: str, *, experimental: bool = False):
        if not experimental:
            warnings.warn(
                "EntityResolver is an experimental, unwired subsystem "
                "(not part of create_default_pipeline); pass experimental=True "
                "to acknowledge its unstable API.",
                stacklevel=2,
            )
        self.experimental = experimental
        # open_db (audit #63/#68) enforces PRAGMA foreign_keys = ON and applies
        # the RAM-scaled cache/mmap pragmas on this working connection, instead
        # of a bare sqlite3.connect that silently left REFERENCES unenforced.
        self.conn = open_db(db_path)

    def ingest_atom(
        self, version_id: int, entity_type: str, source_key: str, properties: dict
    ) -> int:
        """Create an immutable atom. Returns atom_id."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.execute(
            "INSERT INTO atoms (source_version_id, entity_type, source_key, "
            "properties, created_at) VALUES (?, ?, ?, ?, ?)",
            (version_id, entity_type, source_key, json.dumps(properties), now),
        )
        self.conn.commit()
        atom_id = cursor.lastrowid
        assert atom_id is not None
        return atom_id

    def create_bag(
        self, entity_type: str, atom_ids: List[int], canonical_key: Optional[str] = None
    ) -> int:
        """Create a bag grouping one or more atoms. Returns bag_id."""
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.conn.execute(
            "INSERT INTO bags (entity_type, canonical_key, created_at, atom_count) "
            "VALUES (?, ?, ?, ?)",
            (entity_type, canonical_key, now, len(atom_ids)),
        )
        bag_id = cursor.lastrowid
        assert bag_id is not None

        for atom_id in atom_ids:
            self.conn.execute(
                "INSERT INTO bag_atoms (bag_id, atom_id) VALUES (?, ?)",
                (bag_id, atom_id),
            )

        self._log_event("create", bag_id, atom_ids, "initial bag creation")
        self.conn.commit()
        return bag_id

    def merge_bags(self, bag_ids: List[int], reason: str = "") -> int:
        """Merge multiple bags into one. Logs BEFORE modifying. Returns surviving bag_id."""
        if len(bag_ids) < 2:
            raise ValueError("merge_bags requires at least 2 bag IDs")

        surviving_id = bag_ids[0]

        all_atom_ids = []
        for bag_id in bag_ids:
            rows = self.conn.execute(
                "SELECT atom_id FROM bag_atoms WHERE bag_id = ?", (bag_id,)
            ).fetchall()
            all_atom_ids.extend(r[0] for r in rows)

        self._log_event("merge", surviving_id, all_atom_ids, reason)

        for bag_id in bag_ids[1:]:
            self.conn.execute(
                "UPDATE bag_atoms SET bag_id = ? WHERE bag_id = ?",
                (surviving_id, bag_id),
            )
            self.conn.execute(
                "UPDATE resolution_event_log SET bag_id = ? WHERE bag_id = ?",
                (surviving_id, bag_id),
            )
            self.conn.execute("DELETE FROM bags WHERE id = ?", (bag_id,))

        total = self.conn.execute(
            "SELECT COUNT(*) FROM bag_atoms WHERE bag_id = ?", (surviving_id,)
        ).fetchone()[0]
        self.conn.execute(
            "UPDATE bags SET atom_count = ?, resolved_at = ? WHERE id = ?",
            (total, datetime.now(timezone.utc).isoformat(), surviving_id),
        )

        self.conn.commit()
        return surviving_id

    def split_bag(self, bag_id: int, atom_ids_to_remove: List[int], reason: str = "") -> int:
        """Remove atoms from a bag into a new bag. Does NOT delete original. Returns new bag_id."""
        now = datetime.now(timezone.utc).isoformat()

        self._log_event("split", bag_id, atom_ids_to_remove, reason)

        entity_type = self.conn.execute(
            "SELECT entity_type FROM bags WHERE id = ?", (bag_id,)
        ).fetchone()[0]

        cursor = self.conn.execute(
            "INSERT INTO bags (entity_type, created_at, atom_count) VALUES (?, ?, ?)",
            (entity_type, now, len(atom_ids_to_remove)),
        )
        new_bag_id = cursor.lastrowid
        assert new_bag_id is not None

        for atom_id in atom_ids_to_remove:
            self.conn.execute(
                "UPDATE bag_atoms SET bag_id = ? WHERE bag_id = ? AND atom_id = ?",
                (new_bag_id, bag_id, atom_id),
            )

        remaining = self.conn.execute(
            "SELECT COUNT(*) FROM bag_atoms WHERE bag_id = ?", (bag_id,)
        ).fetchone()[0]
        self.conn.execute(
            "UPDATE bags SET atom_count = ?, resolved_at = ? WHERE id = ?",
            (remaining, now, bag_id),
        )

        self.conn.commit()
        return new_bag_id

    def resolve(
        self, entity_type: str, blocking_keys: List[str]
    ) -> Dict[str, Any]:
        """Group unresolved atoms by EXACT blocking key and bag each group.

        Exact-key-blocking MVP: for each unresolved atom of ``entity_type`` a
        cluster key is built by joining the lowercased, stripped values of
        ``blocking_keys`` found in its properties. Atoms sharing a cluster key
        go into one bag (its ``canonical_key`` is that cluster key); an atom
        with a unique key gets a singleton bag. Atoms with no value for any
        blocking key are left unresolved. There is no similarity scoring and no
        FTS-based candidate blocking.

        Returns ``{"merges": N, "atoms_resolved": M}`` where ``merges`` counts
        the multi-atom bags created and ``atoms_resolved`` counts atoms placed
        into any bag.
        """
        unresolved = self.unresolved_atoms(entity_type)
        if not unresolved:
            return {"merges": 0, "atoms_resolved": 0}

        clusters: Dict[str, List[int]] = {}
        for atom_id in unresolved:
            row = self.conn.execute(
                "SELECT properties FROM atoms WHERE id = ?", (atom_id,)
            ).fetchone()
            if not row:
                continue
            props = json.loads(row[0])
            key_parts = []
            for bk in blocking_keys:
                val = props.get(bk, "")
                if val:
                    key_parts.append(str(val).lower().strip())
            if key_parts:
                cluster_key = "|".join(key_parts)
                clusters.setdefault(cluster_key, []).append(atom_id)

        merges = 0
        atoms_resolved = 0
        for cluster_key, atom_ids in clusters.items():
            if len(atom_ids) >= 2:
                self.create_bag(entity_type, atom_ids, canonical_key=cluster_key)
                merges += 1
                atoms_resolved += len(atom_ids)
            else:
                self.create_bag(entity_type, atom_ids)
                atoms_resolved += 1

        return {"merges": merges, "atoms_resolved": atoms_resolved}

    def unresolved_atoms(self, entity_type: str) -> List[int]:
        """Atoms not assigned to any bag."""
        rows = self.conn.execute(
            "SELECT a.id FROM atoms a "
            "LEFT JOIN bag_atoms ba ON a.id = ba.atom_id "
            "WHERE a.entity_type = ? AND ba.bag_id IS NULL",
            (entity_type,),
        ).fetchall()
        return [r[0] for r in rows]

    def _log_event(
        self, event_type: str, bag_id: int, atom_ids: List[int], reason: str = "",
        confidence: Optional[float] = None, operator: str = "auto",
    ) -> None:
        """Append to resolution_event_log. Never update or delete."""
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO resolution_event_log "
            "(event_type, bag_id, atom_ids, reason, confidence, operator, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event_type, bag_id, json.dumps(atom_ids), reason, confidence, operator, now),
        )

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
