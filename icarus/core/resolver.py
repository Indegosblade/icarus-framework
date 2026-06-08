"""
ICARUS Entity Resolver — Atom/Bag/EventLog pattern for cross-source identity.

Entities from different sources may refer to the same real-world thing under
different identifiers. The resolver tracks immutable atoms (raw observations),
groups them into bags (resolved entities), and logs every resolution decision
in an append-only event log.
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


class BlockingIndex:
    """FTS5-backed blocking index for entity resolution candidate generation."""

    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)

    def index_atom(
        self, atom_id: int, entity_type: str, source_key: str, properties: dict
    ) -> None:
        """Manually add an atom to the FTS index (if triggers missed it)."""
        self.conn.execute(
            "INSERT OR REPLACE INTO atoms_fts(rowid, entity_type, source_key, properties) "
            "VALUES (?, ?, ?, ?)",
            (atom_id, entity_type, source_key, json.dumps(properties)),
        )
        self.conn.commit()

    def candidates_for(self, atom_id: int, limit: int = 100) -> List[Tuple[int, float]]:
        """Return (atom_id, score) pairs of potential matches. Never returns self."""
        row = self.conn.execute(
            "SELECT entity_type, source_key, properties FROM atoms WHERE id = ?",
            (atom_id,),
        ).fetchone()
        if not row:
            return []

        entity_type, source_key, properties = row
        tokens = self._extract_tokens(entity_type, source_key, properties)
        if not tokens:
            return []

        match_expr = " OR ".join(tokens)
        rows = self.conn.execute(
            "SELECT rowid, rank FROM atoms_fts WHERE atoms_fts MATCH ? "
            "ORDER BY rank LIMIT ?",
            (match_expr, limit + 1),
        ).fetchall()

        return [(r[0], -r[1]) for r in rows if r[0] != atom_id][:limit]

    def rebuild(self) -> int:
        """Rebuild the full blocking index from atoms table. Returns atom count."""
        self.conn.execute("INSERT INTO atoms_fts(atoms_fts) VALUES ('rebuild')")
        self.conn.commit()
        count = self.conn.execute("SELECT COUNT(*) FROM atoms").fetchone()[0]
        return count

    def _extract_tokens(self, entity_type: str, source_key: str, properties: str) -> List[str]:
        """Extract searchable tokens from atom data."""
        tokens = []
        for val in [source_key]:
            for word in val.split():
                cleaned = "".join(c for c in word if c.isalnum())
                if cleaned and len(cleaned) > 1:
                    tokens.append(cleaned)
        try:
            props = json.loads(properties) if isinstance(properties, str) else properties
            for v in props.values():
                if isinstance(v, str):
                    for word in v.split():
                        cleaned = "".join(c for c in word if c.isalnum())
                        if cleaned and len(cleaned) > 1:
                            tokens.append(cleaned)
        except (json.JSONDecodeError, AttributeError):
            pass
        return tokens[:10]

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class EntityResolver:
    """Resolve entities across sources using the Atom/Bag/EventLog pattern."""

    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("PRAGMA foreign_keys = ON")

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
        return cursor.lastrowid

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
        self, entity_type: str, blocking_keys: List[str], threshold: float = 0.8
    ) -> Dict[str, Any]:
        """Run full resolution: block -> score -> cluster -> merge. Returns stats."""
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
        confidence: float = None, operator: str = "auto",
    ) -> None:
        """Append to resolution_event_log. Never update or delete."""
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            "INSERT INTO resolution_event_log "
            "(event_type, bag_id, atom_ids, reason, confidence, operator, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event_type, bag_id, json.dumps(atom_ids), reason, confidence, operator, now),
        )

    def close(self):
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
