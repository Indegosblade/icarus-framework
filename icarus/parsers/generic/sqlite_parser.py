"""Generic SQLite parser — catalogs .db/.sqlite files and their table schemas."""

import os
import sqlite3
from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BaseParser


class SqliteParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/sqlite"

    @property
    def description(self) -> str:
        return "Generic SQLite database directory — catalogs .db/.sqlite files and schemas"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for f in filenames:
                if f.lower().endswith((".db", ".sqlite", ".sqlite3")):
                    return True
        return False

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = sqlite3.connect(str(db_path))
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    if not fname.lower().endswith((".db", ".sqlite", ".sqlite3")):
                        continue
                    path = Path(dirpath) / fname
                    try:
                        st = path.stat()
                        rel = self._rel_path(path, source)
                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type) VALUES (?,?,?,?,?,?)",
                            (rel, path.name, path.suffix.lower(), st.st_size,
                             self._safe_hash(path, st.st_size), "database"),
                        )
                        stats["files"] += 1

                        file_row = conn.execute(
                            "SELECT id FROM files WHERE path=?", (rel,)
                        ).fetchone()
                        if file_row:
                            try:
                                src_conn = sqlite3.connect(str(path))
                                tables = src_conn.execute(
                                    "SELECT name FROM sqlite_master WHERE type='table' "
                                    "AND name NOT LIKE 'sqlite_%'"
                                ).fetchall()
                                schema_info = ", ".join(t[0] for t in tables[:30])
                                src_conn.close()
                                dup = conn.execute(
                                    "SELECT id FROM observations "
                                    "WHERE entity_table=? AND entity_id=? "
                                    "AND event_type=?",
                                    ("files", file_row[0], "schema_tables"),
                                ).fetchone()
                                if not dup:
                                    conn.execute(
                                        "INSERT INTO observations "
                                        "(entity_table,entity_id,"
                                        "observed_at,event_type,"
                                        "properties) "
                                        "VALUES "
                                        "(?,?,datetime('now'),?,?)",
                                        ("files", file_row[0],
                                         "schema_tables", schema_info),
                                    )
                            except sqlite3.DatabaseError:
                                pass
                    except (PermissionError, OSError):
                        continue
                    if stats["files"] % 50000 == 0:
                        conn.commit()
            conn.commit()
        finally:
            conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        return {"linked": 0}
