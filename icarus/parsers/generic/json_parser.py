"""Generic JSON parser — extracts file entities from directories containing .json files."""

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BaseParser


class JsonParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/json"

    @property
    def description(self) -> str:
        return "Generic JSON file directory — catalogs .json files and top-level keys"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for f in filenames:
                if f.lower().endswith(".json"):
                    return True
        return False

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = sqlite3.connect(str(db_path))
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    path = Path(dirpath) / fname
                    if not fname.lower().endswith(".json"):
                        continue
                    try:
                        st = path.stat()
                        rel = self._rel_path(path, source)
                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type) VALUES (?,?,?,?,?,?)",
                            (rel, path.name, ".json", st.st_size,
                             self._safe_hash(path, st.st_size), "json"),
                        )
                        stats["files"] += 1

                        try:
                            data = json.loads(path.read_text(errors="replace"))
                            if isinstance(data, dict):
                                keys = ", ".join(sorted(data.keys())[:20])
                                file_row = conn.execute(
                                    "SELECT id FROM files WHERE path=?", (rel,)
                                ).fetchone()
                                if file_row:
                                    conn.execute(
                                        "INSERT OR IGNORE INTO observations"
                                        " (entity_table,entity_id,"
                                        "observed_at,event_type,properties)"
                                        " VALUES (?,?,datetime('now'),?,?)",
                                        ("files", file_row[0], "json_keys",
                                         keys),
                                    )
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            pass
                    except (PermissionError, OSError):
                        continue
                    if stats["files"] % 1000 == 0:
                        conn.commit()
            conn.commit()
        finally:
            conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        return {"linked": 0}
