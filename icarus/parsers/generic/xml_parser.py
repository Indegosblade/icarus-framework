"""Generic XML parser — extracts file entities from directories containing .xml files."""

import os
import sqlite3
from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BaseParser


class XmlParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/xml"

    @property
    def description(self) -> str:
        return "Generic XML file directory — catalogs .xml files"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for f in filenames:
                if f.lower().endswith(".xml"):
                    return True
        return False

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = sqlite3.connect(str(db_path))
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    if not fname.lower().endswith(".xml"):
                        continue
                    path = Path(dirpath) / fname
                    try:
                        st = path.stat()
                        rel = self._rel_path(path, source)
                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type) VALUES (?,?,?,?,?,?)",
                            (rel, path.name, ".xml", st.st_size,
                             self._safe_hash(path, st.st_size), "xml"),
                        )
                        stats["files"] += 1
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
