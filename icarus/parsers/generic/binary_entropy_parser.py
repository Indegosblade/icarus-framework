"""Generic binary parser — catalogs unrecognized files by metadata (size, hash, extension)."""

import os
from pathlib import Path
from typing import Any, Dict

from icarus.core.schema import open_db
from icarus.parsers.base import BATCH_COMMIT_INTERVAL, BaseParser

KNOWN_EXTENSIONS = frozenset({
    ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".conf", ".cfg",
    ".py", ".js", ".ts", ".java", ".c", ".h", ".cpp", ".rs", ".go",
    ".md", ".txt", ".rst", ".html", ".css", ".csv",
    ".db", ".sqlite", ".sqlite3",
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".exe", ".dll", ".sys", ".so", ".dylib",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
})


class BinaryEntropyParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/binary"

    @property
    def description(self) -> str:
        return "Generic binary/unknown — catalogs files by metadata (size, hash, extension)"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            if filenames:
                return True
        return False

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    path = Path(dirpath) / fname
                    try:
                        st = path.stat()
                        ext = path.suffix.lower()
                        rel = self._rel_path(path, source)
                        file_type = "unknown"
                        if ext in KNOWN_EXTENSIONS:
                            file_type = ext.lstrip(".")
                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type) VALUES (?,?,?,?,?,?)",
                            (rel, path.name, ext or None, st.st_size,
                             self._safe_hash(path, st.st_size), file_type),
                        )
                        stats["files"] += 1
                    except (PermissionError, OSError):
                        continue
                    if stats["files"] % BATCH_COMMIT_INTERVAL == 0:
                        conn.commit()
            conn.commit()
        finally:
            conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        return {"linked": 0}
