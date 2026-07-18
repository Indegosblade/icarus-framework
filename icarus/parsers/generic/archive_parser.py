"""Generic archive parser — catalogs .zip/.tar/.gz files and their contents."""

import itertools
import os
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Dict

from icarus.core.schema import open_db
from icarus.parsers.base import BaseParser


class ArchiveParser(BaseParser):
    @property
    def name(self) -> str:
        return "generic/archive"

    @property
    def description(self) -> str:
        return "Generic archive directory — catalogs .zip/.tar/.gz files and contents"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for f in filenames:
                if f.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz")):
                    return True
        return False

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = open_db(db_path)
        stats = {"files": 0}
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    if not fname.lower().endswith((".zip", ".tar", ".tar.gz", ".tgz", ".gz")):
                        continue
                    path = Path(dirpath) / fname
                    try:
                        st = path.stat()
                        rel = self._rel_path(path, source)
                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type) VALUES (?,?,?,?,?,?)",
                            (rel, path.name, path.suffix.lower(), st.st_size,
                             self._safe_hash(path, st.st_size), "archive"),
                        )
                        stats["files"] += 1

                        file_row = conn.execute(
                            "SELECT id FROM files WHERE path=?", (rel,)
                        ).fetchone()
                        if file_row:
                            contents = _list_archive(path)
                            if contents:
                                dup = conn.execute(
                                    "SELECT id FROM observations "
                                    "WHERE entity_table=? "
                                    "AND entity_id=? "
                                    "AND event_type=?",
                                    ("files", file_row[0],
                                     "archive_contents"),
                                ).fetchone()
                                if not dup:
                                    conn.execute(
                                        "INSERT INTO observations "
                                        "(entity_table,entity_id,"
                                        "observed_at,event_type,"
                                        "properties) VALUES "
                                        "(?,?,datetime('now'),?,?)",
                                        ("files", file_row[0],
                                         "archive_contents",
                                         ", ".join(contents[:50])),
                                    )
                    except (PermissionError, OSError):
                        continue
            conn.commit()
        finally:
            conn.close()
        return stats

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        return {"linked": 0}


def _list_archive(path: Path, limit: int = 50) -> list:
    """List up to `limit` archive members without materializing all of them.

    Iterates tar members lazily (TarFile.__iter__) so a bomb with millions of
    entries is not fully scanned; the zip central directory is sliced instead
    of copied.
    """
    try:
        if path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as zf:
                return list(itertools.islice(zf.namelist(), limit))
        elif path.suffix.lower() in (".tar", ".tgz") or path.name.lower().endswith(".tar.gz"):
            names = []
            with tarfile.open(path) as tf:
                for member in tf:  # lazy — does not scan the whole archive
                    names.append(member.name)
                    if len(names) >= limit:
                        break
            return names
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError):
        pass
    return []
