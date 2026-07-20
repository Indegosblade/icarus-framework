"""Generic archive parser — catalogs .zip/.tar/.gz files and their contents."""

import gzip
import io
import itertools
import os
import tarfile
import warnings
import zipfile
from pathlib import Path
from typing import Any, Dict

from icarus.core.schema import open_db
from icarus.parsers.base import BaseParser

# Listing a compressed tar requires inflating bytes to advance through member
# payloads. Stop after a bounded amount instead of turning cataloging into an
# unbounded decompression operation.
MAX_DECOMPRESSED_TAR_BYTES = 64 * 1024 * 1024


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
                        st, kind = self._file_kind(path)
                        if st is None or kind in ("special", "unreadable"):
                            continue
                        rel = self._rel_path(path, source)
                        is_link = kind == "symlink"
                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path,filename,extension,size,sha256,file_type,"
                            "is_symlink,symlink_target) VALUES (?,?,?,?,?,?,?,?)",
                            (
                                rel, self._safe_text(path.name), path.suffix.lower(),
                                st.st_size, self._safe_hash(path, st.st_size),
                                "symlink" if is_link else "archive",
                                int(is_link), self._symlink_target(path),
                            ),
                        )
                        stats["files"] += 1

                        file_row = conn.execute(
                            "SELECT id FROM files WHERE path=?", (rel,)
                        ).fetchone()
                        if file_row and not is_link:
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
    """List up to ``limit`` members within bounded work/memory.

    Plain tar members are iterated lazily; compressed tar data is capped before
    parsing; and the already-read ZIP central directory is sliced without a
    second full name list.
    """
    try:
        _, kind = BaseParser._file_kind(path)
        if kind != "regular":
            return []
        if path.suffix.lower() == ".zip":
            with BaseParser._open_regular(path) as source:
                with zipfile.ZipFile(source) as zf:
                    return [
                        BaseParser._safe_text(info.filename)
                        for info in itertools.islice(zf.filelist, limit)
                    ]
        elif path.suffix.lower() == ".tar":
            names = []
            with BaseParser._open_regular(path) as source:
                with tarfile.open(fileobj=source, mode="r:") as tf:
                    for member in tf:  # lazy — does not scan the whole archive
                        names.append(BaseParser._safe_text(member.name))
                        if len(names) >= limit:
                            break
            return names
        elif path.suffix.lower() == ".tgz" or path.name.lower().endswith(".tar.gz"):
            with BaseParser._open_regular(path) as source:
                with gzip.GzipFile(fileobj=source) as compressed:
                    data = compressed.read(MAX_DECOMPRESSED_TAR_BYTES + 1)
            if len(data) > MAX_DECOMPRESSED_TAR_BYTES:
                warnings.warn(
                    "Skipping compressed tar whose decompressed data exceeds "
                    f"{MAX_DECOMPRESSED_TAR_BYTES} bytes: "
                    f"{BaseParser._safe_text(str(path))}",
                    RuntimeWarning,
                    stacklevel=2,
                )
                return []
            names = []
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
                for member in tf:
                    names.append(BaseParser._safe_text(member.name))
                    if len(names) >= limit:
                        break
            return names
    except (
        zipfile.BadZipFile,
        tarfile.TarError,
        gzip.BadGzipFile,
        OSError,
        EOFError,
        MemoryError,
    ):
        pass
    return []
