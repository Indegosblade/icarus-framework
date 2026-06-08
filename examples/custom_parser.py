"""
Example: Minimal custom parser for ICARUS.

Shows the BaseParser interface with a simple filesystem-only parser.
No binary detection — just catalogs every file in the source directory.
Copy this as a starting point for your own parser.
"""

import os
import sqlite3
from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BaseParser


class SimpleParser(BaseParser):
    """Minimal parser — catalogs files only, no binary analysis."""

    @property
    def name(self) -> str:
        return "simple"

    @property
    def description(self) -> str:
        return "Simple filesystem catalog (files only)"

    def identify(self, source: Path) -> bool:
        return source.is_dir()

    def extract_entities(self, source: Path, db_path: Path) -> Dict[str, Any]:
        conn = sqlite3.connect(str(db_path))
        count = 0
        try:
            for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
                for fname in filenames:
                    path = Path(dirpath) / fname
                    try:
                        st = path.stat()
                        conn.execute(
                            "INSERT OR IGNORE INTO files "
                            "(path, filename, extension, size, sha256, file_type) "
                            "VALUES (?, ?, ?, ?, ?, ?)",
                            (self._rel_path(path, source), path.name,
                             path.suffix.lower() or None, st.st_size,
                             self._safe_hash(path, st.st_size), "other"),
                        )
                        count += 1
                    except (PermissionError, OSError):
                        continue
                    if count % 5000 == 0:
                        conn.commit()
            conn.commit()
        finally:
            conn.close()
        return {"files": count}

    def extract_relationships(self, source: Path, db_path: Path) -> Dict[str, Any]:
        return {"linked": 0}


# To register, add to icarus/parsers/__init__.py:
#   from examples.custom_parser import SimpleParser
#   PARSERS["simple"] = SimpleParser
