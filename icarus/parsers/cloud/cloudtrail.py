"""AWS CloudTrail parser — maps IAM identities to daemons, API events to observations."""

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict

from icarus.parsers.base import BaseParser


class CloudTrailParser(BaseParser):
    @property
    def name(self) -> str:
        return "cloud/aws/cloudtrail"

    @property
    def description(self) -> str:
        return "AWS CloudTrail JSON audit log parser"

    def identify(self, source: Path) -> bool:
        if not source.is_dir():
            return False
        for dirpath, _, filenames in os.walk(source, onerror=lambda e: None):
            for fname in filenames:
                if not fname.lower().endswith(".json"):
                    continue
                path = Path(dirpath) / fname
                try:
                    data = json.loads(path.read_text(errors="replace"))
                    if isinstance(data, dict) and "Records" in data:
                        records = data["Records"]
                        if (isinstance(records, list) and len(records) > 0
                                and "eventVersion" in records[0]
                                and "eventSource" in records[0]):
                            return True
                except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                    continue
        return False

    def extract_entities(
        self, source: Path, db_path: Path
    ) -> Dict[str, Any]:
        conn = sqlite3.connect(str(db_path))
        stats = {"files": 0, "daemons": 0, "observations": 0}
        try:
            for dirpath, _, filenames in os.walk(
                source, onerror=lambda e: None
            ):
                for fname in filenames:
                    if not fname.lower().endswith(".json"):
                        continue
                    path = Path(dirpath) / fname
                    try:
                        data = json.loads(
                            path.read_text(errors="replace")
                        )
                    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                        continue

                    if not isinstance(data, dict) or "Records" not in data:
                        continue

                    rel = self._rel_path(path, source)
                    st = path.stat()
                    conn.execute(
                        "INSERT OR IGNORE INTO files "
                        "(path,filename,extension,size,sha256,"
                        "file_type) VALUES (?,?,?,?,?,?)",
                        (rel, path.name, ".json", st.st_size,
                         self._safe_hash(path, st.st_size),
                         "cloudtrail_log"),
                    )
                    stats["files"] += 1

                    for record in data["Records"]:
                        if not isinstance(record, dict):
                            continue

                        identity = record.get("userIdentity", {})
                        arn = identity.get("arn", "")
                        if not arn:
                            continue

                        conn.execute(
                            "INSERT OR IGNORE INTO daemons "
                            "(label,plist_path,program,user_name)"
                            " VALUES (?,?,?,?)",
                            (arn, rel,
                             identity.get("type", ""),
                             identity.get("accountId", "")),
                        )
                        stats["daemons"] += 1

                        daemon_row = conn.execute(
                            "SELECT id FROM daemons WHERE label=?",
                            (arn,),
                        ).fetchone()
                        if not daemon_row:
                            continue

                        event_time = record.get("eventTime", "")
                        event_name = record.get("eventName", "")
                        event_source = record.get("eventSource", "")

                        props = {}
                        for key in ("sourceIPAddress", "awsRegion",
                                    "errorCode", "errorMessage"):
                            val = record.get(key)
                            if val:
                                props[key] = val
                        req = record.get("requestParameters")
                        if isinstance(req, dict):
                            props["requestParameters"] = req
                        resp = record.get("responseElements")
                        if isinstance(resp, dict):
                            props["responseElements"] = resp

                        existing = conn.execute(
                            "SELECT id FROM observations "
                            "WHERE entity_table=? AND entity_id=? "
                            "AND observed_at=? AND event_type=?",
                            ("daemons", daemon_row[0],
                             event_time, event_name),
                        ).fetchone()
                        if not existing:
                            conn.execute(
                                "INSERT INTO observations "
                                "(entity_table,entity_id,observed_at,"
                                "event_type,observer,properties,"
                                "confidence) "
                                "VALUES (?,?,?,?,?,?,?)",
                                ("daemons", daemon_row[0], event_time,
                                 event_name, event_source,
                                 json.dumps(props) if props else None,
                                 0.90),
                            )
                        stats["observations"] += 1
            conn.commit()
        finally:
            conn.close()
        return stats

    def extract_relationships(
        self, source: Path, db_path: Path
    ) -> Dict[str, Any]:
        return {"linked": 0}
