"""AWS CloudTrail parser — maps IAM identities to daemons, API events to observations."""

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict

from icarus.core.schema import open_db
from icarus.parsers.base import BaseParser

# CloudTrail exports can be very large; do not read a single file bigger than
# this fully into memory.
_MAX_JSON_BYTES = 200_000_000


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
        conn = open_db(db_path)
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
                        st = path.stat()
                    except OSError:
                        continue
                    if not 0 < st.st_size <= _MAX_JSON_BYTES:
                        continue
                    try:
                        data = json.loads(
                            path.read_text(errors="replace")
                        )
                    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
                        continue

                    records = data.get("Records") if isinstance(data, dict) else None
                    if not isinstance(records, list):
                        continue

                    rel = self._rel_path(path, source)
                    conn.execute(
                        "INSERT OR IGNORE INTO files "
                        "(path,filename,extension,size,sha256,"
                        "file_type) VALUES (?,?,?,?,?,?)",
                        (rel, path.name, ".json", st.st_size,
                         self._safe_hash(path, st.st_size),
                         "cloudtrail_log"),
                    )
                    stats["files"] += 1

                    for record in records:
                        try:
                            self._ingest_record(conn, record, rel, stats)
                        except (sqlite3.Error, TypeError, ValueError):
                            # One malformed record must not abort the build.
                            continue
            conn.commit()
        finally:
            conn.close()
        return stats

    def _ingest_record(self, conn, record, rel, stats) -> None:
        """Ingest one CloudTrail record. May raise on malformed data — the
        caller skips just that record rather than aborting the whole build."""
        if not isinstance(record, dict):
            return
        identity = record.get("userIdentity") or {}
        if not isinstance(identity, dict):
            return
        arn = identity.get("arn") or ""
        if not arn:
            return

        cur = conn.execute(
            "INSERT OR IGNORE INTO daemons "
            "(label,plist_path,program,user_name) VALUES (?,?,?,?)",
            (arn, rel, identity.get("type", ""), identity.get("accountId", "")),
        )
        if cur.rowcount:
            stats["daemons"] += 1

        daemon_row = conn.execute(
            "SELECT id FROM daemons WHERE label=?", (arn,)
        ).fetchone()
        if not daemon_row:
            return

        event_time = record.get("eventTime", "")
        event_name = record.get("eventName", "")
        event_source = record.get("eventSource", "")
        event_id = record.get("eventID", "")

        props = {}
        if event_id:
            props["eventID"] = event_id
        for key in ("sourceIPAddress", "awsRegion", "errorCode", "errorMessage"):
            val = record.get(key)
            if val:
                props[key] = val
        req = record.get("requestParameters")
        if isinstance(req, dict):
            props["requestParameters"] = req
        resp = record.get("responseElements")
        if isinstance(resp, dict):
            props["responseElements"] = resp

        # Dedup key must include eventID: eventTime has only one-second
        # granularity, and eventName repeats across calls, so two genuinely
        # distinct CloudTrail events for the same identity in the same
        # second would otherwise collapse into a single stored observation.
        # eventID is unique per CloudTrail event, so it is compared against
        # any prior observation's stored properties (there is no dedicated
        # column for it) rather than added to the SQL WHERE clause.
        candidates = conn.execute(
            "SELECT properties FROM observations "
            "WHERE entity_table=? AND entity_id=? AND observed_at=? AND event_type=?",
            ("daemons", daemon_row[0], event_time, event_name),
        ).fetchall()
        duplicate = False
        for (existing_props,) in candidates:
            existing_event_id = ""
            if existing_props:
                try:
                    existing_event_id = json.loads(existing_props).get("eventID", "")
                except (json.JSONDecodeError, AttributeError):
                    existing_event_id = ""
            if existing_event_id == event_id:
                duplicate = True
                break

        if not duplicate:
            conn.execute(
                "INSERT INTO observations "
                "(entity_table,entity_id,observed_at,event_type,observer,"
                "properties,confidence) VALUES (?,?,?,?,?,?,?)",
                ("daemons", daemon_row[0], event_time, event_name, event_source,
                 json.dumps(props) if props else None, 0.90),
            )
            stats["observations"] += 1

    def extract_relationships(
        self, source: Path, db_path: Path
    ) -> Dict[str, Any]:
        return {"linked": 0}
