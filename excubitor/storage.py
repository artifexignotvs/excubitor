"""Indicia localia servantur; secreta non petuntur."""
from __future__ import annotations
from dataclasses import asdict
from pathlib import Path
import csv
import io
import json
import os
import sqlite3
from .model import Alert, iso_time


def exclusive_write(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
        stream.write(text)


def serialize(alerts: list[dict], format: str = "json") -> str:
    if format == "json":
        return json.dumps({"schema": "excubitor.alerts.v1", "alerts": alerts}, indent=2, ensure_ascii=True) + "\n"
    if format == "jsonl":
        return "".join(json.dumps(a, ensure_ascii=True, sort_keys=True) + "\n" for a in alerts)
    if format == "csv":
        out = io.StringIO(newline="")
        fields = ["id", "rule", "severity", "ts", "src", "dst", "count", "summary", "acknowledged"]
        writer = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for alert in alerts:
            row = {key: alert.get(key, "") for key in fields}
            # Formulae alienae in tabulis non exsequendae sunt.
            row = {k: ("'" + str(v) if str(v).lstrip().startswith(("=", "+", "-", "@")) else v) for k, v in row.items()}
            writer.writerow(row)
        return out.getvalue()
    raise ValueError("Unknown export format")


class Store:
    def __init__(self, path: str):
        target = Path(path)
        if target.is_symlink():
            raise ValueError("Database path cannot be a symbolic link")
        if not target.exists():
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, ts REAL NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS alerts_time ON alerts(ts)")
        self.db.commit()

    def add(self, alert: Alert) -> None:
        self.db.execute("INSERT OR IGNORE INTO alerts(id,ts,rule,severity,payload) VALUES(?,?,?,?,?)",
                        (alert.id, alert.ts, alert.rule, alert.severity, json.dumps(asdict(alert), ensure_ascii=True)))
        self.db.commit()

    def acknowledge(self, identifier: str, value: bool = True) -> None:
        self.db.execute("UPDATE alerts SET acknowledged=? WHERE id=?", (int(value), identifier))
        self.db.commit()

    def list(self, limit: int = 1000, rule: str | None = None) -> list[dict]:
        if not 1 <= limit <= 100000:
            raise ValueError("History limit must be between 1 and 100000")
        if rule:
            rows = self.db.execute("SELECT payload,acknowledged FROM alerts WHERE rule=? ORDER BY ts DESC,id LIMIT ?", (rule, limit))
        else:
            rows = self.db.execute("SELECT payload,acknowledged FROM alerts ORDER BY ts DESC,id LIMIT ?", (limit,))
        result = []
        for payload, acknowledged in rows:
            item = json.loads(payload)
            item["acknowledged"] = bool(acknowledged)
            result.append(item)
        return result

    def close(self) -> None:
        self.db.close()
