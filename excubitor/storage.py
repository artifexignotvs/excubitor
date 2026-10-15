"""Indicia localia servantur; secreta non petuntur."""
from __future__ import annotations
from dataclasses import asdict
from pathlib import Path
import csv
import io
import json
import math
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
        cursor = self.db.execute("UPDATE alerts SET acknowledged=? WHERE id=?", (int(value), identifier))
        if not cursor.rowcount:
            raise ValueError("Alert identifier was not found")
        self.db.commit()

    def list(self, limit: int = 1000, rule: str | None = None, *, source=None, destination=None,
             severity=None, since=None, until=None, unacknowledged=False) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100000:
            raise ValueError("History limit must be between 1 and 100000")
        clauses, parameters = [], []
        for name, value in (("rule", rule), ("severity", severity)):
            if value is not None:
                clauses.append(name + "=?")
                parameters.append(value)
        for operator, value in ((">=", since), ("<=", until)):
            if value is not None:
                if type(value) not in (int, float) or not 0 <= value <= 253402214400 or not math.isfinite(value):
                    raise ValueError("History timestamps must be finite and nonnegative")
                clauses.append("ts" + operator + "?")
                parameters.append(value)
        if since is not None and until is not None and since > until:
            raise ValueError("History since must not be after until")
        if unacknowledged:
            clauses.append("acknowledged=0")
        # Valores externi semper ut parametri ligantur.
        for field, value in (("src", source), ("dst", destination)):
            if value is not None:
                clauses.append("json_extract(payload, '$." + field + "')=?")
                parameters.append(value)
        query = "SELECT payload,acknowledged FROM alerts"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY ts DESC,id LIMIT ?"
        rows = self.db.execute(query, [*parameters, limit])
        result = []
        for payload, acknowledged in rows:
            item = json.loads(payload)
            item["acknowledged"] = bool(acknowledged)
            result.append(item)
        return result

    def close(self) -> None:
        self.db.close()
