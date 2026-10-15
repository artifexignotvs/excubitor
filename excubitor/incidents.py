"""Indicia tempore coniunguntur; causa non praesumitur."""
from __future__ import annotations
import hashlib
import html
import ipaddress
import json
import math
import re
from pathlib import Path
from .model import iso_time

MAX_BYTES = 16 * 1024 * 1024
MAX_ALERTS = 10000
LEVELS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
NOTICE = "Time proximity and shared endpoints are investigation leads, not proof of causality or compromise. Alert counts may overlap; they are not unique event counts."


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _finite(value, name):
    if type(value) not in (float, int) or not 0 <= value <= 253402214400 or not math.isfinite(value):
        raise ValueError(f"Invalid {name}")
    return value


def _bounded(value, depth=0):
    if depth > 16:
        raise ValueError("Alert evidence is too deeply nested")
    if isinstance(value, dict):
        if len(value) > 2048:
            raise ValueError("Too many evidence fields")
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Evidence field names must be text")
            _bounded(key, depth + 1)
            _bounded(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 2048:
            raise ValueError("Too many evidence values")
        for item in value:
            _bounded(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 8192 or any(0xD800 <= ord(char) <= 0xDFFF for char in value):
            raise ValueError("Evidence text is too long or has invalid Unicode")
    elif value is not None and type(value) not in (bool, int, float):
        raise ValueError("Unsupported evidence value")
    elif type(value) is int and not -(2**63) <= value < 2**63:
        raise ValueError("Evidence integer exceeds the supported range")
    elif type(value) is float and not math.isfinite(value):
        raise ValueError("Non-finite evidence value")


def validate_alert(item):
    fields = {"id", "rule", "severity", "ts", "first_seen", "src", "dst", "count", "summary", "evidence", "recommendation"}
    if not isinstance(item, dict) or not fields <= item.keys() or item.keys() - fields - {"acknowledged"}:
        raise ValueError("Expected an EXCUBITOR alert")
    for key in ("id", "rule", "severity", "src", "dst", "summary", "recommendation"):
        if (not isinstance(item[key], str) or len(item[key]) > (4096 if key in ("summary", "recommendation") else 256)
                or any(0xD800 <= ord(char) <= 0xDFFF for char in item[key])):
            raise ValueError("Invalid alert text")
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", item["id"])
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,255}", item["rule"]) or item["severity"] not in LEVELS):
        raise ValueError("Invalid alert identifier or severity")
    if _finite(item["first_seen"], "first_seen") > _finite(item["ts"], "timestamp"):
        raise ValueError("First observation occurs after alert")
    if type(item["count"]) is not int or not 1 <= item["count"] <= 10**9:
        raise ValueError("Invalid alert count")
    if not isinstance(item["evidence"], dict) or type(item.get("acknowledged", False)) is not bool:
        raise ValueError("Invalid evidence or acknowledgement")
    _bounded(item["evidence"])
    if len(json.dumps(item, ensure_ascii=True)) > 65536:
        raise ValueError("Alert exceeds 64 KiB")
    return {**item, "acknowledged": item.get("acknowledged", False)}


def load_alerts(path):
    if not Path(path).is_file():
        raise ValueError("Alert input must be an existing regular file")
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Alert input exceeds 16 MiB")
    try:
        text = raw.decode("utf-8")
        try:
            value = json.loads(text, object_pairs_hook=_pairs)
        except json.JSONDecodeError:
            value = []
            for line in text.splitlines():
                if not line.strip():
                    continue
                if len(value) >= MAX_ALERTS:
                    raise ValueError("Expected at most 10000 alerts")
                value.append(json.loads(line, object_pairs_hook=_pairs))
        if isinstance(value, dict):
            if value.keys() != {"schema", "alerts"} or value["schema"] != "excubitor.alerts.v1":
                # Unum indicium in forma JSONL quoque accipitur.
                value = [value]
            else:
                value = value["alerts"]
        if not isinstance(value, list) or len(value) > MAX_ALERTS:
            raise ValueError("Expected at most 10000 alerts")
        result = [validate_alert(item) for item in value]
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as exc:
        raise ValueError("Invalid alert input") from exc
    return result, hashlib.sha256(raw).hexdigest()


def correlate(alerts, gap=300, max_span=900, min_alerts=1, source_sha256=None):
    if not isinstance(alerts, (list, tuple)):
        raise ValueError("Expected a bounded sequence of alerts")
    if source_sha256 is not None and (not isinstance(source_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", source_sha256)):
        raise ValueError("Source digest must be a SHA-256 hexadecimal value")
    if type(gap) is not int or type(max_span) is not int or not 1 <= gap <= max_span <= 86400:
        raise ValueError("Require 1 <= gap <= max-span <= 86400 seconds")
    if type(min_alerts) is not int or not 1 <= min_alerts <= MAX_ALERTS or len(alerts) > MAX_ALERTS:
        raise ValueError("Invalid alert limit")
    unique = {}
    for item in alerts:
        item = validate_alert(item)
        previous = unique.get(item["id"])
        if previous is not None and previous != item:
            raise ValueError("Conflicting duplicate alert identifier")
        unique[item["id"]] = item
    groups, active = [], {}
    for item in sorted(unique.values(), key=lambda a: (a["ts"], a["id"])):
        # Fontes ambigui non in unum artificiose coguntur.
        try:
            key = (str(ipaddress.ip_address(item["src"])), str(ipaddress.ip_address(item["dst"])))
        except ValueError:
            key = (item["src"], item["dst"], item["id"])
        group = active.get(key)
        if group is None or item["ts"] - group[-1]["ts"] > gap or item["ts"] - group[0]["ts"] > max_span:
            group = []
            active[key] = group
            groups.append(group)
        group.append(item)
    incidents = []
    for group in groups:
        if len(group) < min_alerts:
            continue
        identifier = hashlib.sha256(json.dumps([a["id"] for a in group], separators=(",", ":")).encode()).hexdigest()[:24]
        incidents.append({"id": identifier, "src": group[0]["src"], "dst": group[0]["dst"],
                          "first_alert": group[0]["ts"], "last_alert": group[-1]["ts"],
                          "first_observation": min(a["first_seen"] for a in group),
                          "severity": max((a["severity"] for a in group), key=LEVELS.__getitem__),
                          "rules": sorted({a["rule"] for a in group}), "alert_count": len(group),
                          "unacknowledged_count": sum(not a["acknowledged"] for a in group), "alerts": group})
    return {"schema": "excubitor.incidents.v1", "notice": NOTICE,
            "scope": "Provided alert export only; collection completeness is unknown.",
            "source_sha256": source_sha256, "parameters": {"gap_seconds": gap, "max_span_seconds": max_span, "min_alerts": min_alerts},
            "input_alerts": len(alerts), "unique_alerts": len(unique), "duplicate_alerts": len(alerts) - len(unique),
            "omitted_alerts": len(unique) - sum(i["alert_count"] for i in incidents), "incidents": incidents}


def markdown(report):
    def clean(value):
        text = html.escape(str(value), quote=True)
        text = "".join(c if c.isprintable() else " " for c in text)
        for char in "\\`*_{}[]()#+-.!|>":
            text = text.replace(char, "\\" + char)
        return text
    lines = ["# EXCUBITOR investigation timeline", "", report["notice"], "", report["scope"], "",
             f"Input alerts: {report['input_alerts']}; unique: {report['unique_alerts']}; omitted by minimum: {report['omitted_alerts']}.", ""]
    if report["source_sha256"]:
        lines += [f"Source SHA-256: `{report['source_sha256']}`", ""]
    for incident in report["incidents"]:
        lines += [f"## {incident['id']}", "", f"{clean(incident['src'])} → {clean(incident['dst'])} | {incident['severity'].upper()}", "",
                  "| Alert time (UTC) | Rule | Summary | Acknowledged |", "| --- | --- | --- | --- |"]
        for alert in incident["alerts"]:
            lines.append(f"| {iso_time(alert['ts'])} | {clean(alert['rule'])} | {clean(alert['summary'])} | {'yes' if alert['acknowledged'] else 'no'} |")
        lines.append("")
    return "\n".join(lines) + "\n"
