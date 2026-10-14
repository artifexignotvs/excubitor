"""Ex fontibus diversis indicia parva et definita colliguntur."""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import math
import re
import unicodedata
from urllib.parse import urlsplit

from .model import Event

FORMATS = ("auto", "native", "eve", "zeek", "auth")
MAX_LINE_LENGTH = 1_048_576
_KINDS = {"conn", "auth", "http", "alert"}
_HOST = re.compile(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?\Z")
_SYSLOG = re.compile(
    r"^(?:<\d{1,3}>)?(?P<stamp>\d{4}-\d\d-\d\d[Tt]\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+(?P<app>[\w./-]+)(?:\[\d+\])?:\s*(?P<body>.*)$"
)
_AUTH = re.compile(
    r"^(?P<action>Failed|Accepted) (?P<method>password|publickey|keyboard-interactive(?:/pam)?|none) "
    r"for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d{1,5})(?:\s.*)?$"
)
_MONTHS = {name: number for number, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


class ParseError(ValueError):
    """Forma vitiosa sine materia secreta refertur."""


def _text(value: object, field: str, limit: int = 256) -> str:
    if not isinstance(value, str):
        raise ParseError(f"{field} must be a string")
    if len(value) > limit:
        raise ParseError(f"{field} exceeds {limit} characters")
    if any(unicodedata.category(char).startswith("C") for char in value):
        raise ParseError(f"{field} contains control characters")
    return value


def _ip(value: object, field: str, *, hostname: bool = False, optional: bool = False) -> str:
    text = _text(value, field, 253)
    if not text and optional:
        return ""
    try:
        if "%" in text:
            raise ValueError
        return str(ipaddress.ip_address(text))
    except ValueError:
        if hostname and _HOST.fullmatch(text) and not re.fullmatch(r"[\d.]+", text):
            return text.rstrip(".").lower()
        raise ParseError(f"{field} must be a valid IP address" + (" or hostname" if hostname else "")) from None


def _integer(value: object, field: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ParseError(f"{field} must be an integer between 0 and {maximum}")
    return value


def _timestamp(value: object) -> float:
    if isinstance(value, bool):
        raise ParseError("timestamp must be an epoch number or timezone-aware ISO 8601 string")
    try:
        if isinstance(value, (int, float)):
            stamp = float(value)
        elif isinstance(value, str):
            parsed = datetime.fromisoformat(_text(value, "timestamp", 64).replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ParseError("ISO 8601 timestamp must include a timezone")
            stamp = parsed.timestamp()
        else:
            raise ParseError("timestamp must be an epoch number or timezone-aware ISO 8601 string")
        if not math.isfinite(stamp) or stamp < 0:
            raise ValueError
        datetime.fromtimestamp(stamp, timezone.utc)
        return stamp
    except (ValueError, OverflowError, OSError) as error:
        if isinstance(error, ParseError):
            raise
        raise ParseError("timestamp is invalid or outside the supported date range") from None


def _path(value: object) -> str:
    text = _text(value, "path", 8192)
    try:
        # Quaestiones, fragmenta et auctoritas URL non servantur.
        path = urlsplit(text).path
    except ValueError:
        raise ParseError("path is not a valid request target") from None
    return _text(path, "path", 2048)


def _object(value: object, field: str) -> dict:
    if not isinstance(value, dict):
        raise ParseError(f"{field} must be an object")
    return value


def _required(data: dict, field: str) -> object:
    if field not in data:
        raise ParseError(f"missing required field: {field}")
    return data[field]


def _json_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ParseError("JSON objects must not contain duplicate fields")
        result[key] = value
    return result


def _nonfinite(_: str) -> None:
    raise ParseError("JSON constants must be finite")


def _source(data: dict, source: str) -> str:
    return _text(source or data.get("source", ""), "source", 1024)


def _native(data: dict, source: str) -> list[Event]:
    kind = _text(_required(data, "kind"), "kind", 16)
    if kind not in _KINDS:
        raise ParseError("kind must be conn, auth, http or alert")
    outcome = _text(data.get("outcome", ""), "outcome", 32)
    if kind == "auth" and outcome not in {"failure", "success"}:
        raise ParseError("auth outcome must be failure or success")
    severity = _text(data.get("severity", "medium"), "severity", 16)
    if severity not in {"info", "low", "medium", "high", "critical"}:
        raise ParseError("severity must be info, low, medium, high or critical")
    status = _integer(data.get("status", 0), "status", 599)
    if status and status < 100:
        raise ParseError("status must be zero or an HTTP status from 100 to 599")
    return [Event(
        ts=_timestamp(_required(data, "ts")), kind=kind,
        src=_ip(_required(data, "src"), "src"),
        dst=_ip(data.get("dst", ""), "dst", hostname=kind == "auth", optional=kind == "alert"),
        port=_integer(data.get("port", 0), "port", 65535),
        proto=_text(data.get("proto", "tcp"), "proto", 16).lower(),
        user=_text(data.get("user", ""), "user"), outcome=outcome,
        service=_text(data.get("service", ""), "service", 64).lower(),
        path=_path(data.get("path", "")), status=status,
        signature=_text(data.get("signature", ""), "signature", 512), severity=severity,
        source=_source(data, source), event_id=_text(data.get("event_id", ""), "event_id", 256),
    )]


def _eve(data: dict, source: str) -> list[Event]:
    event_type = _text(_required(data, "event_type"), "event_type", 64)
    if event_type not in {"flow", "netflow", "http", "alert"}:
        return []
    body = _object(_required(data, event_type), event_type)
    flow = _object(data.get("flow", {}), "flow")
    ts = _timestamp(_required(data, "timestamp"))
    addresses = data
    if event_type == "alert" and ("src_ip" in flow or "dest_ip" in flow):
        # Directio fluxus ante directionem fasciculi eligitur.
        addresses = flow
    src = _ip(_required(addresses, "src_ip"), "src_ip")
    dst = _ip(_required(addresses, "dest_ip"), "dest_ip")
    port = _integer(addresses.get("dest_port", 0), "dest_port", 65535)
    proto = _text(data.get("proto", "tcp"), "proto", 16).lower()
    service = _text(data.get("app_proto", ""), "app_proto", 64).lower()
    kind = "conn" if event_type in {"flow", "netflow"} else event_type
    extra: dict = {}
    if kind == "http":
        status = _integer(body.get("status", 0), "http.status", 599)
        if status and status < 100:
            raise ParseError("http.status must be zero or an HTTP status from 100 to 599")
        extra.update(path=_path(body.get("url", "")), status=status, service=service or "http")
    elif kind == "alert":
        level = _integer(body.get("severity", 2), "alert.severity", 255)
        extra.update(signature=_text(_required(body, "signature"), "alert.signature", 512),
                     severity={1: "high", 2: "medium", 3: "low"}.get(level, "medium"))
    # Numerus fluxus non est identificator unius observationis.
    return [Event(ts=ts, kind=kind, src=src, dst=dst, port=port, proto=proto,
                  source=_source(data, source),
                  **({"service": service} | extra))]


def _zeek(data: dict, source: str) -> list[Event]:
    if "_path" not in data and "id.orig_h" not in data:
        raise ParseError("expected a Zeek JSON record")
    log_type = _text(data.get("_path", ""), "_path", 64)
    if log_type and log_type not in {"conn", "http", "ssh"}:
        return []
    if not log_type:
        if any(key in data for key in ("auth_success", "auth_attempts", "cipher_alg", "host_key_alg")):
            log_type = "ssh"
        elif any(key in data for key in ("uri", "method", "status_code", "trans_depth")):
            log_type = "http"
        elif any(key in data for key in ("conn_state", "history", "orig_bytes", "resp_bytes")):
            log_type = "conn"
        else:
            return []
    extra: dict = {}
    if log_type == "ssh":
        success = data.get("auth_success")
        if "auth_success" not in data:
            return []
        if not isinstance(success, bool):
            raise ParseError("auth_success must be a boolean when present")
        # Numerus aggregatus in eventus fictos non multiplicatur.
        extra.update(outcome="success" if success else "failure", service="ssh")
        kind = "auth"
    elif log_type == "http":
        status = _integer(data.get("status_code", 0), "status_code", 599)
        if status and status < 100:
            raise ParseError("status_code must be zero or an HTTP status from 100 to 599")
        extra.update(path=_path(data.get("uri", "")), status=status, service="http")
        kind = "http"
    else:
        kind = "conn"
        extra.update(service=_text(data.get("service", ""), "service", 64).lower())
    ts = _timestamp(_required(data, "ts"))
    return [Event(ts=ts, kind=kind, src=_ip(_required(data, "id.orig_h"), "id.orig_h"),
                  dst=_ip(_required(data, "id.resp_h"), "id.resp_h"),
                  port=_integer(_required(data, "id.resp_p"), "id.resp_p", 65535),
                  proto=_text(data.get("proto", "tcp"), "proto", 16).lower(),
                  source=_source(data, source), **extra)]


def _auth(line: str, source: str, year: int | None) -> list[Event]:
    header = _SYSLOG.fullmatch(line)
    if not header:
        raise ParseError("expected a timestamped syslog record")
    if header["app"] not in {"sshd", "sshd-session"}:
        return []
    body = header["body"]
    match = _AUTH.fullmatch(body)
    if not match:
        if body.startswith(("Failed ", "Accepted ")):
            raise ParseError("unsupported or malformed SSH authentication record")
        return []
    stamp = header["stamp"]
    if stamp[0].isdigit():
        ts = _timestamp(stamp)
    else:
        if isinstance(year, bool) or not isinstance(year, int) or not 1970 <= year <= 9999:
            raise ParseError("traditional syslog timestamps require an explicit year")
        try:
            month, day, clock = stamp.split()
            hour, minute, second = map(int, clock.split(":"))
            ts = _timestamp(datetime(year, _MONTHS[month], int(day), hour, minute, second,
                                     tzinfo=timezone.utc).isoformat())
        except (KeyError, ValueError, OverflowError):
            raise ParseError("invalid traditional syslog timestamp") from None
    _integer(int(match["port"]), "source port", 65535)
    return [Event(ts=ts, kind="auth", src=_ip(match["ip"], "source IP"),
                  dst=_ip(header["host"], "syslog host", hostname=True), port=0, proto="tcp",
                  user=_text(match["user"], "user"),
                  outcome="failure" if match["action"] == "Failed" else "success",
                  service="ssh", source=_text(source, "source", 1024))]


def parse_line(line: str, format: str = "auto", source: str = "", year: int | None = None) -> list[Event]:
    """Una linea probatur; forma ignota numquam pro eventu valido habetur."""
    if format not in FORMATS:
        raise ParseError("format must be auto, native, eve, zeek or auth")
    if not isinstance(line, str):
        raise ParseError("line must be text")
    if len(line) > MAX_LINE_LENGTH:
        raise ParseError(f"line exceeds {MAX_LINE_LENGTH} characters")
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    if format == "auth" or (format == "auto" and not line.startswith(("{", "["))):
        return _auth(line, source, year)
    try:
        data = json.loads(line, parse_constant=_nonfinite, object_pairs_hook=_json_object)
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, ParseError):
            raise
        raise ParseError("invalid JSON record") from None
    data = _object(data, "record")
    if format == "auto":
        if "kind" in data:
            format = "native"
        elif "event_type" in data:
            format = "eve"
        elif "id.orig_h" in data or "_path" in data:
            format = "zeek"
        else:
            raise ParseError("JSON record has no recognized event schema")
    return {"native": _native, "eve": _eve, "zeek": _zeek}[format](data, source)
