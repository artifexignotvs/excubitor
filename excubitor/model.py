"""Formae communes; indicia, non sententiae definitivae."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

VERSION = "0.2.0"

@dataclass(frozen=True, slots=True)
class Event:
    ts: float
    kind: str
    src: str
    dst: str = ""
    port: int = 0
    proto: str = "tcp"
    user: str = ""
    outcome: str = ""
    service: str = ""
    path: str = ""
    status: int = 0
    signature: str = ""
    severity: str = "medium"
    source: str = ""
    event_id: str = ""

@dataclass(frozen=True, slots=True)
class Alert:
    id: str
    rule: str
    severity: str
    ts: float
    first_seen: float
    src: str
    dst: str
    count: int
    summary: str
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = "Review the source records and confirm authorized activity."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(frozen=True, slots=True)
class Config:
    window: int = 60
    auth_window: int = 300
    cooldown: int = 120
    allowed_lateness: int = 30
    scan_ports: int = 20
    scan_hosts: int = 15
    auth_failures: int = 8
    spray_users: int = 6
    distributed_sources: int = 5
    web_paths: int = 12
    web_denials: int = 20
    max_keys: int = 10000
    max_events_per_key: int = 512
    allow_src: tuple[str, ...] = ()
    allow_dst: tuple[str, ...] = ()
    disabled_rules: tuple[str, ...] = ()


def iso_time(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
