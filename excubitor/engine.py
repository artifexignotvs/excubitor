"""Vigilia finita; indicia colliguntur, culpa non praesumitur."""
from __future__ import annotations

from bisect import bisect_left, bisect_right, insort
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from typing import Any

from .model import Alert, Config, Event

RULES = {
    "vertical_scan": "Many destination ports observed from one source to one host.",
    "horizontal_scan": "Many destination hosts observed from one source on one port.",
    "auth_bruteforce": "Repeated authentication failures grouped by source, destination, account and service.",
    "password_spray": "Authentication failures across many accounts from one source.",
    "distributed_auth": "Authentication failures against one account from many sources.",
    "auth_success_after_fail": "A successful authentication follows repeated failures for the same known account.",
    "web_path_scan": "Many distinct web paths returned 403 or 404.",
    "web_denial_burst": "A burst of web responses returned 401 or 403.",
    "upstream_alert": "A supplied sensor alert is preserved as an upstream observation.",
}

_LIMITS = {
    "kind": 16, "src": 256, "dst": 256, "proto": 32,
    "user": 256, "outcome": 32, "service": 128, "path": 4096,
    "signature": 2048, "severity": 32, "source": 1024, "event_id": 256,
}


@dataclass(slots=True)
class _Bucket:
    """Tempora ordinantur; memoria terminatur."""

    window: int
    records: list[tuple[float, str]] = field(default_factory=list)


class Engine:
    """Fenestram [t-w, t] inspice; res futuras excludito.

    Eventa ante limen temporis omittuntur. Eventa tarda licita non mutant
    iudicia iam emissa. Singulae tabulae claves finitas servant.
    """

    def __init__(self, config: Config | None = None):
        self.config = config or Config()
        self._validate_config()
        self._allow_src = tuple(ipaddress.ip_network(item, strict=False)
                                for item in self.config.allow_src)
        self._allow_dst = tuple(ipaddress.ip_network(item, strict=False)
                                for item in self.config.allow_dst)
        self._disabled = frozenset(self.config.disabled_rules)
        self._states: OrderedDict[tuple[str, ...], _Bucket] = OrderedDict()
        self._dedup: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._cooldowns: OrderedDict[tuple[str, ...], float] = OrderedDict()
        self._watermark = float("-inf")
        self._next_sweep = float("-inf")
        self._entries = 0
        self.stats: dict[str, int | float] = dict.fromkeys((
            "received_events", "accepted_events", "late_events", "invalid_events",
            "duplicate_events", "allowlisted_events", "alerts", "cooldown_suppressed",
            "keys_evicted", "events_evicted", "keys_expired", "dedup_evicted",
            "cooldowns_evicted", "state_keys", "buffered_events", "dedup_keys",
            "cooldown_keys",
        ), 0)

    @property
    def state_size(self) -> int:
        """Numerum clavium detectionis redde."""
        return len(self._states)

    def _validate_config(self) -> None:
        for name in ("window", "auth_window", "max_keys", "max_events_per_key",
                     "scan_ports", "scan_hosts", "auth_failures", "spray_users",
                     "distributed_sources", "web_paths", "web_denials"):
            value = getattr(self.config, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        for name in ("cooldown", "allowed_lateness"):
            value = getattr(self.config, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        unknown = set(self.config.disabled_rules) - set(RULES)
        if unknown:
            raise ValueError(f"Unknown disabled rules: {', '.join(sorted(unknown))}")
        requirements = {
            "scan_ports": ("vertical_scan",), "scan_hosts": ("horizontal_scan",),
            "auth_failures": ("auth_bruteforce", "auth_success_after_fail"),
            "spray_users": ("password_spray",), "distributed_sources": ("distributed_auth",),
            "web_paths": ("web_path_scan",), "web_denials": ("web_denial_burst",),
        }
        for name, rules in requirements.items():
            if any(rule not in self.config.disabled_rules for rule in rules):
                if getattr(self.config, name) > self.config.max_events_per_key:
                    raise ValueError(f"{name} exceeds max_events_per_key")

    def _valid(self, event: Event) -> bool:
        if not isinstance(event, Event):
            return False
        if isinstance(event.ts, bool) or not isinstance(event.ts, (int, float)):
            return False
        try:
            if not math.isfinite(event.ts) or event.ts < 0:
                return False
            datetime.fromtimestamp(event.ts, timezone.utc)
        except (ValueError, OverflowError, OSError):
            return False
        for name, limit in _LIMITS.items():
            value = getattr(event, name)
            if not isinstance(value, str) or len(value) > limit:
                return False
        if event.kind not in {"conn", "auth", "http", "alert"} or not event.src:
            return False
        if (isinstance(event.port, bool) or not isinstance(event.port, int)
                or not 0 <= event.port <= 65535):
            return False
        if (isinstance(event.status, bool) or not isinstance(event.status, int)
                or not 0 <= event.status <= 599):
            return False
        return True

    @staticmethod
    def _allowed(address: str, networks: tuple[Any, ...]) -> bool:
        if not networks or not address:
            return False
        try:
            value = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(value.version == network.version and value in network
                   for network in networks)

    def _gauges(self) -> None:
        self.stats.update(state_keys=len(self._states), buffered_events=self._entries,
                          dedup_keys=len(self._dedup), cooldown_keys=len(self._cooldowns))

    def _trim(self, bucket: _Bucket) -> None:
        cutoff = self._watermark - bucket.window - self.config.allowed_lateness
        remove = bisect_left(bucket.records, cutoff, key=lambda record: record[0])
        if remove:
            del bucket.records[:remove]
            self._entries -= remove

    def _sweep(self) -> None:
        for key, bucket in list(self._states.items()):
            self._trim(bucket)
            if not bucket.records:
                del self._states[key]
                self.stats["keys_expired"] += 1
        retain = max(self.config.window, self.config.auth_window, self.config.cooldown)
        cutoff = self._watermark - retain - self.config.allowed_lateness
        for key, ts in list(self._dedup.items()):
            if ts < cutoff:
                del self._dedup[key]
        cutoff = self._watermark - self.config.cooldown - self.config.allowed_lateness
        for key, ts in list(self._cooldowns.items()):
            if ts < cutoff:
                del self._cooldowns[key]
        self._next_sweep = self._watermark + min(self.config.window, self.config.auth_window)

    def _records(self, key: tuple[str, ...], ts: float, window: int,
                 value: str | None = None) -> list[tuple[float, str]]:
        bucket = self._states.get(key)
        if bucket is None:
            if value is None:
                return []
            if len(self._states) >= self.config.max_keys:
                _, discarded = self._states.popitem(last=False)
                self._entries -= len(discarded.records)
                self.stats["keys_evicted"] += 1
            bucket = _Bucket(window)
            self._states[key] = bucket
        self._states.move_to_end(key)
        self._trim(bucket)
        if value is not None:
            insort(bucket.records, (ts, value))
            self._entries += 1
            if len(bucket.records) > self.config.max_events_per_key:
                bucket.records.pop(0)
                self._entries -= 1
                self.stats["events_evicted"] += 1
        start = bisect_left(bucket.records, ts - window, key=lambda record: record[0])
        end = bisect_right(bucket.records, ts, key=lambda record: record[0])
        return bucket.records[start:end]

    def _emit(self, rule: str, group: tuple[str, ...], event: Event,
              records: list[tuple[float, str]], count: int, threshold: int,
              window: int, severity: str, summary: str, evidence: dict[str, Any],
              recommendation: str, src: str | None = None, dst: str | None = None
              ) -> Alert | None:
        if rule in self._disabled or count < threshold:
            return None
        key = (rule, *group)
        previous = self._cooldowns.get(key)
        if (self.config.cooldown and previous is not None
                and event.ts < previous + self.config.cooldown):
            self.stats["cooldown_suppressed"] += 1
            return None
        if self.config.cooldown:
            if key not in self._cooldowns and len(self._cooldowns) >= self.config.max_keys:
                self._cooldowns.popitem(last=False)
                self.stats["cooldowns_evicted"] += 1
            self._cooldowns[key] = event.ts
            self._cooldowns.move_to_end(key)
        first_seen = records[0][0] if records else event.ts
        payload = json.dumps([rule, group, event.ts, first_seen, count],
                             ensure_ascii=True, separators=(",", ":"))
        alert_id = hashlib.sha256(payload.encode()).hexdigest()[:24]
        details = {"threshold": threshold, "window_seconds": window,
                   "window_start": event.ts - window, "window_end": event.ts,
                   "sensor_source": event.source, **evidence}
        self.stats["alerts"] += 1
        return Alert(alert_id, rule, severity, event.ts, first_seen,
                     event.src if src is None else src,
                     event.dst if dst is None else dst, count, summary, details,
                     recommendation)

    def feed(self, event: Event) -> list[Alert]:
        """Unum eventum accipe; tantum indicia sustentata redde."""
        self.stats["received_events"] += 1
        if not self._valid(event):
            self.stats["invalid_events"] += 1
            return []
        if (self._allowed(event.src, self._allow_src)
                or self._allowed(event.dst, self._allow_dst)):
            self.stats["allowlisted_events"] += 1
            return []
        if event.ts < self._watermark - self.config.allowed_lateness:
            self.stats["late_events"] += 1
            return []
        dedup_key = (event.source, event.event_id)
        if event.event_id and dedup_key in self._dedup:
            retain = max(self.config.window, self.config.auth_window, self.config.cooldown)
            cutoff = max(self._watermark, event.ts) - retain - self.config.allowed_lateness
            if self._dedup[dedup_key] >= cutoff:
                self.stats["duplicate_events"] += 1
                return []
            del self._dedup[dedup_key]
        self._watermark = max(self._watermark, event.ts)
        if self._watermark >= self._next_sweep:
            self._sweep()
        if event.event_id:
            if len(self._dedup) >= self.config.max_keys:
                self._dedup.popitem(last=False)
                self.stats["dedup_evicted"] += 1
            self._dedup[dedup_key] = event.ts
        self.stats["accepted_events"] += 1
        found: list[Alert | None] = []
        if event.kind == "conn" and event.dst and event.port:
            found.extend(self._connection(event))
        elif event.kind == "auth":
            found.extend(self._authentication(event))
        elif event.kind == "http":
            found.extend(self._http(event))
        elif event.kind == "alert" and event.signature:
            severity = event.severity if event.severity in {"info", "low", "medium", "high", "critical"} else "medium"
            found.append(self._emit(
                "upstream_alert", (event.src, event.dst, event.signature), event,
                [], 1, 1, 0, severity, f"Sensor alert: {event.signature}",
                {"signature": event.signature, "upstream_severity": event.severity,
                 "port": event.port, "protocol": event.proto},
                "Inspect the original sensor event and its rule; this observation is not independent confirmation.",
            ))
        self._gauges()
        return [alert for alert in found if alert is not None]

    def _connection(self, event: Event) -> list[Alert | None]:
        found = []
        rule = "vertical_scan"
        if rule not in self._disabled:
            group = (event.src, event.dst, event.proto)
            records = self._records((rule, *group), event.ts, self.config.window, str(event.port))
            ports = sorted({int(value) for _, value in records})
            found.append(self._emit(
                rule, group, event, records, len(ports), self.config.scan_ports,
                self.config.window, "medium",
                f"{len(ports)} destination ports observed from one source to one host",
                {"ports_sample": ports[:12], "protocol": event.proto,
                 "observations": len(records)},
                "Check whether the source is an approved scanner; correlate connection outcomes and firewall records.",
            ))
        rule = "horizontal_scan"
        if rule not in self._disabled:
            group = (event.src, str(event.port), event.proto)
            records = self._records((rule, *group), event.ts, self.config.window, event.dst)
            hosts = sorted({value for _, value in records})
            found.append(self._emit(
                rule, group, event, records, len(hosts), self.config.scan_hosts,
                self.config.window, "medium",
                f"{len(hosts)} destination hosts observed on port {event.port}",
                {"destinations_sample": hosts[:8], "port": event.port,
                 "protocol": event.proto, "observations": len(records)},
                "Check authorized discovery and service fan-out before treating the source as hostile.",
                dst="multiple",
            ))
        return found

    def _authentication(self, event: Event) -> list[Alert | None]:
        found = []
        group = (event.src, event.dst, event.user, event.service)
        key = ("auth_failures", *group)
        enabled = {"auth_bruteforce", "auth_success_after_fail"} - self._disabled
        if event.outcome == "failure":
            if enabled and (event.user or "auth_bruteforce" not in self._disabled):
                records = self._records(key, event.ts, self.config.auth_window, event.user)
                found.append(self._emit(
                    "auth_bruteforce", group, event, records, len(records),
                    self.config.auth_failures, self.config.auth_window, "high",
                    (f"{len(records)} authentication failures for one account and service" if event.user
                     else f"{len(records)} unknown-account authentication failures for one source and service"),
                    {"user": event.user, "account_known": bool(event.user), "service": event.service},
                    "Review authentication records, source ownership, account policy, and rate limits; failures alone do not prove access.",
                ))
            rule = "password_spray"
            if rule not in self._disabled and event.user:
                spray_group = (event.src, event.dst, event.service)
                records = self._records((rule, *spray_group), event.ts,
                                        self.config.auth_window, event.user)
                users = sorted({value for _, value in records})
                found.append(self._emit(
                    rule, spray_group, event, records, len(users), self.config.spray_users,
                    self.config.auth_window, "high",
                    f"Authentication failures across {len(users)} accounts from one source",
                    {"users_sample": users[:8], "service": event.service,
                     "failures": len(records)},
                    "Check shared egress and legitimate account migrations; correlate failures across accounts and enforce authentication controls.",
                ))
            rule = "distributed_auth"
            if rule not in self._disabled and event.user:
                distributed_group = (event.dst, event.user, event.service)
                records = self._records((rule, *distributed_group), event.ts,
                                        self.config.auth_window, event.src)
                sources = sorted({value for _, value in records})
                found.append(self._emit(
                    rule, distributed_group, event, records, len(sources),
                    self.config.distributed_sources, self.config.auth_window, "high",
                    f"Authentication failures for one account from {len(sources)} sources",
                    {"sources_sample": sources[:8], "user": event.user,
                     "service": event.service, "failures": len(records)},
                    "Review the account's authentication history and source distribution; confirm whether the failures are expected.",
                    src="multiple",
                ))
        elif (event.outcome == "success" and event.user
              and "auth_success_after_fail" not in self._disabled):
            records = self._records(key, event.ts, self.config.auth_window)
            found.append(self._emit(
                "auth_success_after_fail", group, event, records, len(records),
                self.config.auth_failures, self.config.auth_window, "high",
                f"Successful authentication after {len(records)} failures for the same account and source",
                {"user": event.user, "service": event.service,
                 "success_at": event.ts, "prior_failures": len(records)},
                "Verify that the successful login was authorized and review the resulting session; retries can also be legitimate.",
            ))
        return found

    def _http(self, event: Event) -> list[Alert | None]:
        found = []
        group = (event.src, event.dst)
        rule = "web_path_scan"
        if rule not in self._disabled and event.status in {403, 404} and event.path:
            path = event.path.split("?", 1)[0].split("#", 1)[0]
            if path:
                records = self._records((rule, *group), event.ts, self.config.window, path)
                paths = sorted({value for _, value in records})
                found.append(self._emit(
                    rule, group, event, records, len(paths), self.config.web_paths,
                    self.config.window, "medium",
                    f"{len(paths)} distinct web paths returned 403 or 404",
                    {"paths_sample": paths[:8], "responses": len(records),
                     "query_strings_ignored": True},
                    "Inspect requests and user agents; broken links and legitimate crawlers can produce this pattern.",
                ))
        rule = "web_denial_burst"
        if rule not in self._disabled and event.status in {401, 403}:
            records = self._records((rule, *group), event.ts,
                                    self.config.window, str(event.status))
            found.append(self._emit(
                rule, group, event, records, len(records), self.config.web_denials,
                self.config.window, "medium",
                f"{len(records)} web responses returned 401 or 403",
                {"statuses": sorted({int(value) for _, value in records})},
                "Review denied requests and expected access policy; a denial response is not evidence of a successful intrusion.",
            ))
        return found
