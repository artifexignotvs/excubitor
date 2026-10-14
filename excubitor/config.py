"""Limites expliciti errores occultos prohibent."""
from __future__ import annotations
from dataclasses import fields
from pathlib import Path
import ipaddress
import tomllib
from .model import Config

TEMPLATE = '''# Vigilantia ex indiciis nascitur.
[detection]
window = 60
auth_window = 300
cooldown = 120
allowed_lateness = 30
scan_ports = 20
scan_hosts = 15
auth_failures = 8
spray_users = 6
distributed_sources = 5
web_paths = 12
web_denials = 20
max_keys = 10000
max_events_per_key = 512
disabled_rules = []

[allowlist]
sources = []
destinations = []
'''


def load_config(path: str | None) -> Config:
    if not path:
        return Config()
    with Path(path).open("rb") as stream:
        doc = tomllib.load(stream)
    unknown = set(doc) - {"detection", "allowlist"}
    if unknown:
        raise ValueError("Unknown configuration section")
    settings = doc.get("detection", {})
    allow = doc.get("allowlist", {})
    if not isinstance(settings, dict) or not isinstance(allow, dict):
        raise ValueError("Configuration sections must be tables")
    valid = {f.name for f in fields(Config)} - {"allow_src", "allow_dst"}
    if set(settings) - valid or set(allow) - {"sources", "destinations"}:
        raise ValueError("Unknown configuration key")
    settings = dict(settings)
    for name, value in settings.items():
        if name == "disabled_rules":
            if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
                raise ValueError("disabled_rules must be a list of rule names")
            settings[name] = tuple(value)
        elif isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{name} must be an integer")
    for name, key in (("sources", "allow_src"), ("destinations", "allow_dst")):
        values = allow.get(name, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise ValueError("Allowlists must be lists of IP networks")
        settings[key] = tuple(str(ipaddress.ip_network(v, strict=False)) for v in values)
    return Config(**settings)
