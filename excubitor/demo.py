"""Exempla ficta; nullus fasciculus per rete mittitur."""
from dataclasses import replace
from .model import Event


def demo_events(scenario="all") -> list[Event]:
    result = []
    base = 1791979200.0
    def add(offset, **kwargs):
        result.append(Event(ts=base + offset, source="synthetic", event_id=f"demo-{len(result):04}", **kwargs))
    for i in range(20):
        add(i, kind="conn", src="192.0.2.10", dst="198.51.100.10", port=1000 + i)
    for i in range(15):
        add(30 + i, kind="conn", src="192.0.2.20", dst=f"198.51.100.{20+i}", port=445)
    for i in range(8):
        add(50 + i, kind="auth", src="192.0.2.30", dst="198.51.100.40", user="operator", outcome="failure", service="ssh", port=22)
    add(60, kind="auth", src="192.0.2.30", dst="198.51.100.40", user="operator", outcome="success", service="ssh", port=22)
    for i in range(6):
        add(70 + i, kind="auth", src="192.0.2.40", dst="198.51.100.50", user=f"account{i:02}", outcome="failure", service="ssh", port=22)
    for i in range(5):
        add(80 + i, kind="auth", src=f"203.0.113.{20+i}", dst="198.51.100.60", user="operator", outcome="failure", service="ssh", port=22)
    for i in range(12):
        add(90 + i, kind="http", src="192.0.2.50", dst="198.51.100.70", path=f"/missing-{i}", status=404, port=443, service="https")
    for i in range(20):
        add(110 + i, kind="http", src="192.0.2.60", dst="198.51.100.80", path="/login", status=401, port=443, service="https")
    add(135, kind="alert", src="192.0.2.70", dst="198.51.100.90", signature="Synthetic upstream detection for demonstration", severity="high")
    for i in range(5):
        add(140 + i, kind="conn", src="192.0.2.100", dst="198.51.100.100", port=443)
    if scenario == "ssh":
        return [event for event in result if event.src == "192.0.2.30"]
    if scenario != "all":
        raise ValueError("Unknown demo scenario")
    return result
