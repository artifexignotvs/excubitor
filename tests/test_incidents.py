"""Series temporales et fines adversi probantur."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from excubitor.demo import demo_events
from excubitor.engine import Engine
from excubitor.incidents import correlate, load_alerts, markdown, MAX_BYTES
from excubitor.storage import serialize, Store
from excubitor.terminal import Dashboard
from excubitor.cli import Session
import test_cli


def samples():
    engine = Engine()
    return [alert.to_dict() for event in demo_events("ssh") for alert in engine.feed(event)]


class IncidentTests(unittest.TestCase):
    def test_ssh_chain_preserves_evidence_and_does_not_sum_events(self):
        report = correlate(samples())
        self.assertEqual(len(report["incidents"]), 1)
        incident = report["incidents"][0]
        self.assertEqual(incident["rules"], ["auth_bruteforce", "auth_success_after_fail"])
        self.assertEqual(incident["alert_count"], 2)
        self.assertEqual(incident["alerts"][1]["evidence"]["prior_failures"], 8)
        self.assertIn("not proof", report["notice"])
        self.assertNotIn("event_count", incident)

    def test_deterministic_order_and_deduplication(self):
        alerts = samples()
        first = correlate(alerts)["incidents"]
        second = correlate(list(reversed(alerts)) + alerts)["incidents"]
        self.assertEqual(first, second)
        self.assertEqual(correlate(alerts + alerts)["duplicate_alerts"], 2)

    def test_conflicting_id_rejected(self):
        a = samples()[0]
        with self.assertRaises(ValueError):
            correlate([a, {**a, "summary": "different"}])

    def test_anchored_span_prevents_indefinite_chaining(self):
        a = samples()[0]
        alerts = [{**a, "id": str(i), "ts": a["ts"] + i * 200} for i in range(6)]
        report = correlate(alerts, gap=300, max_span=900)
        self.assertEqual([i["alert_count"] for i in report["incidents"]], [5, 1])

    def test_gap_boundary_and_different_endpoints(self):
        a = samples()[0]
        alerts = [a, {**a, "id": "two", "ts": a["ts"] + 300},
                  {**a, "id": "three", "ts": a["ts"] + 601},
                  {**a, "id": "four", "dst": "198.51.100.99"}]
        self.assertEqual(sorted(i["alert_count"] for i in correlate(alerts)["incidents"]), [1, 1, 2])

    def test_ambiguous_addresses_do_not_merge(self):
        for src, dst in (("multiple", "198.51.100.40"), ("192.0.2.30", "")):
            report = correlate([{**a, "src": src, "dst": dst} for a in samples()])
            self.assertEqual(len(report["incidents"]), 2)

    def test_minimum_reports_omission(self):
        report = correlate(samples(), min_alerts=3)
        self.assertEqual(report["incidents"], [])
        self.assertEqual(report["omitted_alerts"], 2)

    def test_invalid_fields_fail_closed(self):
        a = samples()[0]
        for changes in ({"ts": float("nan")}, {"count": True}, {"first_seen": a["ts"] + 1},
                        {"severity": "safe"}, {"acknowledged": 1}, {"unknown": 1}, {"evidence": []}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                correlate([{**a, **changes}])
        for gap, span in ((0, 900), (901, 900), (300, 86401)):
            with self.assertRaises(ValueError):
                correlate([a], gap, span)

    def test_json_jsonl_roundtrip_and_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "alerts"
            for format in ("json", "jsonl"):
                p.write_text(serialize(samples(), format))
                items, digest = load_alerts(p)
                self.assertEqual(len(items), 2)
                self.assertEqual(len(digest), 64)
            p.write_text(json.dumps(samples()[0]))
            self.assertEqual(len(load_alerts(p)[0]), 1)

    def test_bad_input_and_duplicate_keys_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder) / "alerts"
            for text in ('{"schema":"bad","alerts":[]}', '{"id":1,"id":2}',
                         serialize(samples()) + '{"input_errors":1}', 'null', '[' * 2000):
                p.write_text(text)
                with self.assertRaises(ValueError):
                    load_alerts(p)
            p.write_bytes(b" " * (MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                load_alerts(p)

    def test_markdown_does_not_interpret_hostile_text(self):
        a = samples()[0]
        text = markdown(correlate([{**a, "summary": '<script>x</script> | [x](https://example.test)\n# heading'}]))
        self.assertNotIn("<script>", text)
        self.assertNotIn("[x](", text)
        self.assertIn("\\|", text)
        self.assertNotIn("\n# heading", text)

    def test_extreme_integers_and_invalid_unicode_fail_as_validation_errors(self):
        alert = samples()[0]
        for changes in ({"ts": 10**400}, {"summary": "invalid\ud800"}, {"id": "bad\nidentifier"},
                        {"rule": "bad\nrule"}, {"evidence": {"large": 10**400}},
                        {"evidence": {"text": "invalid\udfff"}}, {"evidence": {1: "value"}}):
            with self.subTest(field=next(iter(changes))), self.assertRaises(ValueError):
                correlate([{**alert, **changes}])
        for digest in ("bad", "a" * 63, "`\n# forged", 777):
            with self.assertRaises(ValueError):
                correlate([alert], source_sha256=digest)
        self.assertEqual(correlate([alert], source_sha256="a" * 64)["source_sha256"], "a" * 64)
        with self.assertRaises(ValueError):
            correlate(iter([alert]))

    def test_invalid_utf8_and_excess_jsonl_records_fail(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "alerts.jsonl"
            path.write_bytes(b"\xff")
            with self.assertRaises(ValueError):
                load_alerts(path)
            line = json.dumps(samples()[0]) + "\n"
            path.write_text(line * 10001)
            with self.assertRaisesRegex(ValueError, "10000"):
                load_alerts(path)
            path.write_text("\n\n")
            report = correlate(load_alerts(path)[0])
            self.assertEqual(report["incidents"], [])
            self.assertIn("unknown", report["scope"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Named pipes require POSIX")
    def test_incident_input_refuses_named_pipe_without_waiting(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pipe"
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, "regular file"):
                load_alerts(path)

    def test_history_filters_apply_before_limit_and_parameterize(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(str(Path(folder) / "alerts.db"))
            engine = Engine()
            for event in demo_events():
                for alert in engine.feed(event):
                    store.add(alert)
            items = store.list(1, source="192.0.2.30", destination="198.51.100.40")
            self.assertEqual(items[0]["rule"], "auth_success_after_fail")
            self.assertEqual(store.list(source="' OR 1=1 --"), [])
            store.acknowledge(items[0]["id"])
            self.assertEqual(len(store.list(source="192.0.2.30", unacknowledged=True)), 1)
            self.assertEqual(len(store.list(source="192.0.2.30", since=items[0]["ts"], until=items[0]["ts"])), 1)
            for kwargs in ({"since": float("nan")}, {"since": 2, "until": 1}, {"since": 10**400}, {"limit": True}, {"limit": 1.5}):
                with self.assertRaises(ValueError):
                    store.list(**kwargs)
            with self.assertRaises(ValueError):
                store.acknowledge("missing")
            store.close()

    def test_terminal_unacknowledged_and_severity_order(self):
        session = Session(Engine())
        session.alerts.extend([{**a, "acknowledged": i == 0} for i, a in enumerate(samples())])
        dashboard = Dashboard(session, "test")
        dashboard.unacknowledged = True
        self.assertEqual(len(dashboard._visible()), 1)
        dashboard.unacknowledged = False
        dashboard.priority_sort = True
        self.assertEqual(dashboard._visible()[0]["severity"], "high")


class IncidentCommandTests(unittest.TestCase):
    run_cli = test_cli.CommandTests.run_cli

    def test_invalid_history_request_cannot_acknowledge_a_saved_alert(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "alerts.db"
            result = self.run_cli("demo", "--scenario", "ssh", "--plain", "--db", str(database))
            self.assertEqual(result.returncode, 0, result.stderr)
            store = Store(str(database))
            identifier = store.list()[0]["id"]
            store.close()
            existing = Path(folder) / "existing.json"
            existing.write_text("preserve")
            for arguments in (("--limit", "0"), ("--since", "200", "--until", "100"),
                              ("--since", "nan"), ("--output", str(existing))):
                result = self.run_cli("history", "--db", str(database), "--ack", identifier, *arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                store = Store(str(database))
                self.assertFalse(any(a["acknowledged"] for a in store.list()))
                store.close()
            self.assertEqual(existing.read_text(), "preserve")
            result = self.run_cli("history", "--db", str(database), "--ack", identifier, "--unacknowledged")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(identifier, {a["id"] for a in json.loads(result.stdout)["alerts"]})

    def test_hostile_incident_integer_and_unicode_never_traceback(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "alerts.json"
            for changes in ({"ts": 10**400}, {"summary": "invalid\ud800"}):
                path.write_text(json.dumps({"schema": "excubitor.alerts.v1", "alerts": [{**samples()[0], **changes}]}))
                result = self.run_cli("incidents", "-i", str(path), "--output-format", "markdown")
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_cli_focused_demo_and_incident_report(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "alerts.json"
            result = self.run_cli("demo", "--scenario", "ssh", "--plain", "--output", str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stderr)["engine"]["accepted_events"], 9)
            result = self.run_cli("incidents", "-i", str(path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(json.loads(result.stdout)["incidents"]), 1)
            result = self.run_cli("incidents", "-i", str(path), "--output-format", "markdown", "--output", str(path))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(len(json.loads(path.read_text())["alerts"]), 2)
