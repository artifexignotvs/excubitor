"""Imperium publicum cum indiciis fictis probatur."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from excubitor.demo import demo_events
from excubitor.engine import RULES
from excubitor.terminal import safe

ROOT = Path(__file__).resolve().parents[1]


class CommandTests(unittest.TestCase):
    def run_cli(self, *args, input=None):
        return subprocess.run([sys.executable, "-m", "excubitor", *args], cwd=ROOT, input=input, capture_output=True, text=True, timeout=20)

    def test_demo_all_rules_without_network(self):
        result = self.run_cli("demo", "--jsonl")
        self.assertEqual(result.returncode, 0, result.stderr)
        alerts = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual({a["rule"] for a in alerts}, set(RULES))
        self.assertEqual(len(alerts), 9)
        self.assertEqual(json.loads(result.stderr)["input_errors"], 0)

    def test_fail_on_alert_exit_one(self):
        self.assertEqual(self.run_cli("demo", "--plain", "--fail-on-alert").returncode, 1)

    def test_stdin_replay_matches_demo(self):
        data = "".join(json.dumps(asdict(e)) + "\n" for e in demo_events())
        result = self.run_cli("analyze", "-i", "-", "--jsonl", input=data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 9)

    def test_invalid_input_does_not_hide_valid_alerts(self):
        data = "not json\n" + "".join(json.dumps(asdict(e)) + "\n" for e in demo_events())
        result = self.run_cli("analyze", "-i", "-", "--jsonl", input=data)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(result.stdout.splitlines()), 9)
        self.assertIn('"input_errors": 1', result.stderr)

    def test_multi_file_merge(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = [Path(folder) / f"part{i}.jsonl" for i in range(2)]
            for i, path in enumerate(paths):
                path.write_text("".join(json.dumps(asdict(e)) + "\n" for e in demo_events()[i::2]))
            result = self.run_cli("analyze", "-i", str(paths[0]), "-i", str(paths[1]), "--jsonl")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(result.stdout.splitlines()), 9)

    def test_alias_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input.jsonl"
            path.write_text("")
            alias = Path(folder) / "alias.jsonl"
            alias.symlink_to(path)
            result = self.run_cli("analyze", "-i", str(path), "-i", str(alias))
            self.assertEqual(result.returncode, 2)
            self.assertIn("same file", result.stderr)

    def test_export_history_and_acknowledge(self):
        with tempfile.TemporaryDirectory() as folder:
            db = str(Path(folder) / "alerts.db")
            output = Path(folder) / "alerts.json"
            result = self.run_cli("demo", "--jsonl", "--db", db, "--output", str(output))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(json.loads(output.read_text())["alerts"]), 9)
            result = self.run_cli("history", "--db", db, "--rule", "vertical_scan")
            alerts = json.loads(result.stdout)["alerts"]
            self.assertEqual(len(alerts), 1)
            result = self.run_cli("history", "--db", db, "--ack", alerts[0]["id"], "--rule", "vertical_scan")
            self.assertTrue(json.loads(result.stdout)["alerts"][0]["acknowledged"])
            if os.name == "posix":
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)
                self.assertEqual(Path(db).stat().st_mode & 0o777, 0o600)

    def test_output_never_overwrites(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "saved.json"
            path.write_text("keep")
            result = self.run_cli("demo", "--output", str(path))
            self.assertEqual(result.returncode, 2)
            self.assertEqual(path.read_text(), "keep")

    def test_configuration_validation(self):
        result = self.run_cli("config")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.toml"
            path.write_text(result.stdout)
            self.assertEqual(self.run_cli("config", "--check", str(path)).returncode, 0)
            path.write_text('[detection]\nscan_port = 20\n')
            self.assertEqual(self.run_cli("config", "--check", str(path)).returncode, 2)

    def test_tui_requires_tty(self):
        self.assertEqual(self.run_cli("demo", "--tui").returncode, 2)

    def test_terminal_controls_and_bidi_not_executed(self):
        text = safe("\x1b[2Jbad\rnext\x07\u202eend")
        for forbidden in ("\x1b", "\r", "\x07", "\u202e"):
            self.assertNotIn(forbidden, text)

    def test_replayed_explicit_ids_deduplicate(self):
        events = demo_events()[:20]
        data = "".join(json.dumps(asdict(e)) + "\n" for e in events for _ in range(2))
        result = self.run_cli("analyze", "-i", "-", "--jsonl", input=data)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertEqual(json.loads(result.stderr)["engine"]["duplicate_events"], 20)


if __name__ == "__main__":
    unittest.main()
