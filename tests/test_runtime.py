"""Fines externi, errores et vigilia viva adversis condicionibus probantur."""
import csv
import io
import json
import os
from pathlib import Path
import queue
import selectors
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from excubitor.ingest import follow, records
from excubitor.model import Alert
from excubitor.storage import Store, exclusive_write, serialize
from excubitor.terminal import Dashboard, safe

ROOT = Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    def run_cli(self, *args, data=None):
        return subprocess.run([sys.executable, "-m", "excubitor", *args], cwd=ROOT,
                              input=data, capture_output=True, timeout=10)

    def assert_clean_error(self, result):
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)

    def test_csv_formula_prefixes_are_quoted(self):
        for value in ("=1+1", "+1", "-1", "@SUM(1)", " \t=1", "\r\n=1"):
            with self.subTest(value=value):
                text = serialize([{"id": value, "summary": value, "src": value}], "csv")
                row = next(csv.DictReader(io.StringIO(text)))
                for field in ("id", "summary", "src"):
                    self.assertEqual(row[field], "'" + value)
        row = next(csv.DictReader(io.StringIO(serialize([{"summary": "ordinary, quoted text"}], "csv"))))
        self.assertEqual(row["summary"], "ordinary, quoted text")

    def test_exclusive_output_refuses_symlink_and_existing_target(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "target.json"
            target.write_text("preserved")
            link = Path(folder) / "link.json"
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                exclusive_write(str(link), "replacement")
            self.assertEqual(target.read_text(), "preserved")
            missing = Path(folder) / "missing.json"
            dangling = Path(folder) / "dangling.json"
            dangling.symlink_to(missing)
            with self.assertRaises(FileExistsError):
                exclusive_write(str(dangling), "replacement")
            self.assertFalse(missing.exists())

    def test_store_refuses_symbolic_link(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "target.db"
            link = Path(folder) / "link.db"
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                Store(str(link))
            self.assertFalse(target.exists())

    def test_database_hardlink_alias_cannot_modify_input(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "source.jsonl"
            source.write_bytes(b"")
            database = Path(folder) / "alias.db"
            try:
                os.link(source, database)
            except (OSError, NotImplementedError):
                self.skipTest("Hard links are unavailable")
            result = self.run_cli("analyze", "-i", str(source), "--db", str(database), "--plain")
            self.assert_clean_error(result)
            self.assertEqual(source.read_bytes(), b"")
            self.assertIn(b"Database cannot", result.stderr)
            self.assertIn(b"input file", result.stderr)

    def test_store_acknowledgement_parameters_do_not_change_other_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(str(Path(folder) / "alerts.db"))
            try:
                for identifier in ("first", "second"):
                    store.add(Alert(identifier, "upstream_alert", "medium", 100, 100,
                                    "192.0.2.1", "198.51.100.1", 1, "Synthetic"))
                store.acknowledge("' OR 1=1 --")
                self.assertFalse(any(row["acknowledged"] for row in store.list()))
                store.acknowledge("first")
                self.assertEqual({row["id"] for row in store.list() if row["acknowledged"]}, {"first"})
            finally:
                store.close()

    def test_corrupt_database_and_invalid_history_limit_do_not_traceback(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "corrupt.db"
            path.write_bytes(b"this is not a database" * 100)
            self.assert_clean_error(self.run_cli("history", "--db", str(path)))
            valid = Path(folder) / "valid.db"
            Store(str(valid)).close()
            for limit in ("0", "-1", "100001"):
                self.assert_clean_error(self.run_cli("history", "--db", str(valid), "--limit", limit))

    def test_malformed_saved_payload_does_not_traceback(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "alerts.db"
            Store(str(path)).close()
            with sqlite3.connect(path) as database:
                database.execute("INSERT INTO alerts(id,ts,rule,severity,payload) VALUES(?,?,?,?,?)",
                                 ("bad", 100, "upstream_alert", "medium", "[1,2,3]"))
            self.assert_clean_error(self.run_cli("history", "--db", str(path)))

    def test_abnormal_delay_and_missing_sources_do_not_traceback(self):
        for delay in ("nan", "inf", "-1", "11"):
            with self.subTest(delay=delay):
                self.assert_clean_error(self.run_cli("demo", "--plain", "--delay", delay))
        self.assert_clean_error(self.run_cli("watch", "-i", "-", "--plain"))
        self.assert_clean_error(self.run_cli("analyze", "-i", "/nonexistent/example-input.jsonl"))

    def test_invalid_utf8_and_oversize_stdin_recover_valid_event(self):
        event = {"ts": 100, "kind": "alert", "src": "192.0.2.1", "signature": "Synthetic"}
        data = b"\xff\n" + b"x" * 300000 + b"\n" + json.dumps(event).encode() + b"\n"
        result = self.run_cli("analyze", "-i", "-", "--jsonl", data=data)
        self.assert_clean_error(result)
        alerts = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([alert["rule"] for alert in alerts], ["upstream_alert"])
        summary = json.loads(result.stderr.splitlines()[0])
        self.assertEqual(summary["input_errors"], 2)
        self.assertEqual(summary["engine"]["accepted_events"], 1)

    @unittest.skipUnless(os.name == "posix", "Filename control characters require POSIX")
    def test_control_characters_in_input_filename_are_not_emitted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "input\x1b[2J\u202e.jsonl"
            path.write_text("invalid record\n")
            result = self.run_cli("analyze", "-i", str(path), "--plain")
            self.assert_clean_error(result)
            self.assertNotIn(b"\x1b", result.stderr)
            self.assertNotIn("\u202e".encode(), result.stderr)

    def test_record_limits_count_bytes_and_preserve_next_line(self):
        data = "ééé\n".encode() + "éééé\n".encode() + b"last"
        result = list(records(io.BytesIO(data), "fixture", limit=7))
        self.assertEqual(result[0].text, "ééé\n")
        self.assertEqual(result[1].issue, "record exceeds byte limit")
        self.assertEqual(result[2].text, "last")
        self.assertEqual([item.number for item in result], [1, 2, 3])

    def watcher(self, path, *, limit=262144, gate=None):
        stop = threading.Event()
        received = queue.Queue()
        def work():
            try:
                for item in follow(str(path), stop, from_start=True, limit=limit, poll=0.01):
                    received.put(item)
                    if gate and item.text == "first\n":
                        gate.wait(timeout=3)
            except Exception as error:
                received.put(error)
        thread = threading.Thread(target=work, daemon=True)
        thread.start()
        self.addCleanup(stop.set)
        return stop, received, thread

    def end_watcher(self, stop, thread):
        stop.set()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

    def test_follow_reassembles_split_utf8_and_drains_oversize(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.log"
            path.write_bytes(b"first\n")
            stop, received, thread = self.watcher(path, limit=16)
            try:
                self.assertEqual(received.get(timeout=3).text, "first\n")
                with path.open("ab") as output:
                    output.write(b"\xc3")
                with self.assertRaises(queue.Empty):
                    received.get(timeout=0.05)
                with path.open("ab") as output:
                    output.write(b"\xa9\n" + b"x" * 100 + b"\nlast\n")
                self.assertEqual(received.get(timeout=3).text, "é\n")
                self.assertEqual(received.get(timeout=3).issue, "record exceeds byte limit")
                self.assertEqual(received.get(timeout=3).text, "last\n")
            finally:
                self.end_watcher(stop, thread)

    def test_follow_drains_unread_old_inode_before_new_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.log"
            old = Path(folder) / "old.log"
            lines = [f"old-{number:03d}-" + "x" * 1000 + "\n" for number in range(150)]
            path.write_text("first\n" + "".join(lines))
            gate = threading.Event()
            stop, received, thread = self.watcher(path, gate=gate)
            try:
                self.assertEqual(received.get(timeout=3).text, "first\n")
                path.rename(old)
                with old.open("a") as output:
                    output.write("old-tail\n")
                path.write_text("new-file\n")
                gate.set()
                observed = []
                notices = []
                deadline = time.monotonic() + 5
                while "new-file\n" not in observed:
                    item = received.get(timeout=max(0.01, deadline - time.monotonic()))
                    self.assertNotIsInstance(item, Exception)
                    if item.issue:
                        notices.append(item.issue)
                    else:
                        observed.append(item.text)
                self.assertEqual(observed, lines + ["old-tail\n", "new-file\n"])
                self.assertEqual(len(notices), 1)
                self.assertIn("rotated", notices[0])
            finally:
                gate.set()
                self.end_watcher(stop, thread)

    def test_follow_recovers_after_reopen_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.log"
            path.write_text("first\n")
            original_open = open
            opens = 0
            def interrupted_open(name, *args, **kwargs):
                nonlocal opens
                if str(name) == str(path) and args and args[0] == "rb":
                    opens += 1
                    if opens == 2:
                        raise PermissionError("temporary denial")
                return original_open(name, *args, **kwargs)
            with patch("builtins.open", side_effect=interrupted_open):
                stop, received, thread = self.watcher(path)
                try:
                    self.assertEqual(received.get(timeout=3).text, "first\n")
                    path.write_text("x\n")
                    notices = [received.get(timeout=3), received.get(timeout=3)]
                    self.assertTrue(any("unavailable" in item.issue for item in notices))
                    self.assertTrue(any("truncated" in item.issue for item in notices))
                    self.assertEqual(received.get(timeout=3).text, "x\n")
                    self.assertGreaterEqual(opens, 3)
                finally:
                    self.end_watcher(stop, thread)

    def test_follow_does_not_merge_unterminated_old_record_into_replacement(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.log"
            path.write_text("first\npartial-old")
            stop, received, thread = self.watcher(path)
            try:
                self.assertEqual(received.get(timeout=3).text, "first\n")
                with self.assertRaises(queue.Empty):
                    received.get(timeout=0.05)
                path.rename(Path(folder) / "old.log")
                path.write_text("fresh\n")
                self.assertIn("rotated", received.get(timeout=3).issue)
                self.assertEqual(received.get(timeout=3).text, "fresh\n")
            finally:
                self.end_watcher(stop, thread)

    def test_terminal_output_removes_all_control_classes(self):
        controls = "".join(chr(value) for value in list(range(32)) + list(range(127, 160)))
        controls += "\u202e\u2066\u200b\ufeff"
        self.assertEqual(safe(controls), "?" * len(controls))
        self.assertEqual(safe("Readable é / 123"), "Readable é / 123")

    def test_dashboard_clips_and_sanitizes_text(self):
        written = []
        screen = SimpleNamespace(getmaxyx=lambda: (18, 72), addnstr=lambda *args: written.append(args))
        dashboard = Dashboard(SimpleNamespace(), "Fixture")
        dashboard.screen = screen
        dashboard.curses = SimpleNamespace(error=RuntimeError)
        dashboard._put(-1, 0, "hidden")
        dashboard._put(18, 0, "hidden")
        dashboard._put(0, 71, "hidden")
        dashboard._put(0, 1, "\x1b[2Jpayload")
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0], (0, 1, "?[2Jpayload", 70, 0))

    def test_terminal_initialization_error_becomes_readable_error(self):
        class TerminalError(Exception):
            pass
        def broken_wrapper(*_):
            raise TerminalError("setupterm failed")
        fake = SimpleNamespace(error=TerminalError, wrapper=broken_wrapper)
        with patch.dict(sys.modules, {"curses": fake}):
            with self.assertRaisesRegex(ValueError, "plain"):
                Dashboard(SimpleNamespace(), "Fixture").run(lambda: None)

    @unittest.skipUnless(os.name == "posix", "Live interruption requires POSIX signals")
    def test_live_watch_process_correlates_append_rotation_and_persists(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            database = Path(folder) / "alerts.db"
            def event(number, user="operator"):
                return json.dumps({"ts": 100 + number, "kind": "auth", "src": "192.0.2.1",
                                   "dst": "198.51.100.2", "service": "ssh", "user": user,
                                   "outcome": "failure"}) + "\n"
            path.write_text("".join(event(number) for number in range(7)))
            process = subprocess.Popen([sys.executable, "-m", "excubitor", "watch", "-i", str(path),
                                        "--from-start", "--jsonl", "--db", str(database)], cwd=ROOT,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            def read_alert():
                self.assertTrue(selector.select(timeout=5), "No live alert arrived")
                line = process.stdout.readline()
                self.assertTrue(line, "Live process ended before producing an alert")
                return json.loads(line)
            try:
                with path.open("a") as output:
                    output.write(event(7))
                first = read_alert()
                self.assertEqual(first["rule"], "auth_bruteforce")
                path.rename(Path(folder) / "old.jsonl")
                path.write_text("".join(event(number, "visitor") for number in range(10, 18)))
                second = read_alert()
                self.assertEqual(second["rule"], "auth_bruteforce")
                self.assertNotEqual(first["id"], second["id"])
                process.send_signal(signal.SIGINT)
                remaining, errors = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, errors)
                self.assertEqual(remaining, b"")
                summary = json.loads(errors.splitlines()[0])
                self.assertEqual(summary["engine"]["accepted_events"], 16)
                self.assertEqual(summary["engine"]["alerts"], 2)
                self.assertEqual(summary["input_errors"], 0)
                store = Store(str(database))
                try:
                    self.assertEqual(len(store.list()), 2)
                finally:
                    store.close()
            finally:
                selector.close()
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
