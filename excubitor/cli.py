"""Unum imperium, plures fontes, iudicium humanum."""
from __future__ import annotations
import argparse
from collections import deque
from dataclasses import asdict
import heapq
import json
import os
from pathlib import Path
import queue
import sqlite3
import sys
import threading
import time
from .config import TEMPLATE, load_config
from .demo import demo_events
from .engine import Engine, RULES
from .ingest import follow, records
from .model import VERSION
from .parsers import FORMATS, ParseError, parse_line
from .storage import Store, exclusive_write, serialize
from .terminal import Dashboard, alert_line, safe


class Session:
    def __init__(self, engine, store=None, jsonl=False, plain=False):
        self.engine = engine
        self.store = store
        self.alerts = deque(maxlen=1000)
        self.errors = 0
        self.skipped = 0
        self.note = ""
        self.done = False
        self.cancelled = False
        self.jsonl = jsonl
        self.plain = plain

    def accept(self, event):
        for alert in self.engine.feed(event):
            if self.store:
                self.store.add(alert)
            item = alert.to_dict()
            item["acknowledged"] = False
            self.alerts.append(item)
            if self.jsonl:
                print(json.dumps(item, ensure_ascii=True, sort_keys=True), flush=True)
            elif self.plain:
                print(alert_line(item), flush=True)

    def parse(self, record, format, year):
        if record.issue:
            self.note = safe(f"{record.source}:{record.number}: {record.issue}")
            if "rotated or truncated" not in record.issue:
                self.errors += 1
            return []
        try:
            events = parse_line(record.text, format=format, source=record.source, year=year)
            if not events and record.text.strip():
                self.skipped += 1
            return events
        except (ParseError, ValueError, OverflowError, RecursionError):
            self.errors += 1
            self.note = safe(f"{record.source}:{record.number}: invalid or unsupported record")
            return []


def parsed_file(path, session, format, year):
    if path == "-":
        for record in records(sys.stdin.buffer, "stdin"):
            yield from session.parse(record, format, year)
        return
    with open(path, "rb") as stream:
        for record in records(stream, path):
            yield from session.parse(record, format, year)


def run_stream(args, session):
    stop = threading.Event()
    pending = queue.Queue(maxsize=2048)
    workers = []
    def enqueue(item):
        while not stop.is_set():
            try:
                pending.put(item, timeout=0.1)
                return
            except queue.Full:
                continue
    def worker(path):
        try:
            for record in follow(path, stop, args.from_start):
                enqueue(record)
        except Exception:
            # Error externus sine datis secretis refertur.
            enqueue(RuntimeError("Input reader stopped unexpectedly"))
    for path in args.input:
        thread = threading.Thread(target=worker, args=(path,), daemon=True)
        thread.start()
        workers.append(thread)
    def pump():
        for _ in range(500):
            try:
                record = pending.get_nowait()
            except queue.Empty:
                break
            if isinstance(record, Exception):
                session.errors += 1
                session.note = str(record)
                continue
            for event in session.parse(record, args.format, args.year):
                if event.ts > time.time() + 300:
                    session.errors += 1
                    session.note = "Future timestamp rejected (more than 300 seconds ahead of local clock)"
                    continue
                session.accept(event)
    try:
        if session.plain or session.jsonl:
            while True:
                pump()
                time.sleep(0.05)
        else:
            Dashboard(session, f"LIVE / {len(args.input)} input(s)").run(pump)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        for thread in workers:
            thread.join(timeout=1)


def run_replay(args, session):
    if args.command == "demo":
        events = iter(demo_events())
    else:
        # Fontes singuli ordine temporis praebendi sunt.
        streams = [parsed_file(path, session, args.format, args.year) for path in args.input]
        events = heapq.merge(*streams, key=lambda event: event.ts)
    if session.plain or session.jsonl:
        for event in events:
            session.accept(event)
        session.done = True
    else:
        last = 0.0
        def pump():
            nonlocal last
            if session.done or time.monotonic() < last + args.delay:
                return
            last = time.monotonic()
            for _ in range(1 if args.delay else 300):
                try:
                    session.accept(next(events))
                except StopIteration:
                    session.done = True
                    break
        try:
            Dashboard(session, "SYNTHETIC DEMO" if args.command == "demo" else "FILE REPLAY").run(pump)
        finally:
            if not session.done:
                session.cancelled = True
            if hasattr(events, "close"):
                events.close()


def parser():
    result = argparse.ArgumentParser(prog="excubitor", description="Terminal-first scan and authentication threat correlation. Read-only, local, explainable.")
    result.add_argument("--version", action="version", version=VERSION)
    sub = result.add_subparsers(dest="command", required=True)
    for name, help_text in (("demo", "Run a synthetic scenario; no network traffic"), ("analyze", "Replay saved logs in event-time order"), ("watch", "Follow live logs with rotation detection")):
        p = sub.add_parser(name, help=help_text)
        if name != "demo":
            p.add_argument("-i", "--input", action="append", required=True, help="Input file, repeat for multiple sources; analyze accepts - for stdin")
            p.add_argument("--format", choices=FORMATS, default="auto")
            p.add_argument("--year", type=int, help="Explicit UTC year for traditional syslog timestamps")
        p.add_argument("--config", help="TOML configuration")
        p.add_argument("--db", help="Persist every alert to a local SQLite database")
        mode = p.add_mutually_exclusive_group()
        mode.add_argument("--plain", action="store_true", help="Readable line output")
        mode.add_argument("--jsonl", action="store_true", help="Stream every alert as JSON Lines to stdout")
        mode.add_argument("--tui", action="store_true", help="Interactive monochrome terminal")
        p.add_argument("--output", help="Export up to 1000 retained alerts to a new file; never overwrites")
        p.add_argument("--output-format", choices=("json", "jsonl", "csv"), default="json")
        p.add_argument("--fail-on-alert", action="store_true", help="Exit 1 if any alert was raised")
        if name == "watch":
            p.add_argument("--from-start", action="store_true", help="Read existing content before following; default starts at EOF")
        else:
            p.add_argument("--delay", type=float, default=0.05 if name == "demo" else 0, help="Seconds per event in interactive replay (0..10)")
    sub.add_parser("rules", help="List all detection rules")
    p = sub.add_parser("config", help="Print a starter configuration or validate one")
    p.add_argument("--check", metavar="FILE")
    p = sub.add_parser("history", help="Query stored alerts or export them")
    p.add_argument("--db", required=True)
    p.add_argument("--limit", type=int, default=1000)
    p.add_argument("--rule", choices=tuple(RULES))
    p.add_argument("--output")
    p.add_argument("--output-format", choices=("json", "jsonl", "csv"), default="json")
    p.add_argument("--ack", metavar="ALERT_ID", help="Acknowledge a stored alert")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    store = None
    try:
        if args.command == "rules":
            for rule, info in RULES.items():
                print(safe(f"{rule:26} {info}"))
            return 0
        if args.command == "config":
            if args.check:
                Engine(load_config(args.check))
                print("Configuration valid")
            else:
                print(TEMPLATE, end="")
            return 0
        if args.command == "history":
            if not Path(args.db).is_file():
                raise ValueError("History database does not exist")
            store = Store(args.db)
            if args.ack:
                store.acknowledge(args.ack)
            items = store.list(args.limit, args.rule)
            text = serialize(items, args.output_format)
            if args.output:
                exclusive_write(args.output, text)
            else:
                print(text, end="")
            return 0
        engine = Engine(load_config(args.config))
        if hasattr(args, "delay") and not 0 <= args.delay <= 10:
            raise ValueError("Delay must be between 0 and 10 seconds")
        if getattr(args, "year", None) is not None and not 1970 <= args.year <= 9998:
            raise ValueError("Year must be between 1970 and 9998")
        if args.command != "demo":
            if len(set(args.input)) != len(args.input):
                raise ValueError("Duplicate input paths are not allowed")
            if args.command == "watch" and "-" in args.input:
                raise ValueError("Use analyze -i - for streamed stdin")
            identities = set()
            for path in args.input:
                if path != "-" and not Path(path).is_file():
                    raise ValueError("Each input must be an existing regular file")
                if path != "-":
                    info = Path(path).stat()
                    identity = (info.st_dev, info.st_ino)
                    if identity in identities:
                        raise ValueError("Input aliases refer to the same file")
                    identities.add(identity)
                if path != "-" and args.db and Path(path).resolve() == Path(args.db).resolve():
                    raise ValueError("Database cannot be an input file")
            if args.db and Path(args.db).exists():
                info = Path(args.db).stat()
                if (info.st_dev, info.st_ino) in identities:
                    raise ValueError("Database cannot alias an input file")
        if args.output and Path(args.output).exists():
            raise ValueError("Output already exists; choose a new path")
        if args.tui and (not sys.stdout.isatty() or not sys.stdin.isatty()):
            raise ValueError("Interactive mode requires a terminal")
        plain = args.plain or (not args.tui and (args.command == "analyze" or not sys.stdout.isatty()))
        if args.db:
            store = Store(args.db)
        session = Session(engine, store, args.jsonl, plain)
        if args.command == "watch":
            run_stream(args, session)
        else:
            run_replay(args, session)
        if args.output:
            exclusive_write(args.output, serialize(list(session.alerts), args.output_format))
        summary = {"engine": dict(engine.stats), "input_errors": session.errors, "skipped_records": session.skipped, "retained_alerts": len(session.alerts), "replay_cancelled": session.cancelled}
        print(json.dumps(summary, ensure_ascii=True, sort_keys=True), file=sys.stderr)
        if session.note and session.errors:
            print(safe(session.note), file=sys.stderr)
        if session.errors or engine.stats.get("late_events", 0) or engine.stats.get("invalid_events", 0):
            return 2
        if session.cancelled:
            return 130
        if args.fail_on_alert and engine.stats.get("alerts", 0):
            return 1
        return 0
    except KeyboardInterrupt:
        return 130
    except (OSError, ValueError, TypeError, RuntimeError, sqlite3.Error) as exc:
        print("excubitor: " + safe(exc), file=sys.stderr)
        return 2
    finally:
        if store:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
