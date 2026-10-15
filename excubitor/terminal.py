"""Textus externus numquam imperium terminalis fit."""
from __future__ import annotations
import json
import time
import unicodedata
from .model import VERSION, iso_time
from .storage import exclusive_write, serialize


def safe(value: object) -> str:
    text = str(value)
    return "".join(c if (c.isprintable() and not unicodedata.category(c).startswith("C")) else "?" for c in text)


def alert_line(item: dict) -> str:
    return safe(f"{iso_time(item['ts'])}  {item['severity'].upper():8} {item['rule']:25} {item['src']} -> {item['dst'] or '-'}  {item['summary']}")


def column(value: object, width: int) -> str:
    text = safe(value)
    return (text if len(text) <= width else text[:width - 1] + "~").ljust(width)


class Dashboard:
    def __init__(self, session, title: str):
        self.session = session
        self.title = title
        self.selected = 0
        self.filter = ""
        self.severity = False
        self.unacknowledged = False
        self.priority_sort = False
        self.details = False
        self.detail_offset = 0
        self.paused = False
        self.frozen = []
        self.message = ""

    def run(self, pump) -> None:
        try:
            import curses
        except ImportError as exc:
            raise ValueError("Interactive mode needs curses; use --plain on this platform") from exc
        self.curses = curses
        try:
            curses.wrapper(self._loop, pump)
        except curses.error as exc:
            raise ValueError("Terminal initialization or drawing failed; use --plain or a supported TERM") from exc

    def _put(self, y: int, x: int, text: str, style: int = 0) -> None:
        rows, columns = self.screen.getmaxyx()
        if 0 <= y < rows and 0 <= x < columns - 1:
            try:
                self.screen.addnstr(y, x, safe(text), columns - x - 1, style)
            except self.curses.error:
                pass

    def _visible(self):
        items = self.frozen if self.paused else list(reversed(self.session.alerts))
        items = [a for a in items if (not self.severity or a["severity"] in {"high", "critical"})
                 and (not self.unacknowledged or not a.get("acknowledged"))
                 and self.filter.casefold() in json.dumps(a).casefold()]
        if self.priority_sort:
            levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            items = sorted(items, key=lambda a: (levels.get(a["severity"], 0), a["ts"], a["id"]), reverse=True)
        return items

    def _loop(self, screen, pump) -> None:
        self.screen = screen
        self.pump = pump
        c = self.curses
        try:
            c.curs_set(0)
        except c.error:
            pass
        screen.nodelay(True)
        screen.keypad(True)
        while True:
            pump()
            items = self._visible()
            self.selected = min(self.selected, max(0, len(items) - 1))
            self._draw(items)
            key = screen.getch()
            if key in (ord("q"), 27):
                if self.details:
                    self.details = False
                else:
                    return
            elif key in (ord("j"), c.KEY_DOWN):
                if self.details:
                    self.detail_offset = min(self.detail_offset + 1, 200)
                else:
                    self.selected = min(self.selected + 1, max(0, len(items) - 1))
            elif key in (ord("k"), c.KEY_UP):
                if self.details:
                    self.detail_offset = max(0, self.detail_offset - 1)
                else:
                    self.selected = max(0, self.selected - 1)
            elif key in (10, 13):
                self.details = not self.details
                self.detail_offset = 0
            elif key == ord("h"):
                self.severity = not self.severity
                self.selected = 0
            elif key == ord("p"):
                self.paused = not self.paused
                if self.paused:
                    self.frozen = list(reversed(self.session.alerts))
            elif key == ord("u"):
                self.unacknowledged = not self.unacknowledged
                self.selected = 0
                self.message = "Showing unacknowledged alerts" if self.unacknowledged else "Showing all acknowledgements"
            elif key == ord("s"):
                self.priority_sort = not self.priority_sort
                self.selected = 0
                self.message = "Sorted by severity, then newest" if self.priority_sort else "Sorted newest first"
            elif key == ord("/"):
                self.filter = self._prompt("Filter (empty clears): ")
                self.selected = 0
            elif key == ord("a") and items:
                item = items[self.selected]
                item["acknowledged"] = not item.get("acknowledged", False)
                if self.session.store:
                    self.session.store.acknowledge(item["id"], item["acknowledged"])
                self.message = "Acknowledgement saved" if self.session.store else "Acknowledgement kept for this session"
            elif key == ord("e"):
                name = f"excubitor-alerts-{time.time_ns()}.json"
                try:
                    exclusive_write(name, serialize(list(self.session.alerts)))
                    self.message = f"Exported {len(self.session.alerts)} retained alerts: {name}"
                except OSError:
                    self.message = "Export failed: destination is not writable"
            time.sleep(0.05)

    def _prompt(self, label: str) -> str:
        # Lectio pergit dum operator quaerit.
        text = ""
        while True:
            self.pump()
            rows, _ = self.screen.getmaxyx()
            self._put(rows - 2, 1, " " * 300)
            self._put(rows - 2, 1, label + text, self.curses.A_BOLD)
            self.screen.refresh()
            key = self.screen.getch()
            if key in (10, 13):
                return text
            if key == 27:
                return self.filter
            if key in (127, 8, self.curses.KEY_BACKSPACE):
                text = text[:-1]
            elif 32 <= key < 127 and len(text) < 80:
                text += chr(key)
            time.sleep(0.03)

    def _draw(self, items) -> None:
        screen, c = self.screen, self.curses
        screen.erase()
        height, width = screen.getmaxyx()
        if height < 18 or width < 72:
            self._put(0, 0, "EXCUBITOR | Resize to at least 72 x 18. q exits.", c.A_BOLD)
            screen.refresh()
            return
        heading = f"E X C U B I T O R   /   {VERSION}"
        self._put(1, max(1, (width - len(heading)) // 2), heading, c.A_BOLD)
        state = "COMPLETE" if self.session.done else "OBSERVING"
        if self.paused:
            state += " / DISPLAY PAUSED"
        self._put(3, 2, f"{state}  |  {self.title}", c.A_BOLD)
        stats = self.session.engine.stats
        self._put(4, 2, f"EVENTS {stats.get('accepted_events', 0):,}   ALERTS {stats.get('alerts', 0):,}   INPUT ERRORS {self.session.errors:,}   LATE {stats.get('late_events', 0):,}")
        self._put(5, 2, f"STATE {self.session.engine.state_size:,} keys   EVICTED {stats.get('keys_evicted', 0) + stats.get('events_evicted', 0):,}   RETAINED {len(self.session.alerts):,}   FILTER {self.filter or '*'}{' / HIGH+' if self.severity else ''}")
        self._put(7, 1, " " * (width - 3), c.A_REVERSE)
        rule_width = min(26, max(16, width - 58))
        address_width = max(10, (width - 27 - rule_width) // 2)
        self._put(7, 2, f" UTC      LEVEL     {column('RULE', rule_width)} {column('SOURCE', address_width)} TARGET", c.A_REVERSE | c.A_BOLD)
        if self.details and items:
            item = items[self.selected]
            content = [f"{item['rule']} / {item['severity'].upper()} / {item['id']}", item["summary"], "", "NEXT: " + item["recommendation"], "", "EVIDENCE (j/k scroll)"]
            for k, v in item["evidence"].items():
                content.append(f"{k}: {json.dumps(v, ensure_ascii=True)}")
            import textwrap
            wrapped = [line for part in content for line in (textwrap.wrap(safe(part), width - 6) or [""])]
            self.detail_offset = min(self.detail_offset, max(0, len(wrapped) - (height - 13)))
            for i, line in enumerate(wrapped[self.detail_offset:self.detail_offset + height - 13]):
                self._put(9 + i, 3, line, c.A_BOLD if i == 0 else 0)
        else:
            visible_height = height - 13
            start = max(0, self.selected - visible_height + 1)
            for row, item in enumerate(items[start:start + visible_height], 9):
                selected = row - 9 + start == self.selected
                mark = "+" if item.get("acknowledged") else " "
                text = f"{mark}{iso_time(item['ts'])[11:19]} {item['severity'].upper():9.9} {column(item['rule'], rule_width)} {column(item['src'], address_width)} {column(item['dst'], address_width)}"
                self._put(row, 2, text, (c.A_REVERSE if selected else 0) | (c.A_BOLD if item["severity"] in {"high", "critical"} else 0))
            if not items:
                self._put(10, 3, "No matching alerts. Detection continues.")
        self._put(height - 3, 2, self.message or self.session.note or "Vigilantia ex indiciis.  /  An alert is a lead; verify the evidence.")
        self._put(height - 2, 2, "j/k move  Enter detail  / find  h high  u unacked  s sort  p pause  a ack  e export  q quit", c.A_BOLD)
        screen.refresh()
