"""Lineae finitae; rotatio sine memoria infinita."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import os
import stat
import threading
from typing import BinaryIO, Iterator

MAX_LINE = 262144


@dataclass(frozen=True)
class Record:
    text: str
    source: str
    number: int
    issue: str = ""


def records(stream: BinaryIO, source: str, limit: int = MAX_LINE) -> Iterator[Record]:
    number = 0
    while True:
        chunk = stream.readline(limit + 1)
        if not chunk:
            return
        number += 1
        if len(chunk) > limit:
            while chunk and not chunk.endswith(b"\n"):
                chunk = stream.readline(limit + 1)
            yield Record("", source, number, "record exceeds byte limit")
            continue
        try:
            yield Record(chunk.decode("utf-8"), source, number)
        except UnicodeDecodeError:
            yield Record("", source, number, "record is not valid UTF-8")


def follow(path: str, stop: threading.Event, from_start: bool = False,
           limit: int = MAX_LINE, poll: float = 0.15) -> Iterator[Record]:
    source = str(Path(path))
    first = True
    stream = None
    identity = None
    pending = b""
    oversized = False
    number = 0
    missing_reported = False
    try:
        while not stop.is_set():
            try:
                info = os.stat(path)
                if not stat.S_ISREG(info.st_mode):
                    yield Record("", source, number, "watch requires a regular file")
                    return
                next_id = (info.st_dev, info.st_ino)
                changed = identity != next_id
                if stream is not None and changed and stream.tell() < os.fstat(stream.fileno()).st_size:
                    changed = False
                truncated = stream is not None and not changed and info.st_size < stream.tell()
                if identity != next_id:
                    truncated = False
                if stream is None or changed or truncated:
                    if stream:
                        stream.close()
                        stream = None
                        yield Record("", source, number, "input rotated or truncated; reopening")
                    stream = open(path, "rb")
                    identity = next_id
                    pending = b""
                    oversized = False
                    number = 0
                    if first and not from_start:
                        stream.seek(0, os.SEEK_END)
                    first = False
                missing_reported = False
                data = stream.read(65536)
                if not data:
                    stop.wait(poll)
                    continue
                for part in data.splitlines(keepends=True):
                    complete = part.endswith(b"\n")
                    if not oversized:
                        if len(pending) + len(part) > limit:
                            pending = b""
                            oversized = True
                        else:
                            pending += part
                    if complete:
                        number += 1
                        if oversized:
                            yield Record("", source, number, "record exceeds byte limit")
                        else:
                            try:
                                yield Record(pending.decode("utf-8"), source, number)
                            except UnicodeDecodeError:
                                yield Record("", source, number, "record is not valid UTF-8")
                        pending = b""
                        oversized = False
            except (OSError, ValueError):
                if not missing_reported:
                    yield Record("", source, number, "input unavailable; retrying")
                    missing_reported = True
                stop.wait(poll)
    finally:
        if stream:
            stream.close()
