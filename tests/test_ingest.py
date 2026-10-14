"""Limites, lineae fractae et rotatio probantur."""
import io
from pathlib import Path
import queue
import tempfile
import threading
import unittest
from excubitor.ingest import follow, records


class IngestTests(unittest.TestCase):
    def test_oversize_drained_once_and_next_line_preserved(self):
        result = list(records(io.BytesIO(b"x" * 400 + b"\ngood\n"), "sample", limit=32))
        self.assertEqual(len(result), 2)
        self.assertTrue(result[0].issue)
        self.assertEqual(result[1].text, "good\n")
        self.assertEqual(result[1].number, 2)

    def test_invalid_utf8_and_final_unterminated_record(self):
        result = list(records(io.BytesIO(b"\xff\ngood"), "sample"))
        self.assertTrue(result[0].issue)
        self.assertEqual(result[1].text, "good")

    def test_follow_partial_rotation_and_truncation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.log"
            path.write_bytes(b"first\n")
            stop = threading.Event()
            received = queue.Queue()
            def work():
                for item in follow(str(path), stop, from_start=True, poll=0.01):
                    received.put(item)
            thread = threading.Thread(target=work)
            thread.start()
            try:
                self.assertEqual(received.get(timeout=3).text, "first\n")
                with path.open("ab") as out:
                    out.write(b"par")
                with self.assertRaises(queue.Empty):
                    received.get(timeout=0.08)
                with path.open("ab") as out:
                    out.write(b"tial\n")
                self.assertEqual(received.get(timeout=3).text, "partial\n")
                path.rename(Path(folder) / "old.log")
                path.write_bytes(b"rotated\n")
                self.assertIn("rotated", received.get(timeout=3).issue)
                self.assertEqual(received.get(timeout=3).text, "rotated\n")
                path.write_bytes(b"x\n")
                self.assertIn("truncated", received.get(timeout=3).issue)
                self.assertEqual(received.get(timeout=3).text, "x\n")
            finally:
                stop.set()
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
