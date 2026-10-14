"""Formae, fines et ignorantia explicita examinantur."""
import json
import unittest
from datetime import datetime, timezone

from excubitor.engine import Engine
from excubitor.model import Config
from excubitor.parsers import FORMATS, MAX_LINE_LENGTH, ParseError, parse_line


class ParserTests(unittest.TestCase):
    def native(self, **changes):
        return {"ts": 1_760_000_000, "kind": "conn", "src": "192.0.2.1", "dst": "198.51.100.2", "port": 443} | changes

    def eve(self, event_type="flow", **changes):
        return {"timestamp": "2026-10-15T12:30:40+0000", "event_type": event_type,
                "src_ip": "192.0.2.1", "dest_ip": "198.51.100.2", "dest_port": 443,
                "proto": "TCP", event_type: {}} | changes

    def zeek(self, **changes):
        return {"ts": 1_760_000_000, "uid": "Csample", "id.orig_h": "192.0.2.1", "id.orig_p": 40000,
                "id.resp_h": "198.51.100.2", "id.resp_p": 22, "proto": "tcp", "conn_state": "S0"} | changes

    def parse(self, record, **kwargs):
        return parse_line(json.dumps(record), **kwargs)

    def test_supported_formats_and_whitespace(self):
        self.assertEqual(FORMATS, ("auto", "native", "eve", "zeek", "auth"))
        for line in ("", " \n ", "#fields\tts\tid.orig_h"):
            self.assertEqual(parse_line(line), [])

    def test_native_round_trip_and_ipv6(self):
        event = self.parse(self.native(src="2001:0DB8:0:0::1", proto="UDP", source="untrusted", event_id="event-42"), source="input.jsonl")[0]
        self.assertEqual((event.src, event.proto, event.source, event.event_id), ("2001:db8::1", "udp", "input.jsonl", "event-42"))

    def test_native_aware_timestamp(self):
        first = self.parse(self.native(ts="2026-10-15T12:30:40+02:00"))[0]
        second = self.parse(self.native(ts="2026-10-15T10:30:40Z"))[0]
        self.assertEqual(first.ts, second.ts)

    def test_nonfinite_and_ambiguous_timestamps_rejected(self):
        for timestamp in (True, None, [], "2026-10-15T12:30:40", "yesterday", float("inf"), float("nan"), 1e300, -1):
            with self.subTest(timestamp=timestamp), self.assertRaises(ParseError):
                self.parse(self.native(ts=timestamp))

    def test_required_and_bounded_native_fields(self):
        for key in ("ts", "src", "kind"):
            data = self.native()
            del data[key]
            with self.subTest(key=key), self.assertRaises(ParseError):
                self.parse(data)
        for changes in ({"src": "256.0.0.1"}, {"src": "host.test"}, {"src": "fe80::1%eth0"},
                        {"dst": "host.test"}, {"port": True}, {"port": "443"}, {"port": 65536},
                        {"port": -1}, {"status": 99}, {"status": 600}, {"kind": "anything"},
                        {"user": "a" * 257}, {"severity": "urgent"}, {"user": "bad\x1b[2J"},
                        {"user": "bad\u202etext"}):
            with self.subTest(changes=changes), self.assertRaises(ParseError):
                self.parse(self.native(**changes))

    def test_native_auth_requires_explicit_outcome(self):
        for outcome in ("", "unknown", "failed", False):
            with self.subTest(outcome=outcome), self.assertRaises(ParseError):
                self.parse(self.native(kind="auth", outcome=outcome))
        event = self.parse(self.native(kind="auth", outcome="failure", dst="SERVER.Example."))[0]
        self.assertEqual(event.dst, "server.example")

    def test_native_target_required_except_upstream_alert(self):
        for kind in ("conn", "auth", "http"):
            with self.subTest(kind=kind), self.assertRaises(ParseError):
                self.parse(self.native(kind=kind, dst="", outcome="failure"))
        self.assertEqual(self.parse(self.native(kind="alert", dst="", signature="Synthetic"))[0].dst, "")

    def test_paths_strip_query_fragment_authority_and_credentials(self):
        for target in ("/login?token=secret#fragment", "https://user:secret@example.test/login?key=secret#part"):
            event = self.parse(self.native(kind="http", path=target, password="secret", authorization="secret"))[0]
            self.assertEqual(event.path, "/login")
            self.assertNotIn("secret", repr(event))
        with self.assertRaises(ParseError):
            self.parse(self.native(path="https://[invalid/path"))
        with self.assertRaises(ParseError):
            self.parse(self.native(path="/" + "a" * 2048))

    def test_eve_flow_and_netflow(self):
        for event_type in ("flow", "netflow"):
            event = self.parse(self.eve(event_type, flow_id=1234))[0]
            self.assertEqual((event.kind, event.port, event.proto), ("conn", 443, "tcp"))
            self.assertEqual(event.event_id, "")

    def test_eve_http(self):
        event = self.parse(self.eve("http", http={"url": "/admin?key=secret", "status": 403}))[0]
        self.assertEqual((event.kind, event.path, event.status, event.service), ("http", "/admin", 403, "http"))

    def test_eve_alert_prefers_flow_direction(self):
        event = self.parse(self.eve("alert", alert={"signature": "Synthetic alert", "signature_id": 42, "severity": 1},
                                   flow={"src_ip": "198.51.100.2", "dest_ip": "192.0.2.1", "dest_port": 80}))[0]
        self.assertEqual((event.kind, event.src, event.dst, event.port, event.severity),
                         ("alert", "198.51.100.2", "192.0.2.1", 80, "high"))

    def test_eve_alert_direction_does_not_mix_partial_addresses(self):
        with self.assertRaises(ParseError):
            self.parse(self.eve("alert", alert={"signature": "Synthetic alert"}, flow={"src_ip": "198.51.100.2"}))
        event = self.parse(self.eve("alert", alert={"signature": "Synthetic alert"},
                                   flow={"src_ip": "198.51.100.2", "dest_ip": "192.0.2.1"}))[0]
        self.assertEqual(event.port, 0)

    def test_eve_ssh_metadata_never_becomes_auth(self):
        self.assertEqual(self.parse(self.eve("ssh", ssh={"client": {"proto_version": "2.0"}})), [])
        self.assertEqual(self.parse({"event_type": "stats"}), [])

    def test_malformed_eve_rejected(self):
        for data in (self.eve(src_ip="bad"), self.eve(flow=[]), self.eve("http", http={"status": "403"}),
                     self.eve("alert", alert={}), self.eve(dest_port=False)):
            with self.subTest(data=data), self.assertRaises(ParseError):
                self.parse(data)

    def test_zeek_conn_and_http(self):
        conn = self.parse(self.zeek())[0]
        self.assertEqual((conn.kind, conn.port), ("conn", 22))
        http = self.parse(self.zeek(uri="/login?token=secret", status_code=404, trans_depth=2))[0]
        self.assertEqual((http.kind, http.path, http.status), ("http", "/login", 404))
        self.assertEqual((conn.event_id, http.event_id), ("", ""))

    def test_zeek_ssh_boolean_only(self):
        for success, outcome in ((True, "success"), (False, "failure")):
            result = self.parse(self.zeek(auth_success=success, auth_attempts=9))
            self.assertEqual(len(result), 1)
            self.assertEqual((result[0].kind, result[0].outcome, result[0].user), ("auth", outcome, ""))
        for success in ("false", 0, 1, None):
            with self.subTest(success=success), self.assertRaises(ParseError):
                self.parse(self.zeek(auth_success=success))

    def test_zeek_missing_auth_success_is_unknown(self):
        self.assertEqual(self.parse(self.zeek(auth_attempts=0)), [])
        self.assertEqual(self.parse(self.zeek(auth_attempts=9)), [])
        self.assertEqual(self.parse(self.zeek(_path="ssh")), [])
        self.assertEqual(self.parse(self.zeek(_path="dns", query="example.test")), [])

    def test_zeek_unknown_records_not_assumed_connections(self):
        data = self.zeek()
        del data["conn_state"]
        self.assertEqual(self.parse(data), [])
        event = self.parse(data | {"_path": "conn"})[0]
        self.assertEqual(event.kind, "conn")

    def test_zeek_invalid_fields(self):
        for changes in ({"id.orig_h": "not-an-ip"}, {"id.resp_p": "22"}, {"ts": float("inf")},
                        {"uri": "/", "status_code": 1}):
            with self.subTest(changes=changes), self.assertRaises(ParseError):
                self.parse(self.zeek(**changes))

    def test_auth_iso_and_ipv6(self):
        line = "2026-10-15T12:30:40+02:00 server.example sshd[123]: Failed password for invalid user visitor from 2001:0db8::1 port 34567 ssh2"
        event = parse_line(line, source="auth.log")[0]
        self.assertEqual((event.kind, event.src, event.dst, event.port, event.user, event.outcome, event.source),
                         ("auth", "2001:db8::1", "server.example", 0, "visitor", "failure", "auth.log"))
        self.assertEqual(event.ts, datetime(2026, 10, 15, 10, 30, 40, tzinfo=timezone.utc).timestamp())

    def test_auth_traditional_requires_year_and_uses_utc(self):
        line = "Oct  5 12:30:40 server sshd[123]: Accepted publickey for operator from 192.0.2.1 port 34567 ssh2: ED25519 SHA256:test"
        with self.assertRaisesRegex(ParseError, "explicit year"):
            parse_line(line)
        event = parse_line(line, year=2026)[0]
        self.assertEqual(event.outcome, "success")
        self.assertEqual(event.ts, datetime(2026, 10, 5, 12, 30, 40, tzinfo=timezone.utc).timestamp())
        for year in (True, 0, 1969, 10000, "2026"):
            with self.subTest(year=year), self.assertRaises(ParseError):
                parse_line(line, year=year)

    def test_auth_ignores_unrelated_syslog_and_sshd_records(self):
        for line in ("Oct 15 12:30:40 server cron[42]: Job completed",
                     "Oct 15 12:30:40 server sshd[42]: Connection closed by 192.0.2.1 port 12345 [preauth]"):
            self.assertEqual(parse_line(line), [])

    def test_auth_session_daemon_and_keyboard_interactive(self):
        line = "<38>2026-10-15T12:30:40Z server sshd-session[123]: Accepted keyboard-interactive/pam for operator from 192.0.2.1 port 34567 ssh2"
        self.assertEqual(parse_line(line)[0].outcome, "success")
        self.assertEqual(parse_line(line)[0].port, 0)

    def test_auth_malformed_recognized_records_rejected(self):
        for line in ("Oct 32 12:30:40 server sshd[42]: Failed password for operator from 192.0.2.1 port 12345 ssh2",
                     "Oct 15 12:30:40 server sshd[42]: Failed password for operator from bad-ip port 12345 ssh2",
                     "Oct 15 12:30:40 server sshd[42]: Failed password for operator from 192.0.2.1 port 99999 ssh2",
                     "Oct 15 12:30:40 server sshd[42]: Failed password missing fields"):
            with self.subTest(line=line), self.assertRaises(ParseError):
                parse_line(line, year=2026)
        with self.assertRaises(ParseError):
            parse_line("Oct 15 12:30:40 server sshd[42]: Failed password for operator from 192.0.2.1 port " + "9" * 6000, year=2026)

    def test_malformed_json_unknown_text_arrays_and_large_lines(self):
        for line in ("{", "[]", "null", "just some text", "{\"random\":1}", "[" * 2000, "x" * (MAX_LINE_LENGTH + 1)):
            with self.subTest(prefix=line[:40]), self.assertRaises(ParseError):
                parse_line(line)
        with self.assertRaises(ParseError):
            parse_line("{}", format="unsupported")

    def test_explicit_format_and_no_error_payload_leaks(self):
        event = self.parse(self.native(), format="native")[0]
        self.assertEqual(event.kind, "conn")
        with self.assertRaises(ParseError) as caught:
            self.parse(self.native(src="sensitive-password-value"))
        self.assertNotIn("sensitive-password-value", str(caught.exception))
        with self.assertRaises(ParseError):
            self.parse(self.native(), format="zeek")

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(ParseError):
            parse_line('{"kind":"conn","kind":"auth","ts":1760000000,"src":"192.0.2.1"}')

    def engine(self):
        return Engine(Config(scan_ports=3, scan_hosts=3, auth_failures=3,
                             spray_users=3, distributed_sources=3, web_paths=3, web_denials=3))

    def feed_records(self, engine, records, **kwargs):
        alerts = []
        for record in records:
            for event in self.parse(record, **kwargs):
                alerts.extend(engine.feed(event))
        return alerts

    def test_native_to_engine_scan_threshold(self):
        engine = self.engine()
        first = self.feed_records(engine, [self.native(port=port, ts=100 + port) for port in (20, 21)])
        self.assertEqual(first, [])
        alerts = self.feed_records(engine, [self.native(port=22, ts=122)])
        self.assertEqual([alert.rule for alert in alerts], ["vertical_scan"])
        self.assertEqual(alerts[0].count, 3)

    def test_eve_to_engine_scan_threshold(self):
        engine = self.engine()
        records = [self.eve(dest_port=port, timestamp=f"2026-10-15T12:30:{port:02d}Z") for port in (20, 21, 22)]
        alerts = self.feed_records(engine, records)
        self.assertEqual([alert.rule for alert in alerts], ["vertical_scan"])
        self.assertEqual(engine.stats["accepted_events"], 3)

    def test_zeek_to_engine_horizontal_scan_threshold(self):
        engine = self.engine()
        records = [self.zeek(**{"ts": 100 + number, "id.resp_h": f"198.51.100.{number}"}) for number in (1, 2, 3)]
        alerts = self.feed_records(engine, records)
        self.assertEqual([alert.rule for alert in alerts], ["horizontal_scan"])
        self.assertEqual(alerts[0].count, 3)

    def test_auth_syslog_to_engine_failure_and_success(self):
        engine = self.engine()
        alerts = []
        for second, action in ((10, "Failed"), (11, "Failed"), (12, "Failed"), (13, "Accepted")):
            line = (f"2026-10-15T12:30:{second}Z server sshd[42]: {action} password "
                    "for operator from 192.0.2.1 port 34567 ssh2")
            for event in parse_line(line, source="auth.log"):
                alerts.extend(engine.feed(event))
        self.assertEqual([alert.rule for alert in alerts], ["auth_bruteforce", "auth_success_after_fail"])
        self.assertEqual([alert.count for alert in alerts], [3, 3])

    def test_unknown_ssh_observations_never_trigger_auth(self):
        engine = self.engine()
        records = [self.zeek(ts=100 + number, auth_attempts=20) for number in range(20)]
        records.extend(self.eve("ssh", ssh={"client": {"proto_version": "2.0"}}) for _ in range(20))
        self.assertEqual(self.feed_records(engine, records), [])
        self.assertEqual(engine.stats["accepted_events"], 0)

    def test_zeek_auth_observations_do_not_invent_account_or_attempts(self):
        engine = self.engine()
        records = [self.zeek(ts=100 + number, auth_success=False, auth_attempts=100) for number in range(3)]
        records.append(self.zeek(ts=104, auth_success=True))
        alerts = self.feed_records(engine, records)
        self.assertEqual([alert.rule for alert in alerts], ["auth_bruteforce"])
        self.assertEqual(alerts[0].count, 3)
        self.assertIn("unknown-account", alerts[0].summary)

    def test_http_to_engine_all_json_formats(self):
        for format in ("native", "eve", "zeek"):
            engine = self.engine()
            records = []
            for number in range(3):
                target = f"/missing-{number}?secret=discard"
                if format == "native":
                    records.append(self.native(kind="http", ts=100 + number, status=404, path=target))
                elif format == "eve":
                    records.append(self.eve("http", timestamp=f"2026-10-15T12:30:{number:02d}Z",
                                            http={"url": target, "status": 404}))
                else:
                    records.append(self.zeek(ts=100 + number, uri=target, status_code=404))
            alerts = self.feed_records(engine, records, format=format)
            with self.subTest(format=format):
                self.assertEqual([alert.rule for alert in alerts], ["web_path_scan"])
                self.assertNotIn("discard", repr(alerts))


if __name__ == "__main__":
    unittest.main()
