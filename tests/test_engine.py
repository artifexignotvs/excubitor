"""Probationes vigilum: fines, tempora, atque memoria."""
from dataclasses import replace
import unittest

from excubitor.engine import Engine, RULES
from excubitor.model import Config, Event


def settings(**changes):
    """Limina parva exemplis tribue."""
    base = Config(window=10, auth_window=20, cooldown=5, allowed_lateness=5,
                  scan_ports=3, scan_hosts=3, auth_failures=3, spray_users=3,
                  distributed_sources=3, web_paths=3, web_denials=3,
                  max_keys=100, max_events_per_key=50)
    return replace(base, **changes)


def connection(ts, port=22, src="192.0.2.10", dst="198.51.100.10", **kw):
    return Event(ts, "conn", src, dst, port=port, **kw)


def authentication(ts, outcome="failure", user="operator", src="192.0.2.10",
                   dst="198.51.100.10", service="ssh", **kw):
    return Event(ts, "auth", src, dst, user=user, outcome=outcome, service=service, **kw)


def request(ts, path="/private", status=404, **kw):
    return Event(ts, "http", "192.0.2.10", "198.51.100.10", path=path, status=status, **kw)


def by_rule(alerts, name):
    return [alert for alert in alerts if alert.rule == name]


class ScanTests(unittest.TestCase):
    def test_vertical_threshold_and_evidence(self):
        engine = Engine(settings())
        self.assertEqual(engine.feed(connection(0, 21)), [])
        self.assertEqual(engine.feed(connection(1, 22)), [])
        alerts = by_rule(engine.feed(connection(2, 23)), "vertical_scan")
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.count, 3)
        self.assertEqual(alert.first_seen, 0)
        self.assertEqual(alert.evidence["ports_sample"], [21, 22, 23])
        self.assertEqual(alert.evidence["window_start"], -8)
        self.assertEqual(alert.evidence["threshold"], 3)
        self.assertTrue(alert.recommendation)

    def test_repeated_port_is_not_distinct(self):
        engine = Engine(settings())
        for ts in range(10):
            self.assertEqual(engine.feed(connection(ts)), [])

    def test_separate_protocols_do_not_combine(self):
        engine = Engine(settings())
        engine.feed(connection(0, 21))
        engine.feed(connection(1, 22))
        self.assertEqual(engine.feed(connection(2, 23, proto="udp")), [])

    def test_separate_destinations_do_not_combine(self):
        engine = Engine(settings())
        engine.feed(connection(0, 21))
        engine.feed(connection(1, 22))
        self.assertEqual(engine.feed(connection(2, 23, dst="198.51.100.11")), [])

    def test_horizontal_scan(self):
        engine = Engine(settings())
        alerts = []
        for n in range(3):
            alerts += engine.feed(connection(n, dst=f"198.51.100.{n + 1}"))
        alert, = by_rule(alerts, "horizontal_scan")
        self.assertEqual(alert.count, 3)
        self.assertEqual(alert.dst, "multiple")
        self.assertEqual(alert.evidence["port"], 22)

    def test_horizontal_different_ports_do_not_combine(self):
        engine = Engine(settings())
        alerts = []
        for n in range(3):
            alerts += engine.feed(connection(n, n + 21, dst=f"198.51.100.{n + 1}"))
        self.assertEqual(alerts, [])

    def test_inclusive_left_edge(self):
        engine = Engine(settings())
        engine.feed(connection(0, 21))
        engine.feed(connection(1, 22))
        self.assertTrue(by_rule(engine.feed(connection(10, 23)), "vertical_scan"))

    def test_outside_left_edge(self):
        engine = Engine(settings())
        engine.feed(connection(0, 21))
        engine.feed(connection(1, 22))
        self.assertEqual(engine.feed(connection(10.001, 23)), [])

    def test_ipv6(self):
        engine = Engine(settings())
        alerts = []
        for n in range(3):
            alerts += engine.feed(connection(n, n + 21, src="2001:db8::1", dst="2001:db8:1::1"))
        self.assertEqual(by_rule(alerts, "vertical_scan")[0].src, "2001:db8::1")


class AuthenticationTests(unittest.TestCase):
    def test_bruteforce(self):
        engine = Engine(settings())
        alerts = []
        for ts in range(3):
            alerts += engine.feed(authentication(ts))
        alert, = by_rule(alerts, "auth_bruteforce")
        self.assertEqual(alert.count, 3)
        self.assertEqual(alert.evidence["service"], "ssh")

    def test_account_and_service_isolation(self):
        engine = Engine(settings())
        engine.feed(authentication(0))
        engine.feed(authentication(1))
        self.assertEqual(by_rule(engine.feed(authentication(2, service="vpn")), "auth_bruteforce"), [])
        self.assertEqual(by_rule(engine.feed(authentication(3, user="reader")), "auth_bruteforce"), [])

    def test_password_spray_distinct_users(self):
        engine = Engine(settings())
        alerts = []
        for ts, user in enumerate(("reader", "operator", "maintainer")):
            alerts += engine.feed(authentication(ts, user=user))
        alert, = by_rule(alerts, "password_spray")
        self.assertEqual(alert.count, 3)
        self.assertEqual(alert.evidence["users_sample"], ["maintainer", "operator", "reader"])

    def test_same_user_is_not_spray(self):
        engine = Engine(settings())
        alerts = []
        for ts in range(4):
            alerts += engine.feed(authentication(ts))
        self.assertEqual(by_rule(alerts, "password_spray"), [])

    def test_empty_user_not_spray_or_distributed(self):
        engine = Engine(settings())
        alerts = []
        for ts in range(3):
            alerts += engine.feed(authentication(ts, user="", src=f"192.0.2.{ts + 1}"))
        self.assertEqual(alerts, [])

    def test_distributed_failures(self):
        engine = Engine(settings())
        alerts = []
        for ts in range(3):
            alerts += engine.feed(authentication(ts, src=f"192.0.2.{ts + 1}"))
        alert, = by_rule(alerts, "distributed_auth")
        self.assertEqual(alert.src, "multiple")
        self.assertEqual(alert.count, 3)

    def test_success_after_failures(self):
        engine = Engine(settings())
        for ts in range(3):
            engine.feed(authentication(ts))
        alert, = by_rule(engine.feed(authentication(3, outcome="success")), "auth_success_after_fail")
        self.assertEqual(alert.evidence["prior_failures"], 3)
        self.assertEqual(alert.first_seen, 0)

    def test_unknown_account_never_asserts_success_correlation(self):
        engine = Engine(settings())
        alerts = []
        for ts in range(3):
            alerts += engine.feed(authentication(ts, user=""))
        alert, = by_rule(alerts, "auth_bruteforce")
        self.assertIn("unknown-account", alert.summary)
        self.assertFalse(alert.evidence["account_known"])
        self.assertEqual(engine.feed(authentication(3, user="", outcome="success")), [])

    def test_success_does_not_count_as_failure(self):
        engine = Engine(settings())
        for ts in range(2):
            engine.feed(authentication(ts))
        self.assertEqual(engine.feed(authentication(2, outcome="success")), [])
        self.assertEqual(engine.feed(authentication(3, outcome="success")), [])

    def test_success_does_not_count_future_failures(self):
        engine = Engine(settings(allowed_lateness=10))
        for ts in (10, 11, 20):
            engine.feed(authentication(ts))
        self.assertEqual(engine.feed(authentication(15, outcome="success")), [])
        engine.feed(authentication(14))
        alert, = by_rule(engine.feed(authentication(15, outcome="success")), "auth_success_after_fail")
        self.assertEqual(alert.count, 3)

    def test_no_retrospective_success_alert(self):
        engine = Engine(settings())
        self.assertEqual(engine.feed(authentication(15, outcome="success")), [])
        alerts = []
        for ts in (10, 11, 12):
            alerts += engine.feed(authentication(ts))
        self.assertEqual(by_rule(alerts, "auth_success_after_fail"), [])
        self.assertTrue(by_rule(engine.feed(authentication(16, outcome="success")), "auth_success_after_fail"))

    def test_success_rule_remains_when_bruteforce_disabled(self):
        engine = Engine(settings(disabled_rules=("auth_bruteforce",)))
        for ts in range(3):
            self.assertEqual(engine.feed(authentication(ts)), [])
        self.assertTrue(by_rule(engine.feed(authentication(3, outcome="success")), "auth_success_after_fail"))

    def test_auth_window_inclusive(self):
        engine = Engine(settings())
        engine.feed(authentication(0))
        engine.feed(authentication(1))
        engine.feed(authentication(2))
        self.assertTrue(by_rule(engine.feed(authentication(20, outcome="success")), "auth_success_after_fail"))
        self.assertEqual(engine.feed(authentication(20.1, outcome="success")), [])


class WebAndSensorTests(unittest.TestCase):
    def test_failed_path_scan(self):
        engine = Engine(settings())
        alerts = []
        for ts in range(3):
            alerts += engine.feed(request(ts, path=f"/missing-{ts}"))
        alert, = by_rule(alerts, "web_path_scan")
        self.assertEqual(alert.count, 3)
        self.assertEqual(alert.evidence["paths_sample"], ["/missing-0", "/missing-1", "/missing-2"])

    def test_query_variants_do_not_inflate_path_count(self):
        engine = Engine(settings())
        for ts in range(4):
            self.assertEqual(engine.feed(request(ts, path=f"/missing?q={ts}#anchor")), [])

    def test_successful_paths_do_not_count(self):
        engine = Engine(settings())
        for ts in range(5):
            self.assertEqual(engine.feed(request(ts, path=f"/{ts}", status=200)), [])

    def test_denial_burst(self):
        engine = Engine(settings())
        alerts = []
        for ts, status in enumerate((401, 403, 401)):
            alerts += engine.feed(request(ts, status=status))
        alert, = by_rule(alerts, "web_denial_burst")
        self.assertEqual(alert.count, 3)
        self.assertEqual(alert.evidence["statuses"], [401, 403])

    def test_upstream_preserves_signature_and_source(self):
        engine = Engine(settings())
        alert, = engine.feed(Event(1, "alert", "192.0.2.1", signature="Example sensor rule", severity="critical", source="sensor-a"))
        self.assertEqual(alert.rule, "upstream_alert")
        self.assertEqual(alert.severity, "critical")
        self.assertEqual(alert.evidence["signature"], "Example sensor rule")
        self.assertEqual(alert.evidence["sensor_source"], "sensor-a")
        self.assertIn("not independent", alert.recommendation)

    def test_upstream_informational_severity_preserved(self):
        alert, = Engine(settings()).feed(Event(1, "alert", "192.0.2.1", signature="Rule", severity="info"))
        self.assertEqual(alert.severity, "info")

    def test_upstream_invalid_severity_normalized(self):
        alert, = Engine(settings()).feed(Event(1, "alert", "192.0.2.1", signature="Rule", severity="unknown"))
        self.assertEqual(alert.severity, "medium")
        self.assertEqual(alert.evidence["upstream_severity"], "unknown")


class TimeAndIdentityTests(unittest.TestCase):
    def test_out_of_order_within_tolerance(self):
        engine = Engine(settings())
        engine.feed(connection(10, 21))
        engine.feed(connection(8, 22))
        self.assertEqual(engine.feed(connection(9, 23)), [])
        self.assertTrue(by_rule(engine.feed(connection(11, 24)), "vertical_scan"))
        self.assertEqual(engine.stats["late_events"], 0)

    def test_late_boundary_and_drop(self):
        engine = Engine(settings())
        engine.feed(connection(10, 21))
        engine.feed(connection(5, 22))
        engine.feed(connection(4.999, 23))
        self.assertEqual(engine.stats["accepted_events"], 2)
        self.assertEqual(engine.stats["late_events"], 1)
        self.assertTrue(by_rule(engine.feed(connection(11, 24)), "vertical_scan"))

    def test_cooldown_and_exact_expiration(self):
        engine = Engine(settings())
        for ts in range(3):
            last = engine.feed(connection(ts, 20 + ts))
        self.assertEqual(len(by_rule(last, "vertical_scan")), 1)
        self.assertEqual(engine.feed(connection(3, 23)), [])
        self.assertEqual(engine.feed(connection(6, 24)), [])
        self.assertTrue(by_rule(engine.feed(connection(7, 25)), "vertical_scan"))
        self.assertEqual(engine.stats["cooldown_suppressed"], 2)

    def test_late_event_does_not_regress_cooldown(self):
        engine = Engine(settings())
        for ts in (10, 11, 12):
            engine.feed(connection(ts, ts + 10))
        self.assertEqual(engine.feed(connection(11, 30)), [])
        self.assertEqual(engine.feed(connection(16, 31)), [])
        self.assertTrue(by_rule(engine.feed(connection(17, 32)), "vertical_scan"))

    def test_zero_cooldown(self):
        engine = Engine(settings(cooldown=0))
        for ts in range(3):
            engine.feed(connection(ts, 20 + ts))
        self.assertTrue(engine.feed(connection(3, 23)))
        self.assertEqual(engine.stats["cooldown_keys"], 0)

    def test_explicit_id_only(self):
        engine = Engine(settings())
        self.assertEqual(engine.feed(authentication(0, event_id="one")), [])
        self.assertEqual(engine.feed(authentication(0, event_id="one")), [])
        self.assertEqual(engine.stats["duplicate_events"], 1)
        engine.feed(authentication(1))
        self.assertTrue(by_rule(engine.feed(authentication(1)), "auth_bruteforce"))

    def test_id_scoped_to_source(self):
        engine = Engine(settings())
        engine.feed(authentication(0, event_id="one", source="a"))
        engine.feed(authentication(1, event_id="one", source="b"))
        self.assertEqual(engine.stats["accepted_events"], 2)

    def test_id_expires_after_retention(self):
        engine = Engine(settings())
        engine.feed(authentication(0, event_id="one"))
        engine.feed(authentication(100, event_id="one"))
        self.assertEqual(engine.stats["accepted_events"], 2)
        self.assertEqual(engine.stats["duplicate_events"], 0)

    def test_alert_id_deterministic(self):
        results = []
        for _ in range(2):
            engine = Engine(settings())
            for ts in range(3):
                results.append([a.id for a in engine.feed(connection(ts, ts + 20))])
        self.assertEqual(results[2], results[5])


class BoundsAndConfigurationTests(unittest.TestCase):
    def test_source_cidr_allowlist(self):
        engine = Engine(settings(allow_src=("192.0.2.0/24",)))
        for ts in range(3):
            self.assertEqual(engine.feed(connection(ts, ts + 20)), [])
        self.assertEqual(engine.stats["allowlisted_events"], 3)
        self.assertEqual(engine.state_size, 0)

    def test_destination_ipv6_allowlist(self):
        engine = Engine(settings(allow_dst=("2001:db8:1::/48",)))
        self.assertEqual(engine.feed(connection(0, dst="2001:db8:1::7")), [])
        self.assertEqual(engine.stats["allowlisted_events"], 1)
        engine.feed(connection(1, dst="2001:db8:2::7"))
        self.assertEqual(engine.stats["accepted_events"], 1)

    def test_hostname_does_not_match_cidr(self):
        engine = Engine(settings(allow_dst=("198.51.100.0/24",)))
        engine.feed(authentication(0, dst="host.test"))
        self.assertEqual(engine.stats["accepted_events"], 1)

    def test_disabled_rules_do_not_allocate_state(self):
        engine = Engine(settings(disabled_rules=tuple(RULES)))
        for ts in range(4):
            engine.feed(connection(ts, ts + 20))
            engine.feed(authentication(ts))
            engine.feed(request(ts))
        self.assertEqual(engine.state_size, 0)
        self.assertEqual(engine.stats["alerts"], 0)

    def test_key_capacity_and_observable_eviction(self):
        engine = Engine(settings(max_keys=3, disabled_rules=("horizontal_scan",)))
        for n in range(10):
            engine.feed(connection(n / 10, dst=f"198.51.100.{n + 1}"))
        self.assertEqual(engine.state_size, 3)
        self.assertEqual(engine.stats["keys_evicted"], 7)
        self.assertEqual(engine.stats["buffered_events"], 3)

    def test_record_capacity_retains_newest_and_counts_loss(self):
        engine = Engine(settings(max_events_per_key=3, allowed_lateness=10,
                                 disabled_rules=("horizontal_scan",)))
        for ts in (5, 6, 7, 4):
            engine.feed(connection(ts, 20 + ts))
        self.assertEqual(engine.stats["buffered_events"], 3)
        self.assertEqual(engine.stats["events_evicted"], 1)
        self.assertEqual(engine._states[("vertical_scan", "192.0.2.10", "198.51.100.10", "tcp")].records,
                         [(5, "25"), (6, "26"), (7, "27")])

    def test_expired_state_released(self):
        engine = Engine(settings())
        engine.feed(connection(0))
        engine.feed(Event(100, "alert", "192.0.2.1", signature="Rule"))
        self.assertEqual(engine.state_size, 0)
        self.assertEqual(engine.stats["buffered_events"], 0)
        self.assertEqual(engine.stats["keys_expired"], 2)

    def test_dedup_and_cooldown_maps_bounded(self):
        engine = Engine(settings(max_keys=3))
        for n in range(10):
            engine.feed(Event(n / 10, "alert", "192.0.2.1", signature=f"Rule {n}", event_id=str(n)))
        self.assertEqual(engine.stats["dedup_keys"], 3)
        self.assertEqual(engine.stats["cooldown_keys"], 3)
        self.assertEqual(engine.stats["dedup_evicted"], 7)
        self.assertEqual(engine.stats["cooldowns_evicted"], 7)

    def test_invalid_events(self):
        engine = Engine(settings())
        malformed = [None, Event(float("nan"), "conn", "192.0.2.1"),
                     Event(float("inf"), "conn", "192.0.2.1"),
                     Event(1e100, "conn", "192.0.2.1"),
                     Event(10**1000, "conn", "192.0.2.1"),
                     Event(-1, "conn", "192.0.2.1"),
                     connection(1, port=65536), connection(1, proto="x" * 33),
                     Event(1, "unknown", "192.0.2.1"), Event(1, "auth", ""),
                     Event(True, "auth", "192.0.2.1"), request(1, path="x" * 4097)]
        for event in malformed:
            self.assertEqual(engine.feed(event), [])
        self.assertEqual(engine.stats["invalid_events"], len(malformed))
        self.assertEqual(engine.state_size, 0)

    def test_source_length_matches_adapter_contract(self):
        engine = Engine(settings())
        engine.feed(connection(1, source="s" * 1024))
        self.assertEqual(engine.stats["accepted_events"], 1)
        engine.feed(connection(2, source="s" * 1025))
        self.assertEqual(engine.stats["invalid_events"], 1)

    def test_invalid_configuration(self):
        for change in ({"window": 0}, {"auth_window": -1}, {"max_keys": 0},
                       {"cooldown": -1}, {"allowed_lateness": -1}, {"scan_ports": True},
                       {"disabled_rules": ("missing_rule",)}, {"max_events_per_key": 2},
                       {"allow_src": ("invalid",)}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    Engine(settings(**change))

    def test_disabled_threshold_can_exceed_capacity(self):
        config = settings(max_events_per_key=1, disabled_rules=tuple(RULES))
        self.assertEqual(Engine(config).state_size, 0)


if __name__ == "__main__":
    unittest.main()
