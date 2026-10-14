"""Mensura repetibilis nuclei; non certamen sensorum."""
import argparse
import json
import platform
import resource
import time
from excubitor.engine import Engine
from excubitor.model import Event


def main():
    parser = argparse.ArgumentParser(description="Synthetic engine benchmark; excludes parsing, UI and storage")
    parser.add_argument("--events", type=int, default=100000)
    parser.add_argument("--profile", choices=("many-keys", "repeated"), default="repeated")
    args = parser.parse_args()
    if not 1 <= args.events <= 10000000:
        parser.error("events must be between 1 and 10000000")
    engine = Engine()
    start = time.perf_counter()
    for n in range(args.events):
        kind = ("conn", "auth", "http", "alert")[n % 4]
        if args.profile == "many-keys":
            values = dict(ts=1800000000 + n / 10000, src=f"192.0.2.{n % 250 + 1}",
                          dst=f"198.18.{n // 250 % 250}.{n % 250 + 1}",
                          port=n % 65535 + 1, user=f"user-{n % 500}",
                          path=f"/probe-{n % 1000}", signature=f"sensor-{n % 100}")
        else:
            values = dict(ts=1800000000 + n / 1000, src=f"192.0.2.{n // 4 % 16 + 1}",
                          dst="198.51.100.10", port=n // 64 % 30 + 1,
                          user=f"user-{n // 64 % 20}", path=f"/probe-{n // 64 % 30}",
                          signature=f"sensor-{n // 64 % 10}")
        engine.feed(Event(kind=kind, source="benchmark", event_id=str(n),
                          service="ssh", outcome="failure", status=403, **values))
    duration = time.perf_counter() - start
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if platform.system() == "Darwin":
        rss /= 1024
    print(json.dumps({"profile": args.profile, "events": args.events,
                      "seconds": round(duration, 4), "events_per_second": round(args.events / duration),
                      "process_peak_rss_kib": rss, "python": platform.python_version(),
                      "platform": platform.system(), "engine": engine.stats}, indent=2))


if __name__ == "__main__":
    main()
