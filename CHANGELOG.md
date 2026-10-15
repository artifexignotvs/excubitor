# Changelog

## 0.2.0

- Add bounded offline incident timelines with deterministic grouping, evidence retention, duplicate validation, provenance hashes, JSON and Markdown export.
- Add a focused nine-event SSH demo and an authentic terminal recording using synthetic logs.
- Add source, destination, severity, timestamp and acknowledgement filters to stored history.
- Add unacknowledged filtering and severity sorting to the monochrome terminal.
- Reject acknowledgement requests for unknown alert IDs.
- Keep the existing alert schema and nine detection rules unchanged.

This is an early release. Timelines are investigative groupings, not compromise verdicts. There is no packet capture, blocking, or claimed comparative detection benchmark.

## 0.1.0

Initial public release: nine log-correlation rules, terminal investigation, replay, live log following and local SQLite history.
