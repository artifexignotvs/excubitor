# Input contracts

One UTF-8 record per line. Native JSON, Suricata EVE JSON, Zeek JSON, and OpenSSH syslog can be selected explicitly with `--format`, or recognized with `auto`. Empty lines and comments are skipped. Irrelevant known sensor record types are skipped. Unrecognized text and malformed supported records count as errors.

## Native v1

Required: `ts`, `kind`, `src`, and `dst` (destination optional only for `alert`). `ts` is a finite nonnegative Unix timestamp or timezone-aware ISO 8601 string. IP addresses are normalized. Auth destinations can also be hostnames. Port values are integers from 0 to 65535; zero means unknown.

```json
{"ts":"2026-10-14T12:00:00Z","kind":"conn","src":"192.0.2.10","dst":"198.51.100.10","port":443,"proto":"tcp","event_id":"collector-0001"}
{"ts":"2026-10-14T12:00:01Z","kind":"auth","src":"192.0.2.10","dst":"host.example.test","port":22,"user":"operator","outcome":"failure","service":"ssh"}
{"ts":"2026-10-14T12:00:02Z","kind":"http","src":"192.0.2.10","dst":"198.51.100.10","port":443,"path":"/missing","status":404}
{"ts":"2026-10-14T12:00:03Z","kind":"alert","src":"192.0.2.10","dst":"198.51.100.10","signature":"Example sensor observation","severity":"high"}
```

| Field | Meaning |
| --- | --- |
| `kind` | `conn`, `auth`, `http`, `alert` |
| `proto` | Transport label; default `tcp` |
| `user` | Account, empty when unknown; never invent an identity |
| `outcome` | Required `failure` or `success` for auth |
| `service` | Authentication service; keep consistent across collectors |
| `path`, `status` | HTTP request path and numeric response status |
| `signature`, `severity` | Sensor alert text and `info`/`low`/`medium`/`high`/`critical` |
| `event_id` | Optional unique event identity within its input source |
| `source` | Optional source label; the reader's input path takes precedence |

Native data is not authenticated. Anyone able to write an input can manufacture alerts, suppress signals with false timestamps, or exhaust bounded capacity. Do not merge untrusted collectors into an operational stream without authenticating them externally. Unknown JSON fields are ignored; duplicate object keys are rejected. Text fields are bounded and reject control characters. IP sources must be IP literals; DNS resolution is never performed.

## Suricata EVE

Supported `event_type`: `flow`/`netflow` for connection observations, `http` for HTTP outcomes, and `alert` for upstream findings. SSH protocol metadata contains no reliable server authentication outcome and is skipped. EVE `flow_id` is deliberately not used for event deduplication. For alert direction, a complete nested `flow` address pair takes precedence over the packet tuple; an absent nested destination port stays unknown.

The mapping follows the [official EVE format documentation](https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html). Live deployments need the relevant EVE event types enabled; enabling only alerts does not provide connection observations for scan correlation.

## Zeek JSON

Supported records are recognized from `_path` (`conn`, `http`, `ssh`) or their distinguishing JSON fields. Connections need `id.orig_h`, `id.resp_h`, `id.resp_p`, and `ts`; HTTP uses `uri` and `status_code`; SSH only yields an authentication observation when `auth_success` is explicitly boolean. `uid` identifies a connection, not a unique observation. The collector does not turn an aggregate `auth_attempts` field into repeated fabricated events.

See Zeek's [connection](https://docs.zeek.org/en/current/reference/logs/conn.html), [HTTP](https://docs.zeek.org/en/current/reference/logs/http.html), and [SSH](https://docs.zeek.org/en/current/reference/logs/ssh.html) documentation. Encrypted SSH logs normally lack usernames. That limits account-specific correlation.

## OpenSSH syslog

Recognizes `Failed`/`Accepted` password, publickey, keyboard-interactive, or none messages from `sshd`/`sshd-session`. For example:

```text
2026-10-14T12:00:00Z host.example.test sshd[100]: Failed password for invalid user operator from 192.0.2.10 port 45000 ssh2
Oct 14 12:00:01 host.example.test sshd[100]: Accepted publickey for operator from 192.0.2.10 port 45000 ssh2
```

The latter requires `--year 2026` and is interpreted as UTC. The remote port in the message is a client source port, not the server destination port; the normalized destination port stays unknown. The hostname supplies the authentication target. Different spellings for the same host, or IP-address versus hostname destinations, will form different groups. Normalize these upstream when correlating several collectors. RFC5424 structured syslog, journal JSON, PAM summaries, Windows event logs, and arbitrary access-log text are not implemented in this version.
