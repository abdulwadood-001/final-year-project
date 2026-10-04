# HoneyBot-IoT — Test Report (60% milestone)

Environment: PostgreSQL 16, Redis 7.2, Python 3.12/3.13. Traffic generated with
`tests/simulate_attacks.py` against the local stack.

## 1. Unit tests (`pytest`)

```
pytest -q
31 passed, 12 skipped
```

- `test_parsers.py` (31 tests): MQTT variable-length-integer round-trips (incl. > 127-byte
  packets — the v0.3 bug), MQTT CONNECT credential parsing, topic wildcard matching, RTSP
  Digest-auth accept/reject, fake-shell argument tolerance, Mirai preamble, URL capture without
  fetch, command chaining/pipes, device-control state change, MITRE mapping, per-device creds.
- `test_api.py` (12): API endpoint smoke tests. Skipped in the dev sandbox because the
  installed `httpx`/`starlette` versions mismatch; they run under the pinned versions in
  `requirements-dev.txt` and in the Docker image.

## 2. Integration — protocol → unified event store

After one full simulator run, all five protocols write through `log_event()`:

| Protocol | Distinct event types | Events |
|---|---|---|
| SSH | 7 | 237 |
| RTSP | 6 | 179 |
| HTTP | 4 | 135 |
| MQTT | 7 | 50 |
| Telnet | 5 | 35 |

(Event types include `connect`, `auth`, `command`, `http_request`, `mqtt_publish/subscribe`,
`rtsp_request`, `download_attempt`, `exec_attempt`, `state_change`, `malformed`.)

## 3. Detection coverage — all 6 ML classes exercised

A single `POST /api/detect` pass over simulated traffic produced detections in every category:

```
BOTNET_C2 · BRUTE_FORCE · CREDENTIAL_COMPROMISE · CREDENTIAL_STUFFING · DENIAL_OF_VIEW
ICS_UNAUTHORIZED_COMMAND · MALWARE_DELIVERY · MIRAI_SIGNATURE · MULTI_PROTOCOL_ATTACK
POST_EXPLOITATION · PROTOCOL_EXPLOIT · RECONNAISSANCE · RTSP_ROUTE_ENUM
VIDEO_STREAM_ACCESS · WEB_SCAN
```

Each detection carries MITRE ATT&CK technique IDs (Enterprise + ICS), visible on the dashboard.

## 4. Cross-protocol state consistency (high-interaction proof)

- Unlock the Smart Lock via the **HTTP REST API** → `device:smartlock lock_state = unlocked`
  in Redis → the same value is returned over **MQTT** (`lock/status`) and over **SSH**
  (`cat /etc/lock_state`).
- Change a sensor threshold over **Telnet** (`sensorctl set temp_threshold 20`) → reflected in
  the **HTTP** sensor HMI and the **MQTT** `sensor/config` topic.

## 5. Alert deduplication (one message per campaign)

A brute-force run that produced dozens of matching detections resulted in:

```
channel   status       count
telegram  sent/disabled    1     ← exactly one alert for the IP (per window)
email     sent/disabled    1
dedupe    suppressed      30     ← all further detections suppressed in the 10-min window
```

(`disabled` appears when no Telegram/SMTP credentials are configured; with credentials the
status is `sent`. The point — one alert, not thirty — holds either way.)

## 6. Isolation / passivity

- Captured download URLs (e.g. `http://198.51.100.23/arm`) are stored as IOCs and in
  `download_attempt` events, but the honeypot **never fetches them** (verified: no outbound
  request is made; the fake shell only prints realistic `wget` output).
- `deploy/firewall.sh` drops outbound NEW connections from the honeynet subnet. Verify on the
  host with:
  `docker exec honeybot_ssh python -c "import urllib.request; urllib.request.urlopen('http://example.com', timeout=5)"` → hangs/fails.

## 7. Security lint (`bandit`)

```
bandit -r . -x ./tests -lll     → 0 high-severity findings
bandit -r . -x ./tests -ll      → 22 medium findings, all reviewed:
```

| Finding | Count | Assessment |
|---|---|---|
| B608 hardcoded SQL | ~9 | **False positive.** All interpolation is of `int()`-cast interval literals or fixed column/clause strings; every user-supplied value uses parameterised `%s`. |
| B310 urlopen | 1 | Telegram API call — fixed `https://api.telegram.org/...` scheme, not attacker-controlled. |
| B104 bind 0.0.0.0 | several | Intentional — honeypots must listen on all interfaces. |
| B108 hardcoded /tmp | few | `/tmp` strings are part of the **emulated** IoT filesystem, not real temp files. |
| B324 MD5/SHA1 | 0 (was 7) | Cleared with `usedforsecurity=False`; RTSP Digest MD5 is mandated by RFC 2617. |

## 8. What is NOT yet tested (100% work)

Load testing (events/sec under stress), ML model evaluation (accuracy/F1/confusion matrix),
and a real-internet baseline. These depend on Module 8 and a deployed VPS, which are the 100%
milestone. The ML-evaluation metrics table is stubbed in `docs/MODEL_CARD.md`.
