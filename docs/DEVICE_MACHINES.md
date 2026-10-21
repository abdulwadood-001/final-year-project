# HoneyBot-IoT — Device Machines & the Real Restricted Shell (v0.8)

This document describes the v0.8 work on top of the 70% milestone:

1. each emulated IoT device now runs as its **own machine** (container) with its own
   identity and only its protocols;
2. a successful SSH/Telnet login drops the attacker into a **real but heavily
   restricted BusyBox shell** in a throw-away, network-less sandbox;
3. an **industrial Modbus/TCP** service and emulation of **real IoT web CVEs**;
4. new **behavioural + ICS detection rules** with MITRE ATT&CK tags.

Everything here was built and attacked end-to-end with `docker compose` and the bundled
simulator; see §6 for the observed results.

## 1. Devices as machines

The five single-protocol honeypots of v0.7 are regrouped into **three device machines**,
each a container with its own hostname, IP and MAC on the honeynet, started by a small
supervisor (`device_machine.py`) that runs only that device's protocol front-ends and
restarts any that crash:

| Machine (container) | Hostname | Protocols (host ports) |
|---|---|---|
| `cctv-machine` | IPC-HFW2431S | RTSP :554 · HTTP/HTTPS :8080/:8443 |
| `smartlock-machine` | smartlock | SSH :2222 · MQTT :1883 · HTTP :8081 |
| `sensor-machine` | sensor-node | Telnet :2323 · Modbus :502 · HTTP :8082 |

The device-state manager and the shared Redis/Postgres data plane are unchanged, so a
change made on one protocol is still seen on all the others.

## 2. The real restricted shell

`SHELL_MODE=real` (default; override per device with `SHELL_MODE_<DEVICE>`) makes the SSH
and Telnet front-ends hand a logged-in attacker a **real BusyBox shell** instead of the
emulated one. The shell runs in a fresh container the `sandbox` service starts from that
device's **machine image** (`vm/Dockerfile`, one per device):

```
attacker ── SSH/Telnet ──► device machine ──► sandbox service ──► throw-away device container
   (keystrokes logged)       (front-end)        (Docker API)        real /bin/sh, no network
```

Every session container is locked down:

- **`--network none`** — downloads, scans, C2 and reverse shells all fail inside it
  (`wget: bad address`), yet the command, the URL (IOC) and any dropped file are recorded;
- **read-only root**, writable only on small `tmpfs` mounts (`/tmp`, `/var/tmp`, `/root`);
- **`--cap-drop ALL` + `no-new-privileges`**, **pids/memory/CPU limits**, an **`fsize`
  ulimit**, and a hard **lifetime** (`SANDBOX_TIMEOUT`, default 900 s);
- **destroyed at logout**; a janitor also reaps machines past their lifetime, and per-IP /
  global caps bound how many can exist at once;
- optional **gVisor** (`SANDBOX_RUNTIME=runsc`) for a kernel-level boundary.

The sandbox service is the **only** component that talks to the Docker daemon; it sits on
the internal `backnet`, accepts a fixed set of operations, and never takes an image, mount
or flag from the request. If it is unreachable or at capacity, the front-ends **fall back
to the in-process emulated shell**, so the honeypot never goes dark.

### What HoneyBot still does while the attacker runs real commands

Because the commands really run, HoneyBot watches the command stream rather than
interpreting it (`common/cmdintel.py`, `common/realshell.py`):

- each command line is reconstructed from the keystrokes and logged as a `command` event
  (session replay is unchanged);
- `wget`/`curl`/`tftp`/`ftpget` targets become `download_attempt` IOCs — **never fetched**;
- `./x`, `/tmp/x`, `sh x.sh` become `exec_attempt` events;
- files the attacker writes to the tmpfs dirs are pulled out at logout and **quarantined**
  read-only through `common/capture.py` (`source=sandbox_drop`);
- `lockctl` / `sensorctl` / `camctl` inside the sandbox talk to a per-session
  **device-control bridge** (`/run/devctl` FIFOs) that applies the change to the shared
  device state — so unlocking the door in the real shell is visible over HTTP, MQTT and the
  sensor HMI too.

## 3. Modbus/TCP (ICS)

`modbus_honeypot/` makes the sensor node's long-advertised `modbusd -p 502` real. It speaks
enough Modbus/TCP for the usual ICS tools (modbus-cli, pymodbus, Metasploit `modbus*`,
PLCScan): read holding/input registers (FC 3/4) and coils (FC 1/2), write single/multiple
registers (FC 6/16), write coil (FC 5) and report-server-id (FC 17); anything else returns a
Modbus exception. Live telemetry is served from the shared state; **writing a threshold
register changes that shared state**, so the tamper is visible on every protocol and is
logged as `modbus_write` / `state_change`.

| Register | Field | Writable |
|---|---|---|
| 40001–40003 | temperature / pressure / humidity (×10) | no (telemetry) |
| 40004–40005 | temp / pressure threshold (×10) | yes |
| 40006–40007 | interval · mode (0=auto 1=manual) | yes |

## 4. Real IoT web exploit emulation

`http_honeypot/exploits.py` answers a set of widely-exploited camera/router bugs the way the
real firmware would, so exploit tools and botnet loaders proceed to their payload stage.
Where the bug is a command injection, the injected command is extracted and **really run in
the device's shell** (output returned, downloads logged, drops quarantined):

| Route | Emulated vulnerability |
|---|---|
| `PUT /SDK/webLanguage` | Hikvision **CVE-2021-36260** unauth command injection |
| `POST /RPC2_Login` | Dahua authentication bypass |
| `POST /ctrlt/DeviceUpgrade_1` | Huawei HG532 **CVE-2017-17215** |
| `POST /GponForm/diag_Form` | Dasan GPON **CVE-2018-10561/62** |
| `POST /picsdesc.xml`, `/wanipcn.xml` | Realtek SDK **CVE-2014-8361** |
| `GET/POST /setup.cgi` | Netgear DGN `setup.cgi` injection |
| `/cgi-bin/…?cmd=` | generic Boa/GoAhead shell-CGI injection |

Each match raises an `exploit_attempt` event (with the CVE id) and feeds the
`PROTOCOL_EXPLOIT` detection.

## 5. New detections (MITRE ATT&CK)

Post-exploitation in the real shell and the new protocols are classified by
`intel/rules.py` (`behavioural`, `modbus_ics`, and an MQTT-flood branch) and tagged in
`intel/mitre.py`:

| Attack type | Trigger | MITRE |
|---|---|---|
| `PERSISTENCE` | cron / init.d / rc.local edits | T1053.003, T1037.004 |
| `DEFENSE_EVASION` | kill watchdog, flush iptables, clear history/logs | T1070.004, T1562.004, T1489 |
| `DENIAL_OF_SERVICE` | fork bomb, `dd if=/dev/zero`, busy-loop | T1499, T0814 |
| `CRYPTO_MINING` | xmrig/minerd, `stratum+tcp://` | T1496 |
| `CONTAINER_ESCAPE` | nsenter, `/proc/1`, docker.sock, `/dev/mem`, insmod | T1611, T1610 |
| `REVERSE_SHELL` | `/dev/tcp/`, `nc -e`, `mkfifo…|sh`, `python -c socket` | T1059.004, T1572 |
| `MQTT_FLOOD` | publish flood | T1499, T0814 |
| `ICS_PARAMETER_TAMPERING` | Modbus register write | T0836, T0831, T0855 |
| `ICS_DEVICE_SCAN` | Modbus register/coil enumeration | T0846, T0801 |

## 6. End-to-end test result

Full stack built and run with Docker; the bundled simulator ran all 13 scenarios against the
three device machines (real shell on). After a `POST /api/detect` pass:

- **30 detections across 19 distinct attack types**, including the new
  `CONTAINER_ESCAPE` (CRITICAL), `REVERSE_SHELL` (CRITICAL), `CRYPTO_MINING`,
  `PERSISTENCE`, `DEFENSE_EVASION`, and `ICS_PARAMETER_TAMPERING` (CRITICAL);
- **10 real sandbox shells** opened and destroyed cleanly (0 leftover containers);
- `lockctl unlock` in the SSH sandbox propagated to Redis and showed as
  `ICS_UNAUTHORIZED_COMMAND` across HTTP, MQTT, Telnet **and** Modbus;
- the five CVE requests were captured as `exploit_attempt` events and executed in the
  camera's shell (e.g. `$(id;uname -a)` returned the camera's real ARM identity).

`pytest` is green (68 passed, 33 DB-backed skipped without PostgreSQL), including the new
`tests/test_v08.py` (23 tests: command intel, real-shell mode, Modbus dispatch, CVE routing,
behavioural-rule↔MITRE coverage, sandbox request validation).

## 7. Running it

```bash
cp .env.example .env            # set SANDBOX_TOKEN; SHELL_MODE=real is the default
docker compose up -d --build    # builds the machine images on first sandbox start
docker compose --profile sim run --rm attacker     # 13 attack scenarios, incl. CVE + Modbus
```

> The sandbox needs the Docker socket to start the per-session machines, so it is **not for
> rootless Docker**. Set `SHELL_MODE=fake` there to keep the emulated shell. As in v0.7 the
> system is a research tool for an isolated lab (scope LI-11); see the README safety notes.
