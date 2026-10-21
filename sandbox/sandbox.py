"""
HoneyBot-IoT — Sandbox service: one throw-away device machine per attacker session.

The SSH and Telnet front-ends hand a logged-in attacker a REAL BusyBox shell. It
runs in a fresh container started from the device's machine image (vm/Dockerfile):

    --network none            no route anywhere: downloads, scans, C2 and reverse
                              shells fail inside the sandbox ("bad address")
    --read-only               firmware is read-only; only size-limited tmpfs is writable
    --cap-drop ALL            plus no-new-privileges, pids / memory / CPU / file-size limits
    hard time limit           SANDBOX_TIMEOUT seconds, then the machine is destroyed
    optional gVisor           SANDBOX_RUNTIME=runsc for a VM-grade kernel boundary

This service is the only component that talks to the Docker daemon. It sits on the
internal backnet, accepts a fixed set of operations from the front-ends, and never
takes an image, mount or option from the request.

Wire protocol (TCP, one JSON header line, then raw bytes):

    → {"op":"open", "session_id", "device", "ip", "user", "tty", "cmd", "cols", "rows", "token"}
    ← {"ok":true, "sandbox":"<id>"}   then the shell's raw I/O in both directions;
                                      the server closes the socket when the shell exits
    → {"op":"collect", "session_id", "token"}
    ← {"ok":true, "exit_code", "files":[{path,size,mode,mtime,data_b64}], "processes"}
                                      and the machine is destroyed
    → {"op":"ping"}  ← {"ok":true, "active":n}
"""

import io
import os
import re
import hmac
import json
import time
import base64
import socket
import struct
import tarfile
import logging
import threading

import docker
from docker.types import Mount

logging.basicConfig(level=logging.INFO, format="%(asctime)s | sandbox | %(message)s")
log = logging.getLogger("sandbox")

PORT = int(os.environ.get("SANDBOX_PORT", 7070))
TOKEN = os.environ.get("SANDBOX_TOKEN", "")
IMAGE = os.environ.get("SANDBOX_IMAGE", "honeybot/vm-{device}:0.8")
RUNTIME = os.environ.get("SANDBOX_RUNTIME") or None          # e.g. "runsc" (gVisor)
TIMEOUT = int(os.environ.get("SANDBOX_TIMEOUT", 900))          # hard lifetime per machine
MAX_TOTAL = int(os.environ.get("SANDBOX_MAX", 20))
MAX_PER_IP = int(os.environ.get("SANDBOX_MAX_PER_IP", 3))
IPC_VOLUME = os.environ.get("SANDBOX_IPC_VOLUME", "honeybot_vm_ipc")
IPC_HOSTDIR = os.environ.get("SANDBOX_IPC_HOSTDIR", "/srv/vm-ipc")   # the IPC volume mounted here
MEMORY = os.environ.get("SANDBOX_MEMORY", "64m")
CPUS = float(os.environ.get("SANDBOX_CPUS", 0.25))
PIDS = int(os.environ.get("SANDBOX_PIDS", 64))
MAX_FILE = int(os.environ.get("CAPTURE_MAX_BYTES", 10 * 1024 * 1024))
MAX_COLLECT = 24 * 1024 * 1024

DEVICES = {"cctv", "smartlock", "sensor"}
USERS = {"root": ("0:0", "/root"), "admin": ("1000:1000", "/home/admin")}
SID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
WRITABLE = ("tmp", "var/tmp", "dev/shm", "root", "home/admin", "var/run")
LABEL = "org.honeybot.sandbox"

api = None
_lock = threading.Lock()
_machines = {}          # session_id -> {"id", "ip", "device", "created", "exit_code"}


# ── machine lifecycle ───────────────────────────────────────────────────────

def _create(sid, device, ip):
    hostname = {"cctv": "IPC-HFW2431S", "smartlock": "smartlock", "sensor": "sensor-node"}[device]
    mounts = []
    if IPC_VOLUME:
        # the device-daemon FIFOs for THIS session only (volume sub-path). The sandbox
        # (root) pre-creates the sub-dir 0777 so the mount has a target and the device
        # machine (uid 10001) can then create its FIFOs inside it.
        try:
            d = os.path.join(IPC_HOSTDIR, sid)
            os.makedirs(d, exist_ok=True)
            # world-accessible on purpose: the device-control FIFOs are shared between the
            # root-owned sandbox and the unprivileged (uid 10001) device machine across
            # containers, on an internal volume in an isolated lab honeynet.
            os.chmod(d, 0o777)  # nosec B103 - cross-container IPC dir, lab-only
            # create the FIFOs here (root) so the device machine only has to OPEN them
            # (uid 10001 can open 0666 FIFOs but cannot mkfifo in a root-owned dir)
            for name in ("req", "resp"):
                p = os.path.join(d, name)
                if not os.path.exists(p):
                    os.mkfifo(p, 0o666)
                os.chmod(p, 0o666)  # nosec B103 - cross-container IPC FIFO, lab-only
        except OSError as e:
            log.warning("could not prepare IPC dir for %s: %s", sid[:8], e)
        m = Mount(target="/run/devctl", source=IPC_VOLUME, type="volume")
        m["VolumeOptions"] = {"Subpath": sid}
        mounts.append(m)
    host_config = api.create_host_config(
        network_mode="none",
        read_only=True,
        tmpfs={"/tmp": "size=16m,mode=1777", "/var/tmp": "size=8m,mode=1777",
               "/root": "size=4m,mode=700", "/home/admin": "size=4m,mode=700,uid=1000,gid=1000",
               "/var/run": "size=1m,mode=755"},
        shm_size="8m",
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        pids_limit=PIDS,
        mem_limit=MEMORY, memswap_limit=MEMORY,
        nano_cpus=int(CPUS * 1e9),
        ulimits=[docker.types.Ulimit(name="nofile", soft=256, hard=256),
                 docker.types.Ulimit(name="fsize", soft=MAX_FILE, hard=MAX_FILE)],
        mounts=mounts,
        runtime=RUNTIME,
        auto_remove=False,
    )
    c = api.create_container(
        IMAGE.format(device=device), hostname=hostname, host_config=host_config,
        labels={LABEL: "1", f"{LABEL}.session": sid, f"{LABEL}.ip": ip, f"{LABEL}.device": device},
        name=f"hb-sbx-{device}-{sid[:8]}", network_disabled=True)
    api.start(c["Id"])
    return c["Id"]


def _destroy(cid):
    try:
        api.remove_container(cid, force=True)
    except Exception as e:
        log.debug("remove %s: %s", cid[:12], e)


def acquire(sid, device, ip):
    """Return the session's machine, starting one if needed. None when over a limit."""
    with _lock:
        m = _machines.get(sid)
        if m:
            return m
        if len(_machines) >= MAX_TOTAL or sum(1 for x in _machines.values() if x["ip"] == ip) >= MAX_PER_IP:
            return None
        m = {"id": None, "ip": ip, "device": device, "created": time.time(), "exit_code": None,
             "ready": threading.Event()}
        _machines[sid] = m
    try:
        m["id"] = _create(sid, device, ip)
        log.info("machine %s started for %s (%s)", m["id"][:12], ip, device)
    except Exception as e:
        log.error("cannot start %s machine: %s", device, e)
        with _lock:
            _machines.pop(sid, None)
        m["ready"].set()
        return None
    m["ready"].set()
    return m


def release(sid):
    with _lock:
        m = _machines.pop(sid, None)
    if m and m["id"]:
        _destroy(m["id"])
        log.info("machine %s destroyed", m["id"][:12])
    try:
        import shutil
        shutil.rmtree(os.path.join(IPC_HOSTDIR, sid), ignore_errors=True)
    except Exception:
        pass


def janitor():
    """Hard lifetime: destroy machines older than TIMEOUT (their sockets then close)."""
    while True:
        time.sleep(15)
        now = time.time()
        with _lock:
            old = [sid for sid, m in _machines.items() if now - m["created"] > TIMEOUT + 120]
            expired = [m["id"] for m in _machines.values() if m["id"] and now - m["created"] > TIMEOUT]
        for cid in expired:
            try:
                api.kill(cid)
            except Exception:
                pass
        for sid in old:                       # never collected (front-end died)
            release(sid)


def cleanup_stale():
    for c in api.containers(all=True, filters={"label": LABEL}):
        _destroy(c["Id"])


VM_BUILD_CONTEXT = os.environ.get("VM_BUILD_CONTEXT", "/app/vm")


def ensure_images():
    """Build honeybot/vm-<device>:0.8 from the mounted build context if missing, so the
    stack is self-contained (no separate build step needed)."""
    existing = set()
    for img in api.images():
        for tag in img.get("RepoTags") or []:
            existing.add(tag)
    for device in sorted(DEVICES):
        tag = IMAGE.format(device=device)
        if tag in existing:
            continue
        if not os.path.isdir(VM_BUILD_CONTEXT):
            log.warning("image %s missing and no build context at %s", tag, VM_BUILD_CONTEXT)
            continue
        log.info("building %s from %s ...", tag, VM_BUILD_CONTEXT)
        try:
            for chunk in api.build(path=VM_BUILD_CONTEXT, dockerfile="Dockerfile", tag=tag,
                                   buildargs={"DEVICE": device}, rm=True, forcerm=True, decode=True):
                if "error" in chunk:
                    log.error("build %s: %s", tag, chunk["error"].strip())
        except Exception as e:
            log.error("could not build %s: %s", tag, e)


# ── stream relay ────────────────────────────────────────────────────────────

def _raw(sock):
    return getattr(sock, "_sock", sock)


def _demux_to(src, dst):
    """Docker multiplexes stdout/stderr of a non-TTY exec: 8-byte header + payload."""
    buf = b""
    while True:
        data = src.recv(65536)
        if not data:
            break
        buf += data
        while len(buf) >= 8:
            size = struct.unpack(">I", buf[4:8])[0]
            if len(buf) < 8 + size:
                break
            dst.sendall(buf[8:8 + size])
            buf = buf[8 + size:]


def _pump(src, dst, half_close=True):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        if half_close:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass


def op_open(conn, req):
    sid, device, ip = req.get("session_id", ""), req.get("device"), str(req.get("ip", ""))[:64]
    if not SID_RE.match(sid) or device not in DEVICES:
        return _reply(conn, ok=False, error="bad request")
    m = acquire(sid, device, ip)
    if m is None:
        return _reply(conn, ok=False, error="busy")
    m["ready"].wait(30)
    if not m["id"]:
        return _reply(conn, ok=False, error="unavailable")
    user, home = USERS.get(req.get("user"), USERS["root"])
    tty = bool(req.get("tty"))
    cmd = req.get("cmd")
    argv = ["/bin/sh", "-c", str(cmd)[:8192]] if cmd else ["/bin/sh", "-l"]
    name = "root" if user.startswith("0") else "admin"
    env = {"HOME": home, "USER": name, "LOGNAME": name, "SHELL": "/bin/sh",
           "TERM": str(req.get("term") or "vt100")[:32],
           "PATH": "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    eid = api.exec_create(m["id"], argv, stdin=True, tty=tty, user=user, workdir=home,
                          environment=env)["Id"]
    sock = api.exec_start(eid, socket=True, tty=tty)
    raw = _raw(sock)
    if tty:
        try:
            api.exec_resize(eid, height=int(req.get("rows") or 24), width=int(req.get("cols") or 80))
        except Exception:
            pass
    _reply(conn, ok=True, sandbox=m["id"][:12])
    t = threading.Thread(target=_pump, args=(conn, raw), daemon=True)
    t.start()
    try:
        if tty:
            _pump(raw, conn, half_close=False)
        else:
            _demux_to(raw, conn)
    except OSError:
        pass
    try:
        m["exit_code"] = api.exec_inspect(eid).get("ExitCode")
    except Exception:
        pass
    try:
        raw.close()
    except OSError:
        pass


def op_collect(conn, req):
    sid = req.get("session_id", "")
    with _lock:
        m = _machines.get(sid)
    if not m or not m["id"]:
        return _reply(conn, ok=True, exit_code=None, files=[], processes="")
    files, processes = [], ""
    try:
        processes = _exec_out(m["id"], ["ps", "-o", "pid,user,args"]).decode("utf-8", "replace")[:8000]
        script = ("cd / && find " + " ".join(WRITABLE) + " -xdev -type f 2>/dev/null | head -n 300 "
                  "| tar -cf - -T - 2>/dev/null")
        files = _untar(_exec_out(m["id"], ["sh", "-c", script], limit=MAX_COLLECT + 1024 * 1024))
    except Exception as e:
        log.warning("collect %s: %s", m["id"][:12], e)
    _reply(conn, ok=True, exit_code=m["exit_code"], files=files, processes=processes)
    release(sid)


def _exec_out(cid, argv, limit=1024 * 1024):
    eid = api.exec_create(cid, argv, stdout=True, stderr=False, user="0:0")["Id"]
    out = api.exec_start(eid, demux=True)
    data = out[0] if isinstance(out, tuple) else out
    return (data or b"")[:limit]


def _untar(blob):
    files, total = [], 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:")
    except tarfile.TarError:
        return files
    for ti in tf:
        if not ti.isfile():
            continue
        item = {"path": "/" + ti.name.lstrip("./"), "size": ti.size, "mode": ti.mode, "mtime": ti.mtime}
        if total + min(ti.size, MAX_FILE) <= MAX_COLLECT:
            f = tf.extractfile(ti)
            data = f.read(MAX_FILE) if f else b""
            total += len(data)
            item["data_b64"] = base64.b64encode(data).decode()
            item["truncated"] = ti.size > len(data)
        else:
            item["skipped"] = True
        files.append(item)
    return files


# ── server ──────────────────────────────────────────────────────────────────

def _reply(conn, **obj):
    conn.sendall(json.dumps(obj).encode() + b"\n")


def _read_header(conn):
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk or len(buf) > 64 * 1024:
            return None
        buf += chunk
    line, _, rest = buf.partition(b"\n")
    return json.loads(line), rest


def handle(conn, addr):
    try:
        conn.settimeout(10)
        hdr = _read_header(conn)
        if not hdr:
            return
        req, rest = hdr
        if TOKEN and not hmac.compare_digest(str(req.get("token", "")), TOKEN):
            log.warning("bad token from %s", addr[0])
            return _reply(conn, ok=False, error="unauthorized")
        if rest:
            return _reply(conn, ok=False, error="send the header alone first")
        conn.settimeout(None)
        op = req.get("op")
        if op == "open":
            op_open(conn, req)
        elif op == "collect":
            conn.settimeout(120)
            op_collect(conn, req)
        elif op == "ping":
            _reply(conn, ok=True, active=len(_machines))
        else:
            _reply(conn, ok=False, error="unknown op")
    except Exception as e:
        log.warning("request from %s failed: %s", addr[0], e)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    global api
    api = docker.APIClient(base_url=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"))
    api.ping()
    if not TOKEN:
        log.warning("SANDBOX_TOKEN is empty: any container on backnet may open sandboxes")
    ensure_images()
    cleanup_stale()
    threading.Thread(target=janitor, daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(64)
    log.info("sandbox service on :%d  (image %s, runtime %s, timeout %ds, max %d)",
             PORT, IMAGE, RUNTIME or "runc", TIMEOUT, MAX_TOTAL)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    main()
