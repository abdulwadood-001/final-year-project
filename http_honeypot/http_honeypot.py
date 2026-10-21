"""
HoneyBot-IoT — HTTP/HTTPS honeypot, one process, three device personalities

    :8080 / :8443(TLS)  CCTV camera web panel   (Server: Boa/0.94.14rc21)
    :8081               Smart-lock REST API     (Server: lighttpd/1.4.35)
    :8082               Industrial sensor HMI   (Server: GoAhead-Webs)

Every request (any path, any method) is logged as an `http_request` event, so
scanners probing /cgi-bin, /.env, /shell?, /HNAP1 … are all captured.
Logins (form, JSON and HTTP Basic) are logged as `auth` events.
State (lock, sensor readings, camera motion) comes from the shared Device State.
"""

import os
import sys
import json
import time
import base64
import asyncio
import hashlib
import logging
import secrets
import threading
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, RedirectResponse

from common.db import Session
from common.state import STATE, start_heartbeat
from common.creds import is_weak
from common import capture
from http_honeypot import exploits

logging.basicConfig(level=logging.INFO, format="%(asctime)s | http | %(message)s")
log = logging.getLogger("http")
for noisy in ("uvicorn.access", "uvicorn.error"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

CCTV_PORT = int(os.environ.get("HTTP_CCTV_PORT", 8080))
CCTV_TLS_PORT = int(os.environ.get("HTTPS_CCTV_PORT", 8443))
LOCK_PORT = int(os.environ.get("HTTP_LOCK_PORT", 8081))
SENSOR_PORT = int(os.environ.get("HTTP_SENSOR_PORT", 8082))
CERT_DIR = os.environ.get("CERT_DIR", "/app/data")
SESSION_IDLE = 300          # an HTTP "session" = same IP+device, < 5 min idle


# ── per-IP HTTP session tracking ────────────────────────────────────────────
class HttpSessions:
    def __init__(self):
        self._s = {}
        self._lock = threading.Lock()
        threading.Thread(target=self._reaper, daemon=True).start()

    def get(self, ip, sport, device, port, ua):
        key = (ip, device)
        with self._lock:
            entry = self._s.get(key)
            if entry and time.time() - entry[1] < SESSION_IDLE:
                self._s[key] = (entry[0], time.time())
                return entry[0]
            if entry:
                entry[0].close("idle")
            s = Session("HTTP", device, ip, sport, port, client_version=ua[:200])
            self._s[key] = (s, time.time())
            return s

    def _reaper(self):
        while True:
            time.sleep(30)
            now = time.time()
            with self._lock:
                for k, (s, t) in list(self._s.items()):
                    if now - t > SESSION_IDLE:
                        s.close("idle")
                        del self._s[k]


SESSIONS = HttpSessions()
WEB_TOKENS = {}            # cookie -> username  (CCTV web login)


def _ip(request):
    return request.client.host if request.client else "unknown"


def _basic(request):
    h = request.headers.get("authorization", "")
    if h.lower().startswith("basic "):
        try:
            u, _, p = base64.b64decode(h[6:]).decode("utf-8", "replace").partition(":")
            return u, p
        except Exception:
            return "", ""
    return None


def add_logging(app, device, server_header, port):
    @app.middleware("http")
    async def log_everything(request: Request, call_next):
        ip = _ip(request) if request.client else "unknown"
        sport = request.client.port if request.client else None
        ua = request.headers.get("user-agent", "")
        s = SESSIONS.get(ip, sport, device, port, ua)
        request.state.hs = s
        body = b""
        try:
            body = await request.body()
        except Exception:
            pass
        creds = _basic(request)
        if creds is not None:
            u, p = creds
            ok = is_weak(device, u, p)
            s.auth(u, p, ok, method="basic", path=request.url.path, user_agent=ua)
            request.state.basic_ok = ok
        else:
            request.state.basic_ok = False
        handler = exploits.match(request.url.path, request.method)
        if handler is not None:
            try:
                result = await asyncio.to_thread(
                    handler, device, s, request, request.url.path, request.url.query, body)
            except Exception as e:
                log.debug("exploit handler error %s", e)
                result = None
            if result is not None:
                request.state.captured = True
                status, media, payload = result
                response = Response(payload, status_code=status, media_type=media)
            else:
                response = await call_next(request)
        else:
            try:
                response = await call_next(request)
            except Exception as e:
                log.debug("handler error %s", e)
                response = Response("Internal Server Error", status_code=500)
        response.headers["Server"] = server_header
        hdrs = {k: v for k, v in request.headers.items()
                if k.lower() not in ("authorization", "cookie")}
        if body and request.method in ("POST", "PUT", "PATCH") \
                and not getattr(request.state, "captured", False) and capture.looks_interesting(body):
            capture.store(s, body, "http_body", filename=request.url.path)
        s.event("http_request",
                command=f"{request.method} {request.url.path}"
                        + (f"?{request.url.query}" if request.url.query else ""),
                payload=body[:2048].decode("utf-8", "replace") if body else None,
                method=request.method, path=request.url.path, query=request.url.query,
                status=response.status_code, user_agent=ua, headers=hdrs,
                body_sha256=hashlib.sha256(body).hexdigest() if body else None,
                body_size=len(body), port=port)
        return response


def not_found(server):
    return HTMLResponse("<html><head><title>404 Not Found</title></head><body>"
                        f"<h1>404 Not Found</h1><hr><address>{server}</address></body></html>",
                        status_code=404)


# ═══════════════════════════════════════════════════════════════════════════
#  CCTV camera  (:8080 / :8443)
# ═══════════════════════════════════════════════════════════════════════════
CCTV_SERVER = "Boa/0.94.14rc21"
cctv = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
add_logging(cctv, "cctv", CCTV_SERVER, CCTV_PORT)

CCTV_CSS = """*{box-sizing:border-box;margin:0;padding:0}body{background:#1e2329;font-family:Arial,Helvetica,sans-serif;color:#d8dde3}
.top{background:#2b3138;padding:10px 24px;display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #c8102e}
.top b{color:#fff;letter-spacing:1px}.top a{color:#9aa4ae;font-size:12px;margin-left:14px;text-decoration:none}
.card{background:#2b3138;border:1px solid #3a424b;border-radius:3px;padding:36px;width:360px;margin:12vh auto}
h2{font-size:18px;color:#fff;margin-bottom:4px}.sub{font-size:11px;color:#8b95a0;margin-bottom:22px}
label{font-size:12px;color:#9aa4ae;display:block;margin:10px 0 4px}input,select{width:100%;padding:8px;background:#1e2329;border:1px solid #3a424b;color:#fff}
button{margin-top:18px;width:100%;padding:9px;background:#c8102e;border:0;color:#fff;font-weight:bold;cursor:pointer}
.err{background:#4a1f25;color:#ff9aa5;padding:7px;font-size:12px;margin-bottom:8px}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;padding:18px}.cam{background:#000;height:220px;position:relative;border:1px solid #3a424b}
.cam span{position:absolute;left:8px;top:6px;font-size:11px;color:#fff;font-family:monospace}.cam i{position:absolute;right:8px;top:6px;color:#e33;font-size:11px;font-style:normal}
.side{padding:18px;font-size:12px;line-height:1.9}"""

CCTV_LOGIN = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>WEB SERVICE</title><style>{css}</style></head>
<body><div class="card"><h2>Network Camera</h2><div class="sub">Model {model} &middot; Firmware {fw}</div>{err}
<form method="post" action="/login"><label>User Name</label><input name="username" autocomplete="off">
<label>Password</label><input type="password" name="password"><label>Language</label><select><option>English</option></select>
<button type="submit">Login</button></form></div></body></html>"""

CCTV_LIVE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>WEB SERVICE</title><meta http-equiv="refresh" content="10"><style>{css}</style></head>
<body><div class="top"><b>Network Camera &middot; {model}</b><div><a href="/live">Live View</a><a href="/settings">Setup</a>
<a href="/cgi-bin/snapshot.cgi">Snapshot</a><a href="/logout">Logout ({user})</a></div></div>
<div style="display:grid;grid-template-columns:3fr 1fr"><div class="grid">{cams}</div>
<div class="side"><b>Device</b><br>Serial: {serial}<br>Firmware: {fw}<br>Resolution: {res}<br>Recording: {rec}<br>
Motion: {motion}<br>Last motion: {last}<br><br><b>Stream</b><br>rtsp://&lt;device-ip&gt;:554/cam/realmonitor?channel=1&amp;subtype=0</div></div></body></html>"""

JPEG_1PX = base64.b64decode(
    "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////"
    "////////////////////////////wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=")


def _cctv_user(request):
    tok = request.cookies.get("WebSession")
    return WEB_TOKENS.get(tok)


@cctv.get("/", response_class=HTMLResponse)
async def cctv_index():
    st = STATE.get("cctv")
    return CCTV_LOGIN.format(css=CCTV_CSS, model=st["model"], fw=st["firmware"], err="")


@cctv.post("/login")
async def cctv_login(request: Request):
    form = {}
    try:
        form = dict(await request.form())
    except Exception:
        pass
    u, p = str(form.get("username", "")), str(form.get("password", ""))
    ok = is_weak("cctv", u, p)
    request.state.hs.auth(u, p, ok, method="form", user_agent=request.headers.get("user-agent", ""))
    log.info("CCTV %s | %s:%s | %s", _ip(request), u, p, "ACCEPT" if ok else "REJECT")
    st = STATE.get("cctv")
    if not ok:
        await asyncio.sleep(1)
        return HTMLResponse(CCTV_LOGIN.format(css=CCTV_CSS, model=st["model"], fw=st["firmware"],
                                              err='<div class="err">Invalid user name or password.</div>'))
    tok = secrets.token_hex(16)
    WEB_TOKENS[tok] = u
    r = RedirectResponse("/live", status_code=302)
    r.set_cookie("WebSession", tok, httponly=True)
    return r


@cctv.get("/live", response_class=HTMLResponse)
async def cctv_live(request: Request):
    user = _cctv_user(request)
    if not user:
        return RedirectResponse("/", status_code=302)
    st = STATE.get("cctv")
    names = ["Front Door", "Parking Lot", "Loading Bay", "Warehouse"]
    cams = "".join(f'<div class="cam"><span>CH{i+1} {n}</span>'
                   f'{"<i>&#9679; MOTION</i>" if (st["motion"] == "true" and i == 0) else ""}</div>'
                   for i, n in enumerate(names))
    return CCTV_LIVE.format(css=CCTV_CSS, model=st["model"], user=user, cams=cams, serial=st["serial"],
                            fw=st["firmware"], res=st["resolution"], rec=st["recording"],
                            motion=st["motion"], last=st["last_motion"] or "-")


@cctv.get("/settings", response_class=HTMLResponse)
async def cctv_settings(request: Request):
    if not _cctv_user(request):
        return RedirectResponse("/", status_code=302)
    return HTMLResponse(f"<html><head><style>{CCTV_CSS}</style></head><body><div class='card'><h2>Setup</h2>"
                        "<form method='post' action='/upgrade' enctype='multipart/form-data'>"
                        "<label>Firmware upgrade (.bin)</label><input type='file' name='firmware'>"
                        "<button>Upgrade</button></form></div></body></html>")


@cctv.post("/upgrade")
async def cctv_upgrade(request: Request):
    body = await request.body()
    data, fname = body, None
    if "multipart/form-data" in request.headers.get("content-type", ""):
        try:                                   # keep only the uploaded file part
            form = await request.form()
            for v in form.values():
                if hasattr(v, "read"):
                    data, fname = await v.read(), getattr(v, "filename", None)
                    break
        except Exception:
            pass
    request.state.hs.event("file_upload", payload=f"firmware upload {fname or ''} {len(data)} bytes",
                           sha256=hashlib.sha256(data).hexdigest(), size=len(data),
                           path="/upgrade", filename=fname)
    capture.store(request.state.hs, data, "http_upload", filename=fname or "firmware.bin")
    request.state.captured = True
    return HTMLResponse("<html><body>Upgrade failed: invalid image header (0x0005)</body></html>",
                        status_code=200)


@cctv.get("/logout")
async def cctv_logout(request: Request):
    WEB_TOKENS.pop(request.cookies.get("WebSession"), None)
    return RedirectResponse("/", status_code=302)


@cctv.get("/cgi-bin/snapshot.cgi")
async def cctv_snapshot(request: Request):
    if not (request.state.basic_ok or _cctv_user(request)):
        return Response("401 Unauthorized", status_code=401,
                        headers={"WWW-Authenticate": 'Basic realm="Login to 6C02E1A4B9F3"'})
    return Response(JPEG_1PX, media_type="image/jpeg")


@cctv.get("/ISAPI/System/deviceInfo")
@cctv.get("/cgi-bin/magicBox.cgi")
async def cctv_devinfo(request: Request):
    if not request.state.basic_ok:
        return Response("401 Unauthorized", status_code=401,
                        headers={"WWW-Authenticate": 'Basic realm="Login to 6C02E1A4B9F3"'})
    st = STATE.get("cctv")
    return Response(f'<?xml version="1.0" encoding="UTF-8"?><DeviceInfo><deviceName>IP CAMERA</deviceName>'
                    f'<model>{st["model"]}</model><serialNumber>{st["serial"]}</serialNumber>'
                    f'<firmwareVersion>{st["firmware"]}</firmwareVersion></DeviceInfo>',
                    media_type="application/xml")


@cctv.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def cctv_any(path: str):
    return not_found(CCTV_SERVER)


# ═══════════════════════════════════════════════════════════════════════════
#  Smart lock REST API  (:8081)
# ═══════════════════════════════════════════════════════════════════════════
LOCK_SERVER = "lighttpd/1.4.35"
lock = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
add_logging(lock, "smartlock", LOCK_SERVER, LOCK_PORT)


def _lock_token_ok(request):
    tok = request.headers.get("authorization", "")
    tok = tok[7:] if tok.lower().startswith("bearer ") else request.query_params.get("token", "")
    return tok and tok == STATE.field("smartlock", "api_token")


@lock.get("/")
async def lock_root():
    st = STATE.get("smartlock")
    return {"device": st["model"], "vendor": st["vendor"], "fw": st["firmware"], "api": "/api/v1",
            "endpoints": ["/api/v1/auth", "/api/v1/status", "/api/v1/lock"]}


@lock.post("/api/v1/auth")
async def lock_auth(request: Request):
    try:
        data = await request.json()
    except Exception:
        try:
            data = dict(await request.form())
        except Exception:
            data = {}
    u, p = str(data.get("username", "")), str(data.get("password", ""))
    ok = is_weak("smartlock", u, p)
    request.state.hs.auth(u, p, ok, method="api")
    log.info("LOCK %s | %s:%s | %s", _ip(request), u, p, "ACCEPT" if ok else "REJECT")
    if not ok:
        await asyncio.sleep(0.8)
        return JSONResponse({"error": "invalid_credentials"}, status_code=401)
    exp = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat(timespec="seconds")
    return {"token": STATE.field("smartlock", "api_token"), "expires": exp}


@lock.get("/api/v1/status")
async def lock_status(request: Request):
    if not _lock_token_ok(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    st = STATE.get("smartlock")
    return {k: st[k] for k in ("lock_state", "door", "battery", "auto_lock", "last_action",
                                "last_change", "firmware", "serial")}


@lock.post("/api/v1/lock")
async def lock_cmd(request: Request):
    if not _lock_token_ok(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        data = await request.json()
    except Exception:
        data = {}
    action = str(data.get("action", request.query_params.get("action", "")))
    new = STATE.lock_action(action, actor=f"http:{_ip(request)}")
    if not new:
        return JSONResponse({"error": "invalid action", "allowed": ["lock", "unlock"]}, status_code=400)
    request.state.hs.event("state_change", payload=f"lock_state={new}", device_field="lock_state",
                           value=new, via="rest")
    return {"result": "ok", "lock_state": new}


@lock.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def lock_any(path: str):
    return JSONResponse({"error": "not_found"}, status_code=404)


# ═══════════════════════════════════════════════════════════════════════════
#  Industrial sensor HMI  (:8082)  — HTTP Basic auth, cleartext (ICS realism)
# ═══════════════════════════════════════════════════════════════════════════
SENSOR_SERVER = "GoAhead-Webs"
sensor = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
add_logging(sensor, "sensor", SENSOR_SERVER, SENSOR_PORT)
SENSOR_401 = {"WWW-Authenticate": 'Basic realm="ISN-4000"'}


def _need_auth():
    return HTMLResponse("<html><body><h2>401 Unauthorized</h2></body></html>",
                        status_code=401, headers=SENSOR_401)


@sensor.get("/", response_class=HTMLResponse)
async def sensor_index(request: Request):
    if not request.state.basic_ok:
        return _need_auth()
    s = STATE.get("sensor")
    alarm_color = "#c00" if s["alarm"] != "none" else "#080"
    hist = "".join(f"<tr><td>-{i*5}s</td><td>{float(s['temperature']) + (i % 3 - 1) * 0.3:.1f}</td>"
                   f"<td>{float(s['pressure']) + (i % 2) * 0.4:.1f}</td></tr>" for i in range(8))
    return f"""<html><head><title>ISN-4000 HMI</title><meta http-equiv="refresh" content="5">
<style>body{{font-family:Verdana;font-size:12px;background:#eee}}table{{border-collapse:collapse}}
td,th{{border:1px solid #999;padding:4px 10px;background:#fff}}h3{{background:#036;color:#fff;padding:6px}}</style></head>
<body><h3>ISN-4000 Industrial Sensor Node &mdash; {s['serial']}</h3>
<table><tr><th>Temperature (&deg;C)</th><th>Pressure (kPa)</th><th>Humidity (%)</th><th>Alarm</th></tr>
<tr><td>{s['temperature']}</td><td>{s['pressure']}</td><td>{s['humidity']}</td>
<td style="color:{alarm_color}"><b>{s['alarm']}</b></td></tr></table><br>
<b>Alert thresholds</b><form method="post" action="/config">
Temp <input name="temp_threshold" value="{s['temp_threshold']}" size="4">
Pressure <input name="pressure_threshold" value="{s['pressure_threshold']}" size="4">
Interval <input name="interval" value="{s['interval']}" size="3"> s
<input type="submit" value="Apply"></form><br><b>History</b>
<table><tr><th>t</th><th>Temp</th><th>Pressure</th></tr>{hist}</table>
<p>Firmware {s['firmware']} &middot; PLC link {s['plc_link']} &middot; Modbus/TCP :502</p></body></html>"""


@sensor.get("/api/readings")
async def sensor_readings(request: Request):
    if not request.state.basic_ok:
        return _need_auth()
    s = STATE.get("sensor")
    return {k: s[k] for k in ("temperature", "pressure", "humidity", "alarm", "temp_threshold",
                              "pressure_threshold", "interval")}


@sensor.post("/config")
async def sensor_config(request: Request):
    if not request.state.basic_ok:
        return _need_auth()
    try:
        form = dict(await request.form())
    except Exception:
        form = {}
    changed = STATE.sensor_config(f"http:{_ip(request)}", {k: str(v) for k, v in form.items()})
    if changed:
        request.state.hs.event("state_change", payload=json.dumps(changed), via="hmi", **changed)
    return RedirectResponse("/", status_code=302)


@sensor.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
async def sensor_any(path: str):
    return not_found(SENSOR_SERVER)


# ═══════════════════════════════════════════════════════════════════════════
def ensure_cert():
    """Self-signed certificate for the CCTV HTTPS port (generated once)."""
    key_p, crt_p = os.path.join(CERT_DIR, "cctv.key"), os.path.join(CERT_DIR, "cctv.crt")
    if os.path.exists(key_p) and os.path.exists(crt_p):
        return key_p, crt_p
    os.makedirs(CERT_DIR, exist_ok=True)
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IPCam"),
                      x509.NameAttribute(NameOID.COMMON_NAME, "IPC-HFW2431S")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=900))
            .not_valid_after(now + timedelta(days=3650)).sign(key, hashes.SHA256()))
    with open(key_p, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    with open(crt_p, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key_p, crt_p


async def main():
    STATE.init_defaults()
    start_heartbeat("http", port=CCTV_PORT, device="cctv,smartlock,sensor", protocol="HTTP")
    common = dict(host="0.0.0.0", log_level="warning", server_header=False, date_header=True,
                  proxy_headers=False)
    # HTTP_DEVICES limits which device web services this process serves, so one
    # device "machine" container runs only its own HTTP front-end (default: all).
    want = {d.strip() for d in os.environ.get("HTTP_DEVICES", "cctv,smartlock,sensor").split(",") if d.strip()}
    by_device = {"cctv": [(cctv, CCTV_PORT)], "smartlock": [(lock, LOCK_PORT)],
                 "sensor": [(sensor, SENSOR_PORT)]}
    servers = [uvicorn.Server(uvicorn.Config(app, port=port, **common))
               for dev in want for app, port in by_device.get(dev, [])]
    if "cctv" in want:
        try:
            key_p, crt_p = ensure_cert()
            servers.append(uvicorn.Server(uvicorn.Config(cctv, port=CCTV_TLS_PORT, ssl_keyfile=key_p,
                                                         ssl_certfile=crt_p, **common)))
        except Exception as e:
            log.warning("HTTPS disabled: %s", e)
    if not servers:
        log.error("HTTP_DEVICES=%s selected no services", want)
        return
    for s in servers:
        s.install_signal_handlers = lambda: None
    log.info("HTTP honeypots: CCTV :%d (TLS :%d)  SmartLock :%d  Sensor :%d",
             CCTV_PORT, CCTV_TLS_PORT, LOCK_PORT, SENSOR_PORT)
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(main())
