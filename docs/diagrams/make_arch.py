import html, sys
W, H = 1400, 1030
out = []
def esc(s): return html.escape(s)
def group(x1,y1,x2,y2,stroke,fill,label,lx=None,ly=None,lcolor=None):
    out.append(f'<rect x="{x1}" y="{y1}" width="{x2-x1}" height="{y2-y1}" rx="8" fill="{fill}" stroke="{stroke}" stroke-width="2" stroke-dasharray="7,5"/>')
    out.append(f'<text x="{lx or x1+14}" y="{ly or y2-14}" font-size="13.5" font-weight="bold" fill="{lcolor or stroke}">{esc(label)}</text>')
def box(x1,y1,x2,y2,stroke,fill,title,lines=(),dash=False,tsize=14.5):
    d=' stroke-dasharray="6,4"' if dash else ''
    out.append(f'<rect x="{x1}" y="{y1}" width="{x2-x1}" height="{y2-y1}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="1.6"{d}/>')
    cx=(x1+x2)/2
    n=len(lines); total=18+n*17
    y=(y1+y2)/2-total/2+14
    out.append(f'<text x="{cx}" y="{y}" font-size="{tsize}" font-weight="bold" text-anchor="middle" fill="#111">{esc(title)}</text>')
    for i,l in enumerate(lines):
        out.append(f'<text x="{cx}" y="{y+19+i*17}" font-size="12" text-anchor="middle" fill="#333">{esc(l)}</text>')
def arrow(pts,color="#444",dash=False,label=None,lpos=None,anchor="start",w=1.6):
    d=' stroke-dasharray="6,4"' if dash else ''
    p=" ".join(f"{x},{y}" for x,y in pts)
    out.append(f'<polyline points="{p}" fill="none" stroke="{color}" stroke-width="{w}"{d} marker-end="url(#ah{color[1:]})"/>')
    if label:
        lx,ly=lpos
        out.append(f'<text x="{lx}" y="{ly}" font-size="11.5" font-style="italic" fill="#333" text-anchor="{anchor}">{esc(label)}</text>')
colors=["#444","#b33a3a","#b37a1a","#2c4a85"]
# palette
G=("#3d7a2a","#e7f2e0"); B=("#2c4a85","#e8eef8"); O=("#b37a1a","#fdf2e1"); P=("#7b3f98","#f1e4f5"); R=("#b33a3a","#fbe9e9"); GR=("#777777","#f2f2f2")
# attacker
box(590,10,810,50,*R,"Attacker / Internet")
# honeynet
group(20,70,1380,240,"#3d7a2a","#f6faf3","honeynet (bridge 172.31.66.0/24) — inbound only: every outbound connection is logged and dropped by the firewall service")
hp=[("SSH Honeypot",["Smart Lock · :2222","shell · exec · stdin/scp capture"]),
    ("Telnet Honeypot",["Industrial Sensor · :2323","asyncio, IAC negotiation"]),
    ("HTTP / HTTPS Honeypot",["CCTV :8080/:8443 · Lock :8081","Sensor HMI :8082 · uploads"]),
    ("MQTT Broker Honeypot",["Lock + Sensor · :1883","MQTT 3.1.1, payload capture"]),
    ("RTSP Honeypot",["CCTV Camera · :554","Basic + Digest auth, SDP"])]
xs=[40,308,576,844,1112]
for x,(t,l) in zip(xs,hp):
    box(x,96,x+248,170,*G,t,l)
    arrow([(700,50),(x+124,96)],color="#b33a3a")
out.append('<text x="700" y="196" font-size="12" font-style="italic" text-anchor="middle" fill="#3d7a2a">all honeypots: non-root · read-only FS · cap_drop ALL · no-new-privileges · CPU/memory limits · start only after the firewall healthcheck passes</text>')
# firewall
box(1060,262,1380,312,*R,"Firewall service",["DOCKER-USER: LOG + DROP outbound","host network · re-checked every 30 s"],tsize=13)
arrow([(1220,262),(1220,240)],color="#b33a3a",dash=True)
out.append('<text x="1228" y="256" font-size="11" font-style="italic" fill="#b33a3a">enforces</text>')
# backnet
group(20,316,1380,830,"#2c4a85","#f3f6fb","backnet (internal: true) — no route to the internet, not published to the host")
box(50,345,470,460,*B,"PostgreSQL 16",["sessions · events (GIN full-text) · file_captures","detections · attackers · campaigns","iocs · ioc_sightings · alerts · intel_state"])
box(490,345,910,460,*B,"Redis 7.2",["device:* · history:sensor · changes:*","pub/sub honeybot:events / :detections / :state","service heartbeats"])
box(930,345,1350,460,*B,"Device State Manager",["device_state.py — every 5 s","telemetry · alarms · auto re-lock"])
box(50,495,470,615,*O,"Threat Intelligence Engine",["intel/engine.py — every 30 s","YARA → rules (16 classes) → MITRE","→ correlate + GeoIP + IOCs → notify()","daily / weekly PDF report"])
box(490,495,910,615,*B,"REST + WebSocket API (FastAPI)",["api/api.py · port 5000 (internal)","stats · attackers · sessions · devices · search","STIX 2.1 · PDF · CSV · ML dataset · /metrics","/api/ws live push"])
box(930,495,1350,615,*O,"Alert Notifier",["alerts.yaml thresholds","10-min dedupe + escalation","Telegram Bot API · SMTP e-mail"])
box(50,665,330,770,*GR,"captures volume",["quarantine, mode 0400","never executed or served"],dash=True)
box(350,665,650,770,*B,"Backup service",["pg_dump + samples archive","SHA-256 manifest → ./backups","verify · restore · retention"])
# arrows into backnet
arrow([(225,240),(225,345)],label="Session.log_event() → async writer → events",lpos=(233,300))
arrow([(700,240),(700,345)],label="device state read/write · publish events",lpos=(708,300))
arrow([(32,240),(32,717),(50,717)],label="capture.store()",lpos=(38,650))
arrow([(930,402),(910,402)])
out.append('<text x="920" y="390" font-size="11" font-style="italic" text-anchor="middle" fill="#333">state</text>')
arrow([(260,495),(260,460)],label="read events / write detections",lpos=(268,482))
arrow([(190,665),(190,615)],label="YARA scan (read-only)",lpos=(197,645))
arrow([(600,495),(470,415)],label="SQL",lpos=(540,450))
arrow([(760,495),(760,460)],label="subscribe",lpos=(767,482))
arrow([(470,600),(510,640),(1140,640),(1140,615)],dash=True,label="new detections → notify()",lpos=(900,656))
arrow([(480,665),(480,450),(470,450)],dash=True,label="pg_dump",lpos=(486,652))
arrow([(330,740),(350,740)],dash=True)
# frontnet
group(560,860,1240,1015,"#7b3f98","#f9f3fb","frontnet — the ONLY published dashboard port")
box(590,880,880,965,*P,"Nginx 1.26 · :80",["bcrypt basic auth (auth-init)","CSP · /api + /api/ws proxy"])
box(930,880,1220,965,*P,"SOC Dashboard",["React 19 + TypeScript SPA","offline d3-geo map · live WebSocket"])
arrow([(880,922),(930,922)])
arrow([(780,615),(780,880)],label="/api/* and /api/ws (proxy)",lpos=(787,845))
box(1255,900,1390,958,*O,"Security Analyst",["phone / inbox"],tsize=13)
arrow([(1320,615),(1320,900)],color="#b37a1a",label="Telegram / e-mail",lpos=(1314,845),anchor="end")
out.append('<text x="1326" y="862" font-size="11" font-style="italic" fill="#b37a1a">egress</text>')
box(40,872,520,960,*GR,"Monitoring profile (optional)",["Prometheus · Grafana · cAdvisor (127.0.0.1 only)","scrapes /api/metrics and container metrics"],dash=True,tsize=13.5)
defs="".join(f'<marker id="ah{c[1:]}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>' for c in colors)
svg=f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="Liberation Sans, Arial, sans-serif"><defs>{defs}</defs><rect width="100%" height="100%" fill="white"/>{"".join(out)}</svg>'
open(sys.argv[1],"w").write(svg)
