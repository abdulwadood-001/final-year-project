import html, sys
W,H=1400,1190
o=[]
e=html.escape
C={'blue':('#2c4a85','#e8eef8'),'orange':('#b37a1a','#fdf2e1'),'green':('#3d7a2a','#e7f2e0'),'red':('#9a2f6b','#f7e6f0')}
RH=21
def ent(x,y,name,rows,color,w=340):
    s,f=C[color]; h=32+len(rows)*RH+10
    o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="white" stroke="{s}" stroke-width="2"/>')
    o.append(f'<rect x="{x}" y="{y}" width="{w}" height="32" fill="{f}" stroke="{s}" stroke-width="2"/>')
    o.append(f'<text x="{x+w/2}" y="{y+22}" font-size="16" font-weight="bold" text-anchor="middle">{e(name)}</text>')
    for i,(k,n,t) in enumerate(rows):
        yy=y+32+18+i*RH
        if k: o.append(f'<text x="{x+10}" y="{yy}" font-size="12.5" font-weight="bold" fill="{"#c0392b" if k=="PK" else "#2c4a85"}">{k}</text>')
        o.append(f'<text x="{x+42}" y="{yy}" font-size="13" {"font-weight=\"bold\"" if k=="PK" else ""}>{e(n)}</text>')
        o.append(f'<text x="{x+w-10}" y="{yy}" font-size="11.5" fill="#666" text-anchor="end">{e(t)}</text>')
    return (x,y,w,h)
def line(pts,dash=False,label=None,lp=None,m1=None,p1=None,m2=None,p2=None):
    d=' stroke-dasharray="6,4"' if dash else ''
    o.append(f'<polyline points="{" ".join(f"{a},{b}" for a,b in pts)}" fill="none" stroke="#444" stroke-width="1.6"{d}/>')
    if label: o.append(f'<text x="{lp[0]}" y="{lp[1]}" font-size="11.5" font-style="italic" fill="#444">{e(label)}</text>')
    for m,p in ((m1,p1),(m2,p2)):
        if m: o.append(f'<text x="{p[0]}" y="{p[1]}" font-size="13" font-weight="bold">{m}</text>')
sess=ent(30,30,"sessions",[("PK","session_id","UUID"),("","ip","TEXT"),("","src_port / dst_port","INTEGER"),("","device","TEXT"),("","protocol","TEXT"),("","started_at / ended_at","TIMESTAMPTZ"),("","auth_attempts","INTEGER"),("","login_success","BOOLEAN"),("","username","TEXT"),("","commands","INTEGER"),("","client_version","TEXT"),("","meta","JSONB")],'blue')
ev=ent(530,30,"events",[("PK","id","BIGSERIAL"),("","ts","TIMESTAMPTZ"),("FK","session_id","UUID"),("","ip / src_port","TEXT / INT"),("","device / protocol","TEXT"),("","event_type","TEXT"),("","username / password","TEXT"),("","success","BOOLEAN"),("","command","TEXT"),("","payload","TEXT"),("","raw","JSONB"),("IX","GIN to_tsvector(command‖payload)","")],'blue')
att=ent(1030,30,"attackers",[("PK","ip","TEXT"),("","first_seen / last_seen","TIMESTAMPTZ"),("","sessions / events","INTEGER"),("","auth_attempts / auth_success","INTEGER"),("","commands / downloads","INTEGER"),("","protocols / devices","TEXT[]"),("","country / city","TEXT"),("","lat / lon","DOUBLE"),("","geo_source","TEXT"),("FK","campaign_id","TEXT"),("","threat_level / threat_score","TEXT / INT"),("","attack_types","TEXT[]")],'blue')
det=ent(30,430,"detections",[("PK","id","BIGSERIAL"),("","timestamp","TIMESTAMPTZ"),("","ip","TEXT"),("","attack_type / severity","TEXT"),("","protocol / device","TEXT"),("","details","TEXT"),("","mitre / mitre_names","TEXT[]"),("FK","session_id → sessions","UUID"),("UQ","dedupe_key","TEXT"),("","alerted","BOOLEAN")],'orange')
al=ent(530,470,"alerts",[("PK","id","BIGSERIAL"),("","ts","TIMESTAMPTZ"),("FK","detection_id","BIGINT"),("","ip / attack_type / severity","TEXT"),("","channel","telegram|email|dedupe"),("","status","sent|suppressed|…"),("","message / error","TEXT")],'orange')
cmp_=ent(1030,430,"campaigns",[("PK","campaign_id","TEXT"),("","fingerprint","TEXT"),("","first_seen / last_seen","TIMESTAMPTZ"),("","ips","TEXT[]"),("","credentials","TEXT[]"),("","description","TEXT")],'green')
fc=ent(30,790,"file_captures  (new in v0.7)",[("PK","id","BIGSERIAL"),("","ts","TIMESTAMPTZ"),("","session_id → sessions","UUID"),("","ip / protocol / device","TEXT"),("","source / filename","TEXT"),("IX","sha256","CHAR(64)"),("","md5","CHAR(32)"),("","size","BIGINT"),("","mime_type / arch","TEXT"),("","storage_path","TEXT"),("","yara_result","TEXT"),("","yara_matches","TEXT[]"),("IX","scanned_at (partial: NULL)","TIMESTAMPTZ")],'red')
iocs=ent(1030,700,"iocs",[("PK","id","BIGSERIAL"),("UQ","(type, value)","url|domain|ipv4|sha256"),("","first_seen / last_seen","TIMESTAMPTZ"),("","source_ip","TEXT"),("FK","session_id → sessions","UUID"),("","protocol / context","TEXT"),("","hits = distinct sightings","INTEGER")],'green')
sig=ent(530,760,"ioc_sightings  (new in v0.7)",[("PK","source","event|detection|capture"),("PK","source_id","BIGINT"),("PK","type","TEXT"),("PK","value","TEXT"),("","seen_at","TIMESTAMPTZ")],'red')
ist=ent(530,1000,"intel_state  (new in v0.7)",[("PK","key","TEXT"),("","value","TEXT"),("","updated_at","TIMESTAMPTZ")],'red')
# relations
line([(370,170),(530,170)],label="session_id",lp=(420,192),m1="1",p1=(376,164),m2="∞",p2=(512,164))
line([(870,140),(1030,140)],label="aggregated by ip",lp=(900,162),m1="∞",p1=(876,134),m2="1",p2=(1016,134))
line([(200,324),(200,430)],label="session_id",lp=(208,400),m1="0..1",p1=(208,342),m2="∞",p2=(208,426))
line([(370,620),(530,620)],label="detection_id",lp=(410,642),m1="1",p1=(376,614),m2="∞",p2=(512,614))
line([(1200,324),(1200,430)],label="campaign_id",lp=(1208,400),m1="∞",p1=(1208,342),m2="0..1",p2=(1170,426))
line([(15,170),(15,850),(30,850)],dash=True,label="session_id (logical)",lp=(20,770),m1="1",p1=(18,162),m2="∞",p2=(18,843))
o.append('<line x1="15" y1="170" x2="30" y2="170" stroke="#444" stroke-width="1.6" stroke-dasharray="6,4"/>')
line([(870,830),(1030,830)],dash=True,label="(type, value)",lp=(910,852),m1="∞",p1=(876,824),m2="1",p2=(1016,824))
line([(370,880),(530,880)],dash=True,label="source = capture",lp=(392,902),m1="1",p1=(376,874),m2="∞",p2=(512,874))
o.append('<text x="30" y="1170" font-size="12.5" fill="#333">Legend: PK primary key · FK reference · UQ unique · IX index · dashed line = logical link (no foreign-key constraint). Compatibility VIEWS ssh_attempts … rtsp_attempts are defined over events.</text>')
o.append('<text x="890" y="1060" font-size="12" fill="#555">engine key/value store, e.g. last_daily_report</text>')
svg=f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="Liberation Sans, Arial, sans-serif"><rect width="100%" height="100%" fill="white"/>{"".join(o)}</svg>'
open(sys.argv[1],'w').write(svg)
