-- ═══════════════════════════════════════════════════════════════════════════
--  HoneyBot-IoT — PostgreSQL schema (v0.7 — 70% milestone)
--
--  One unified event store:
--    sessions   one row per attacker connection (any protocol)
--    events     every single interaction, written through common.db.log_event
--    attackers  per-IP correlation + GeoIP   (filled by the intel engine)
--    campaigns  IPs grouped by shared credential sets (cross-session correlation)
--    detections rule-based classifications + MITRE ATT&CK technique IDs
--    iocs       indicators of compromise (URLs, hashes, IPs, domains)
--    alerts     notification log (Telegram / e-mail) incl. dedupe decisions
--    file_captures  stored malware samples: SHA-256, MIME/arch, YARA verdict (v0.7)
--    ioc_sightings  one row per IOC observation, so iocs.hits is exact (v0.7)
--  The whole file is idempotent: the API / intel engine re-apply it at start-up,
--  which upgrades an existing v0.6 database in place.
--  The old per-protocol tables are kept as VIEWS so older queries still work.
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS sessions (
    session_id     UUID PRIMARY KEY,
    ip             TEXT        NOT NULL,
    src_port       INTEGER,
    dst_port       INTEGER,
    device         TEXT        NOT NULL,          -- cctv | smartlock | sensor
    protocol       TEXT        NOT NULL,          -- SSH | Telnet | HTTP | MQTT | RTSP
    started_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at       TIMESTAMPTZ,
    auth_attempts  INTEGER     NOT NULL DEFAULT 0,
    login_success  BOOLEAN     NOT NULL DEFAULT FALSE,
    username       TEXT,
    commands       INTEGER     NOT NULL DEFAULT 0,
    client_version TEXT,
    meta           JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_sessions_ip       ON sessions(ip);
CREATE INDEX IF NOT EXISTS idx_sessions_started  ON sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_sessions_protocol ON sessions(protocol);

CREATE TABLE IF NOT EXISTS events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_id  UUID REFERENCES sessions(session_id) ON DELETE CASCADE,
    ip          TEXT        NOT NULL,
    src_port    INTEGER,
    device      TEXT        NOT NULL,
    protocol    TEXT        NOT NULL,
    event_type  TEXT        NOT NULL,   -- connect|disconnect|auth|command|http_request|
                                        -- mqtt_connect|mqtt_publish|mqtt_subscribe|
                                        -- rtsp_request|download_attempt|file_write|
                                        -- state_change|malformed
    username    TEXT,
    password    TEXT,
    success     BOOLEAN,
    command     TEXT,
    payload     TEXT,
    raw         JSONB       NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_ip_ts     ON events(ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_session   ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_type_ts   ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS idx_events_proto_ts  ON events(protocol, ts);
-- Full-text search across commands and payloads (scope M3: log indexing)
CREATE INDEX IF NOT EXISTS idx_events_fts ON events
    USING GIN (to_tsvector('simple', coalesce(command,'') || ' ' || coalesce(payload,'')));

CREATE TABLE IF NOT EXISTS attackers (
    ip            TEXT PRIMARY KEY,
    first_seen    TIMESTAMPTZ,
    last_seen     TIMESTAMPTZ,
    sessions      INTEGER  DEFAULT 0,
    events        INTEGER  DEFAULT 0,
    auth_attempts INTEGER  DEFAULT 0,
    auth_success  INTEGER  DEFAULT 0,
    commands      INTEGER  DEFAULT 0,
    downloads     INTEGER  DEFAULT 0,
    protocols     TEXT[]   DEFAULT '{}',
    devices       TEXT[]   DEFAULT '{}',
    country       TEXT,
    country_code  TEXT,
    city          TEXT,
    lat           DOUBLE PRECISION,
    lon           DOUBLE PRECISION,
    geo_source    TEXT,              -- maxmind | dbip | demo | private | unknown
    campaign_id   TEXT,
    threat_level  TEXT     DEFAULT 'LOW',
    threat_score  INTEGER  DEFAULT 0,
    attack_types  TEXT[]   DEFAULT '{}',
    updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id  TEXT PRIMARY KEY,
    fingerprint  TEXT NOT NULL,
    first_seen   TIMESTAMPTZ,
    last_seen    TIMESTAMPTZ,
    ips          TEXT[] DEFAULT '{}',
    credentials  TEXT[] DEFAULT '{}',
    description  TEXT
);

CREATE TABLE IF NOT EXISTS detections (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip          TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    severity    TEXT NOT NULL,
    protocol    TEXT,
    device      TEXT,
    details     TEXT,
    mitre       TEXT[] DEFAULT '{}',   -- e.g. {T1110,T1078}
    mitre_names TEXT[] DEFAULT '{}',
    session_id  UUID,
    dedupe_key  TEXT UNIQUE,
    alerted     BOOLEAN DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_detections_ip ON detections(ip);
CREATE INDEX IF NOT EXISTS idx_detections_ts ON detections(timestamp);

CREATE TABLE IF NOT EXISTS iocs (
    id          BIGSERIAL PRIMARY KEY,
    type        TEXT NOT NULL,            -- url | domain | ipv4 | sha256
    value       TEXT NOT NULL,
    first_seen  TIMESTAMPTZ DEFAULT NOW(),
    last_seen   TIMESTAMPTZ DEFAULT NOW(),
    source_ip   TEXT,
    session_id  UUID,
    protocol    TEXT,
    context     TEXT,
    hits        INTEGER DEFAULT 1,
    UNIQUE (type, value)
);

CREATE TABLE IF NOT EXISTS alerts (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ DEFAULT NOW(),
    detection_id BIGINT REFERENCES detections(id) ON DELETE SET NULL,
    ip           TEXT,
    attack_type  TEXT,
    severity     TEXT,
    channel      TEXT,      -- telegram | email | log
    status       TEXT,      -- sent | suppressed | failed | disabled
    message      TEXT,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

-- ── v0.7: malware sample store (SDS data dictionary: file_captures) ─────────
CREATE TABLE IF NOT EXISTS file_captures (
    id            BIGSERIAL PRIMARY KEY,
    ts            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_id    UUID,
    ip            TEXT NOT NULL,
    protocol      TEXT,
    device        TEXT,
    source        TEXT NOT NULL,          -- http_upload | http_body | shell_write | ssh_stdin | mqtt_payload
    filename      TEXT,
    sha256        CHAR(64) NOT NULL,
    md5           CHAR(32),
    size          BIGINT NOT NULL,
    mime_type     TEXT,
    arch          TEXT,                   -- ELF machine, e.g. ARM / MIPS / x86-64
    storage_path  TEXT,                   -- quarantine path (non-executable volume)
    yara_result   TEXT,                   -- 'CLEAN' | comma-separated rule names | NULL = not scanned
    yara_matches  TEXT[] DEFAULT '{}',
    scanned_at    TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_captures_sha ON file_captures(sha256);
CREATE INDEX IF NOT EXISTS idx_captures_ts  ON file_captures(ts);
CREATE INDEX IF NOT EXISTS idx_captures_unscanned ON file_captures(id) WHERE scanned_at IS NULL;

-- ── v0.7: exact IOC hit counting ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS ioc_sightings (
    source     TEXT   NOT NULL,           -- event | detection | capture
    source_id  BIGINT NOT NULL,
    type       TEXT   NOT NULL,
    value      TEXT   NOT NULL,
    seen_at    TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (source, source_id, type, value)
);

-- ── v0.7: small key/value store for the intel engine (report schedule etc.) ─
CREATE TABLE IF NOT EXISTS intel_state (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Backwards-compatible views (old per-protocol tables) ────────────────────
CREATE OR REPLACE VIEW ssh_attempts AS
    SELECT id, ts AS timestamp, ip, src_port AS port, username, password,
           COALESCE(success,false) AS accepted
    FROM events WHERE protocol='SSH' AND event_type='auth';

CREATE OR REPLACE VIEW telnet_attempts AS
    SELECT id, ts AS timestamp, ip, username, password,
           COALESCE(success,false) AS accepted
    FROM events WHERE protocol='Telnet' AND event_type='auth';

CREATE OR REPLACE VIEW http_attempts AS
    SELECT id, ts AS timestamp, ip, username, password,
           COALESCE(success,false) AS accepted, raw->>'user_agent' AS user_agent
    FROM events WHERE protocol='HTTP' AND event_type='auth';

CREATE OR REPLACE VIEW mqtt_attempts AS
    SELECT id, ts AS timestamp, ip, raw->>'client_id' AS client_id, username, password,
           upper(replace(event_type,'mqtt_','')) AS action,
           raw->>'topic' AS topic, payload, COALESCE(success,false) AS accepted
    FROM events WHERE protocol='MQTT';

CREATE OR REPLACE VIEW rtsp_attempts AS
    SELECT id, ts AS timestamp, ip, username, password,
           COALESCE(success,false) AS accepted, raw->>'method' AS method, raw->>'url' AS url
    FROM events WHERE protocol='RTSP' AND event_type IN ('auth','rtsp_request');
