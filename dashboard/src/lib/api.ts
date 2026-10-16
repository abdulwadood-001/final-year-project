// Typed client for the HoneyBot-IoT API (api/api.py). Every page reads live data
// through these hooks; nothing in the dashboard is mocked.
import { useQuery, keepPreviousData } from "@tanstack/react-query";

export const API_BASE = "/api";

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { headers: { Accept: "application/json" }, ...init });
  } catch {
    throw new ApiError("API unreachable — is the honeybot_api container running?", 0);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = (await res.json()) as { detail?: unknown };
      if (typeof body.detail === "string") detail = body.detail;
    } catch {
      /* not JSON */
    }
    throw new ApiError(`${res.status} ${detail}`, res.status);
  }
  return (await res.json()) as T;
}

// ── models (mirror the SQL in api/api.py) ───────────────────────────────────
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export const PROTOCOLS = ["SSH", "Telnet", "HTTP", "MQTT", "RTSP"] as const;

export type Stats = {
  version: string;
  sessions: Record<string, number>;
  auth_attempts: Record<string, number>;
  total_sessions: number;
  total_events: number;
  events_24h: number;
  unique_ips: number;
  successful_logins: number;
  commands: number;
  detections: number;
  critical: number;
  iocs: number;
  samples: number;
  malicious_samples: number;
  alerts_sent: number;
  active_sessions: number;
  services_up: number;
  services_total: number;
};

export type AttackEvent = {
  id?: number;
  ts: string;
  ip: string;
  protocol: string;
  device: string;
  event_type: string;
  username: string | null;
  password: string | null;
  success: boolean | null;
  command: string | null;
  payload: string | null;
  session_id: string | null;
  country_code?: string | null;
  country?: string | null;
};

export type Attacker = {
  ip: string;
  attempts?: number;
  events?: number;
  sessions?: number;
  auth_attempts?: number;
  auth_success?: number;
  commands?: number;
  downloads?: number;
  protocols?: string[] | null;
  devices?: string[] | null;
  country?: string | null;
  country_code?: string | null;
  city?: string | null;
  geo_source?: string | null;
  threat_level: Severity;
  threat_score: number;
  campaign_id?: string | null;
  attack_types?: string[] | null;
  first_seen?: string | null;
  last_seen?: string | null;
  note?: string;
};

export type TimelinePoint = { hour: string } & Record<
  "ssh" | "telnet" | "http" | "mqtt" | "rtsp",
  number
>;

export type Detection = {
  id: number;
  timestamp: string;
  ip: string;
  attack_type: string;
  severity: Severity;
  protocol: string | null;
  device: string | null;
  details: string;
  mitre: string[] | null;
  mitre_names: string[] | null;
  session_id?: string | null;
  alerted?: boolean;
  country_code?: string | null;
};

export type Ioc = {
  type: string;
  value: string;
  first_seen: string;
  last_seen: string;
  source_ip: string | null;
  protocol: string | null;
  hits: number;
  context: string | null;
};

export type MitreRow = { technique: string; name: string; detections: number; ips: number };
export type CredRow = {
  username: string | null;
  password: string | null;
  count: number;
  protocols?: string;
  worked: boolean;
};
export type CommandRow = { command: string; count: number };

export type MapPoint = {
  ip: string;
  lat: number;
  lon: number;
  city: string | null;
  country: string | null;
  country_code: string | null;
  geo_source: string | null;
  events: number;
  threat_level: Severity;
  threat_score: number;
  protocols: string[] | null;
};

export type Service = {
  up: boolean;
  uptime?: number;
  port?: number;
  protocol?: string;
  ts?: string;
};
export type DeviceSummary = {
  name: string;
  protocols: string[];
  services: string[];
  state: Record<string, string>;
  online: boolean;
  active_sessions: number;
  last_attack: string | null;
  events_24h: number;
  detections_24h: number;
};
export type DevicesResponse = {
  devices: Record<string, DeviceSummary>;
  services: Record<string, Service>;
  active_by_protocol: Record<string, number>;
};

export type SessionRow = {
  session_id: string;
  ip: string;
  src_port: number | null;
  dst_port: number | null;
  device?: string;
  protocol: string;
  started_at: string;
  ended_at: string | null;
  auth_attempts: number;
  login_success: boolean;
  username: string | null;
  commands: number;
  client_version: string | null;
};

export type StateChange = { ts: string; actor: string; fields: Record<string, string> };
export type SensorSample = {
  ts: string;
  temperature: number;
  pressure: number;
  humidity: number;
  alarm: string;
};

export type DeviceDetail = DeviceSummary & {
  device: string;
  services_detail: Record<string, Service>;
  changes: StateChange[];
  sessions: SessionRow[];
  events: AttackEvent[];
  detections: Detection[];
  credentials: CredRow[];
  history?: SensorSample[];
  stream_paths?: { path: string; requests: number; ips: number }[];
  stream_opens?: number;
  web_logins?: Record<string, number>;
};

export type Sample = {
  sha256: string;
  md5: string | null;
  size: number;
  mime_type: string | null;
  arch: string | null;
  yara_result: string | null;
  yara_rules: string | null;
  first_seen: string;
  last_seen: string;
  times: number;
  ips: string[];
  protocols: (string | null)[];
  sources: string[];
  filename: string | null;
  scanned: boolean;
};

export type SessionEvent = {
  id: number;
  ts: string;
  event_type: string;
  username: string | null;
  password: string | null;
  success: boolean | null;
  command: string | null;
  payload: string | null;
  raw: Record<string, unknown>;
  mitre?: { id: string; name: string }[];
};

export type SessionDetail = {
  session: SessionRow & { meta?: Record<string, unknown> };
  events: SessionEvent[];
  detections: Detection[];
  samples: Pick<Sample, "sha256" | "filename" | "size" | "mime_type" | "arch" | "yara_result">[];
};

export type AttackerDetail = {
  attacker: Attacker;
  campaign: Campaign | null;
  sessions: SessionRow[];
  events: AttackEvent[];
  detections: Detection[];
  iocs: Ioc[];
  samples: (Pick<Sample, "sha256" | "filename" | "size" | "mime_type" | "arch" | "yara_result"> & {
    ts: string;
    source: string;
    protocol: string | null;
  })[];
  credentials: CredRow[];
};

export type Campaign = {
  campaign_id: string;
  fingerprint: string;
  first_seen: string | null;
  last_seen: string | null;
  ips: string[];
  credentials: string[];
  description: string;
};

export type AlertRow = {
  id: number;
  ts: string;
  ip: string;
  attack_type: string;
  severity: Severity;
  channel: string;
  status: string;
  error: string | null;
  detection_id: number | null;
};

export type Report = {
  generated_at: string;
  window_hours: number;
  summary: string;
  totals: Record<string, number>;
  events_by_protocol: Record<string, number>;
  detections_by_severity: Record<string, number>;
  detections_by_type: { attack_type: string; count: number; max_severity: Severity }[];
};

export type MlSummary = {
  sessions: number;
  classes: Record<string, number>;
  features: string[];
  label_source: string;
};

// ── query hooks ─────────────────────────────────────────────────────────────
// Live data refreshes on an interval; the WebSocket (live.tsx) additionally pushes
// events and detections the moment they happen.
const FAST = 10_000;
const SLOW = 30_000;

export const useStats = () =>
  useQuery({ queryKey: ["stats"], queryFn: () => api<Stats>("/stats"), refetchInterval: FAST });
export const useTimeline = (hours = 24) =>
  useQuery({
    queryKey: ["timeline", hours],
    queryFn: () => api<TimelinePoint[]>(`/timeline?hours=${hours}`),
    refetchInterval: SLOW,
  });
export const useRecent = (limit = 40) =>
  useQuery({
    queryKey: ["recent", limit],
    queryFn: () => api<AttackEvent[]>(`/attacks/recent?limit=${limit}`),
    refetchInterval: FAST,
  });
export const useTopAttackers = (limit = 50) =>
  useQuery({
    queryKey: ["attackers", limit],
    queryFn: () => api<Attacker[]>(`/attackers/top?limit=${limit}`),
    refetchInterval: SLOW,
  });
export const useAttacker = (ip: string) =>
  useQuery({
    queryKey: ["attacker", ip],
    queryFn: () => api<AttackerDetail>(`/attackers/${encodeURIComponent(ip)}`),
    refetchInterval: SLOW,
  });
export const useDetections = (
  params: { severity?: string; attack_type?: string; limit?: number } = {},
) => {
  const q = new URLSearchParams({ limit: String(params.limit ?? 100) });
  if (params.severity) q.set("severity", params.severity);
  if (params.attack_type) q.set("attack_type", params.attack_type);
  return useQuery({
    queryKey: ["detections", params],
    queryFn: () => api<Detection[]>(`/detections?${q.toString()}`),
    refetchInterval: FAST,
    placeholderData: keepPreviousData,
  });
};
export const useMitre = () =>
  useQuery({
    queryKey: ["mitre"],
    queryFn: () => api<MitreRow[]>("/mitre/summary"),
    refetchInterval: SLOW,
  });
export const useIocs = (type?: string, limit = 200) =>
  useQuery({
    queryKey: ["iocs", type, limit],
    queryFn: () =>
      api<Ioc[]>(`/iocs?limit=${limit}${type ? `&type=${encodeURIComponent(type)}` : ""}`),
    refetchInterval: SLOW,
    placeholderData: keepPreviousData,
  });
export const useCreds = (limit = 12) =>
  useQuery({
    queryKey: ["creds", limit],
    queryFn: () => api<CredRow[]>(`/credentials/top?limit=${limit}`),
    refetchInterval: SLOW,
  });
export const useCommands = (limit = 12) =>
  useQuery({
    queryKey: ["commands", limit],
    queryFn: () => api<CommandRow[]>(`/commands/top?limit=${limit}`),
    refetchInterval: SLOW,
  });
export const useMap = () =>
  useQuery({ queryKey: ["map"], queryFn: () => api<MapPoint[]>("/map"), refetchInterval: SLOW });
export const useDevices = () =>
  useQuery({
    queryKey: ["devices"],
    queryFn: () => api<DevicesResponse>("/devices"),
    refetchInterval: FAST,
  });
export const useDevice = (device: string) =>
  useQuery({
    queryKey: ["device", device],
    queryFn: () => api<DeviceDetail>(`/devices/${encodeURIComponent(device)}`),
    refetchInterval: 5_000,
  });
export const useSessions = (
  params: { protocol?: string; active?: boolean; limit?: number } = {},
) => {
  const q = new URLSearchParams({ limit: String(params.limit ?? 200) });
  if (params.protocol) q.set("protocol", params.protocol);
  if (params.active) q.set("active", "true");
  return useQuery({
    queryKey: ["sessions", params],
    queryFn: () => api<SessionRow[]>(`/sessions/list?${q.toString()}`),
    refetchInterval: FAST,
    placeholderData: keepPreviousData,
  });
};
export const useSession = (id: string) =>
  useQuery({
    queryKey: ["session", id],
    queryFn: () => api<SessionDetail>(`/sessions/${encodeURIComponent(id)}`),
    refetchInterval: FAST,
  });
export const useCaptures = () =>
  useQuery({
    queryKey: ["captures"],
    queryFn: () => api<Sample[]>("/captures?limit=500"),
    refetchInterval: SLOW,
  });
export const useAlerts = () =>
  useQuery({
    queryKey: ["alerts"],
    queryFn: () => api<AlertRow[]>("/alerts?limit=200"),
    refetchInterval: SLOW,
  });
export const useCampaigns = () =>
  useQuery({
    queryKey: ["campaigns"],
    queryFn: () => api<Campaign[]>("/campaigns"),
    refetchInterval: SLOW,
  });
export const useReport = (hours: number) =>
  useQuery({
    queryKey: ["report", hours],
    queryFn: () => api<Report>(`/report?hours=${hours}`),
    refetchInterval: 60_000,
  });
export const useMlSummary = () =>
  useQuery({
    queryKey: ["ml"],
    queryFn: () => api<MlSummary>("/ml/summary"),
    refetchInterval: 60_000,
  });
export const useSearch = (q: string) =>
  useQuery({
    queryKey: ["search", q],
    queryFn: () =>
      api<(AttackEvent & { username: string | null })[]>(
        `/search?q=${encodeURIComponent(q)}&limit=300`,
      ),
    enabled: q.trim().length >= 2,
  });

export async function runDetectionPass() {
  return api<{ status: string; new_detections: number; samples_scanned: number }>("/detect", {
    method: "POST",
  });
}

// ── helpers ─────────────────────────────────────────────────────────────────
/** Postgres arrays arrive as string[]; older rows or mocks may use "A,B". */
export function list(v: string[] | string | null | undefined): string[] {
  if (!v) return [];
  return Array.isArray(v)
    ? v.filter(Boolean)
    : v
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
}

/** "Telnet" / "TELNET" / "telnet" → the canonical protocol label used by the backend. */
export function protoLabel(p: string | null | undefined): string {
  if (!p) return "—";
  const hit = PROTOCOLS.find((x) => x.toLowerCase() === p.toLowerCase());
  return hit ?? p;
}

export function shortId(id: string | null | undefined, n = 8) {
  return id ? id.slice(0, n) : "—";
}

export function fmtBytes(n: number | null | undefined) {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function fmtTime(iso: string | null | undefined) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function isMalicious(verdict: string | null | undefined) {
  return !!verdict && !["CLEAN", "UNAVAILABLE", "ERROR"].includes(verdict);
}
