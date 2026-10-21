// Turns the raw event rows of GET /api/sessions/{id} into the "attacker input vs
// honeypot output" replay the session page shows.
import type { SessionEvent } from "./api";

export type ReplayLine = {
  ts: string;
  type: string;
  detail: string;
  dir: "in" | "out";
  mitre?: { id: string; name: string }[];
  tone?: "critical" | "high" | "ok" | "muted";
};

const s = (v: unknown) => (v == null ? "" : String(v));

export function toReplay(events: SessionEvent[], protocol: string): ReplayLine[] {
  const out: ReplayLine[] = [];
  for (const e of events) {
    const raw = e.raw ?? {};
    const base = { ts: e.ts, type: e.event_type };
    switch (e.event_type) {
      case "connect":
        out.push({
          ...base,
          dir: "in",
          detail: `TCP connection → port ${s(raw["dst_port"]) || "?"} (${protocol})`,
        });
        break;
      case "auth": {
        const method = s(raw["method"] ?? raw["mqtt_action"]);
        out.push({
          ...base,
          dir: "in",
          detail: `${s(e.username) || "(empty)"}:${s(e.password) || "(empty)"} → ${e.success ? "accepted" : "rejected"}${method ? ` (${method})` : ""}`,
          tone: e.success ? "critical" : "muted",
        });
        break;
      }
      case "command": {
        const line: ReplayLine = { ...base, dir: "in", detail: s(e.command) };
        if (e.mitre?.length) line.mitre = e.mitre;
        out.push(line);
        if (e.payload) out.push({ ts: e.ts, type: "output", dir: "out", detail: e.payload });
        break;
      }
      case "http_request":
        out.push({ ...base, dir: "in", detail: s(e.command) });
        out.push({
          ts: e.ts,
          type: "response",
          dir: "out",
          detail: `HTTP ${s(raw["status"])}${e.payload ? ` · body: ${e.payload.slice(0, 160)}` : ""}`,
        });
        break;
      case "rtsp_request":
        out.push({ ...base, dir: "in", detail: s(e.command) });
        break;
      case "mqtt_publish":
        out.push({
          ...base,
          dir: "in",
          detail: `PUBLISH ${s(raw["topic"])} → ${s(e.payload).slice(0, 200)}`,
          tone: raw["control"] ? "high" : undefined,
        } as ReplayLine);
        break;
      case "mqtt_subscribe":
        out.push({ ...base, dir: "in", detail: `SUBSCRIBE ${s(e.payload)}` });
        break;
      case "download_attempt":
        out.push({
          ...base,
          dir: "out",
          detail: `download URL logged as IOC (never fetched): ${s(e.payload)}`,
          tone: "high",
        });
        break;
      case "file_capture":
        out.push({
          ...base,
          dir: "out",
          detail: `sample quarantined · ${s(raw["mime_type"])}${raw["arch"] ? ` · ${s(raw["arch"])}` : ""} · sha256 ${s(raw["sha256"]).slice(0, 16)}…`,
          tone: "critical",
        });
        break;
      case "exec_attempt":
        out.push({
          ...base,
          dir: "in",
          detail: `execute ${s(e.payload)} ${s(raw["args"])}`.trim(),
          tone: "critical",
        });
        break;
      case "state_change":
        out.push({
          ...base,
          dir: "out",
          detail: `device state changed: ${s(e.payload)}`,
          tone: "critical",
        });
        break;
      case "disconnect":
        out.push({
          ...base,
          dir: "out",
          detail: `session closed (${s(raw["reason"]) || "closed"}, ${s(raw["duration"])} s)`,
          tone: "muted",
        });
        break;
      default: {
        const detail =
          e.command ||
          e.payload ||
          Object.entries(raw)
            .map(([k, v]) => `${k}=${s(v)}`)
            .join(" ");
        out.push({ ...base, dir: "in", detail: detail || "—" });
      }
    }
  }
  return out.map((l) => {
    if (l.tone === undefined) delete l.tone;
    return l;
  });
}
