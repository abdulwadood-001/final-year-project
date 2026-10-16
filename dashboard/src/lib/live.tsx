// Live push from GET /api/ws (FastAPI relays Redis pub/sub). Pushed rows are merged
// into the React Query cache so feeds update instantly; polling stays on as a
// fallback, so the dashboard keeps working if the WebSocket is blocked.
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import type { AttackEvent, Detection } from "./api";

export type LiveStatus = "connecting" | "live" | "offline";

type LiveCtx = {
  status: LiveStatus;
  eventsPerMin: number;
  toasts: Toast[];
  dismiss: (id: number) => void;
};
export type Toast = { id: number; detection: Detection };

const Ctx = createContext<LiveCtx>({
  status: "connecting",
  eventsPerMin: 0,
  toasts: [],
  dismiss: () => {},
});

export const useLive = () => useContext(Ctx);

function wsUrl() {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/api/ws`;
}

/** Prepend `row` to every cached list whose key starts with `prefix` (dedupe by id). */
function prepend<T extends { id?: number }>(qc: QueryClient, prefix: string, row: T, max = 500) {
  qc.setQueriesData<T[]>({ queryKey: [prefix] }, (old) => {
    if (!Array.isArray(old)) return old;
    if (row.id != null && old.some((r) => r.id === row.id)) return old;
    return [row, ...old].slice(0, Math.max(old.length, Math.min(max, old.length + 1)));
  });
}

export function LiveProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const [status, setStatus] = useState<LiveStatus>("connecting");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [eventsPerMin, setEpm] = useState(0);
  const stamps = useRef<number[]>([]);
  const dirty = useRef(new Set<string>());

  // throttled invalidation of aggregate queries (counts, charts) – at most every 3 s
  useEffect(() => {
    const t = setInterval(() => {
      const now = Date.now();
      stamps.current = stamps.current.filter((s) => now - s < 60_000);
      setEpm(stamps.current.length);
      if (dirty.current.size) {
        for (const key of dirty.current) void qc.invalidateQueries({ queryKey: [key] });
        dirty.current.clear();
      }
    }, 3_000);
    return () => clearInterval(t);
  }, [qc]);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    const connect = () => {
      setStatus((s) => (s === "live" ? s : "connecting"));
      try {
        ws = new WebSocket(wsUrl());
      } catch {
        schedule();
        return;
      }
      ws.onopen = () => {
        retry = 0;
        setStatus("live");
      };
      ws.onmessage = (msg) => {
        let parsed: { channel?: string; data?: unknown };
        try {
          parsed = JSON.parse(String(msg.data)) as { channel?: string; data?: unknown };
        } catch {
          return;
        }
        if (parsed.channel === "event" && parsed.data) {
          const ev = parsed.data as AttackEvent;
          stamps.current.push(Date.now());
          if (ev.event_type !== "connect" && ev.event_type !== "disconnect")
            prepend(qc, "recent", ev, 200);
          for (const k of ["stats", "timeline", "sessions", "devices"]) dirty.current.add(k);
        } else if (parsed.channel === "detection" && parsed.data) {
          const det = parsed.data as Detection;
          prepend(qc, "detections", det, 500);
          for (const k of ["stats", "mitre", "attackers", "iocs", "map"]) dirty.current.add(k);
          if (det.severity === "CRITICAL" || det.severity === "HIGH") {
            setToasts((t) => [...t.slice(-3), { id: det.id ?? Date.now(), detection: det }]);
          }
        } else if (parsed.channel === "state") {
          dirty.current.add("devices");
          dirty.current.add("device");
        }
      };
      ws.onclose = () => {
        if (!closed) schedule();
      };
      ws.onerror = () => ws?.close();
    };

    const schedule = () => {
      setStatus("offline");
      retry = Math.min(retry + 1, 6);
      timer = setTimeout(connect, 1000 * 2 ** retry); // 2 s … 64 s back-off
    };

    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, [qc]);

  // toasts disappear after 8 s
  useEffect(() => {
    if (!toasts.length) return;
    const t = setTimeout(() => setToasts((x) => x.slice(1)), 8_000);
    return () => clearTimeout(t);
  }, [toasts]);

  const dismiss = (id: number) => setToasts((t) => t.filter((x) => x.id !== id));

  return <Ctx.Provider value={{ status, eventsPerMin, toasts, dismiss }}>{children}</Ctx.Provider>;
}
