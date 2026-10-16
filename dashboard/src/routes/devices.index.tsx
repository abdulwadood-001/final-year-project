import { createFileRoute, Link } from "@tanstack/react-router";
import { Camera, DoorOpen, Gauge } from "lucide-react";
import {
  Panel,
  PageHeader,
  ProtocolTag,
  LiveDot,
  timeAgo,
  QueryState,
} from "@/components/dashboard/ui";
import { useDevices } from "@/lib/api";
import { pageHead } from "@/lib/head";
import { headline } from "@/components/dashboard/device-views";

export const Route = createFileRoute("/devices/")({
  head: pageHead(
    "Devices",
    "Status of the three emulated IoT devices and the honeypot services behind them.",
  ),
  component: Devices,
});

const ICONS: Record<string, typeof Camera> = { cctv: Camera, smartlock: DoorOpen, sensor: Gauge };
const SHOWN: Record<string, string[]> = {
  cctv: ["model", "firmware", "recording", "motion", "viewers", "resolution"],
  smartlock: ["model", "firmware", "lock_state", "door", "battery", "auto_lock"],
  sensor: ["model", "firmware", "temperature", "pressure", "humidity", "alarm"],
};

function Devices() {
  const q = useDevices();
  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <PageHeader
        title="Device Status"
        subtitle="Emulated device state, shared consistently across all protocols (Redis)"
      />
      <QueryState q={q} isEmpty={() => false}>
        {(data) => (
          <>
            <div className="grid gap-4 lg:grid-cols-3">
              {Object.entries(data.devices).map(([key, d]) => {
                const Icon = ICONS[key] ?? Gauge;
                const h = headline(key, d.state);
                return (
                  <Panel key={key}>
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className="flex size-10 items-center justify-center rounded-md bg-primary/10">
                          <Icon className="size-5 text-primary" />
                        </div>
                        <div>
                          <h3 className="text-sm font-semibold">
                            <Link
                              to="/devices/$device"
                              params={{ device: key }}
                              className="hover:text-primary"
                            >
                              {d.name}
                            </Link>
                          </h3>
                          <div className="mt-1 flex gap-1">
                            {d.protocols.map((p) => (
                              <ProtocolTag key={p} protocol={p} />
                            ))}
                          </div>
                        </div>
                      </div>
                      {d.online ? (
                        <span className="flex items-center gap-1.5 text-[11px] text-primary">
                          <LiveDot /> online
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 text-[11px] text-sev-critical">
                          <LiveDot className="bg-sev-critical" /> degraded
                        </span>
                      )}
                    </div>

                    {h && <p className={`mt-3 font-mono text-sm font-bold ${h.tone}`}>{h.text}</p>}

                    <dl className="mt-4 grid grid-cols-4 gap-2 border-t pt-4 text-center">
                      <div>
                        <dt className="text-[10px] uppercase tracking-widest text-muted-foreground">
                          Active
                        </dt>
                        <dd className="mt-1 font-mono text-lg font-semibold">
                          {d.active_sessions}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-[10px] uppercase tracking-widest text-muted-foreground">
                          24h
                        </dt>
                        <dd className="mt-1 font-mono text-lg font-semibold">{d.events_24h}</dd>
                      </div>
                      <div>
                        <dt className="text-[10px] uppercase tracking-widest text-muted-foreground">
                          Detect.
                        </dt>
                        <dd
                          className={`mt-1 font-mono text-lg font-semibold ${d.detections_24h ? "text-sev-critical" : ""}`}
                        >
                          {d.detections_24h}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-[10px] uppercase tracking-widest text-muted-foreground">
                          Last hit
                        </dt>
                        <dd className="mt-1 font-mono text-xs font-medium text-muted-foreground">
                          {timeAgo(d.last_attack)}
                        </dd>
                      </div>
                    </dl>

                    <div className="mt-4 rounded-md border border-border/60 bg-background/60 p-3">
                      <p className="mb-1.5 text-[10px] uppercase tracking-widest text-muted-foreground">
                        Live state (Redis)
                      </p>
                      <div className="space-y-1 font-mono text-xs">
                        {(SHOWN[key] ?? Object.keys(d.state)).map((k) => (
                          <p key={k} className="flex justify-between gap-3">
                            <span className="text-muted-foreground">{k}</span>
                            <span className="truncate text-terminal">{d.state[k] ?? "—"}</span>
                          </p>
                        ))}
                      </div>
                    </div>
                    <Link
                      to="/devices/$device"
                      params={{ device: key }}
                      className="mt-3 inline-block text-xs text-primary hover:underline"
                    >
                      device detail →
                    </Link>
                  </Panel>
                );
              })}
            </div>

            <Panel
              title="Service Health"
              subtitle="Heartbeat of every honeypot service (expires after 30 s of silence)"
              className="mt-4"
            >
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
                {Object.entries(data.services).map(([name, s]) => (
                  <div
                    key={name}
                    className="rounded-md border border-border/60 bg-background/40 px-3 py-2.5"
                  >
                    <div className="flex items-center gap-2">
                      <span
                        className={`size-2 rounded-full ${s.up ? "animate-pulse-dot bg-primary" : "bg-sev-critical"}`}
                      />
                      <span className="font-mono text-xs">{name}</span>
                    </div>
                    <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                      {s.up
                        ? `up ${s.uptime != null ? formatUptime(s.uptime) : ""}`
                        : "no heartbeat"}
                      {s.port ? ` · :${s.port}` : ""}
                    </p>
                  </div>
                ))}
              </div>
            </Panel>
          </>
        )}
      </QueryState>
    </div>
  );
}

function formatUptime(s: number) {
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}
