import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, Camera, DoorOpen, Gauge } from "lucide-react";
import {
  Panel,
  StatCard,
  ProtocolTag,
  LiveDot,
  timeAgo,
  QueryState,
  SeverityBadge,
} from "@/components/dashboard/ui";
import { useDevice, shortId } from "@/lib/api";
import { DeviceSpecificView } from "@/components/dashboard/device-views";

export const Route = createFileRoute("/devices/$device")({
  head: ({ params }) => ({
    meta: [
      { title: `Device ${params.device} — HoneyBot-IoT` },
      {
        name: "description",
        content: `Live state, sessions and attacks against the emulated ${params.device}.`,
      },
    ],
  }),
  component: DeviceDetail,
});

const ICONS: Record<string, typeof Camera> = { cctv: Camera, smartlock: DoorOpen, sensor: Gauge };

function DeviceDetail() {
  const { device } = Route.useParams();
  const q = useDevice(device);
  const Icon = ICONS[device] ?? Gauge;

  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <Link
        to="/devices"
        className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> All devices
      </Link>
      <QueryState q={q} isEmpty={() => false}>
        {(d) => {
          const active = d.sessions.filter((s) => s.ended_at === null);
          return (
            <>
              <header className="mb-6 mt-3 flex flex-wrap items-center gap-3">
                <div className="flex size-10 items-center justify-center rounded-md bg-primary/10">
                  <Icon className="size-5 text-primary" />
                </div>
                <div>
                  <h1 className="font-mono text-xl font-bold tracking-tight">{d.name}</h1>
                  <div className="mt-1 flex items-center gap-2">
                    {d.protocols.map((p) => (
                      <ProtocolTag key={p} protocol={p} />
                    ))}
                    {d.online ? (
                      <span className="flex items-center gap-1.5 text-[11px] text-primary">
                        <LiveDot /> online
                      </span>
                    ) : (
                      <span className="text-[11px] text-sev-critical">
                        service down:{" "}
                        {Object.entries(d.services_detail)
                          .filter(([, s]) => !s.up)
                          .map(([n]) => n)
                          .join(", ")}
                      </span>
                    )}
                  </div>
                </div>
              </header>

              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <StatCard label="Active sessions" value={d.active_sessions} tone="ok" />
                <StatCard label="Events 24h" value={d.events_24h} />
                <StatCard
                  label="Detections 24h"
                  value={d.detections_24h}
                  tone={d.detections_24h > 0 ? "critical" : "default"}
                />
                <StatCard label="Last attack" value={timeAgo(d.last_attack)} />
              </div>

              <div className="mt-4">
                <DeviceSpecificView device={device} data={d} />
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-3">
                <Panel title="Sessions" subtitle={`${active.length} active · newest first`}>
                  {d.sessions.length === 0 ? (
                    <p className="text-xs text-muted-foreground">No sessions.</p>
                  ) : (
                    <div className="max-h-80 space-y-2 overflow-y-auto">
                      {d.sessions.map((s) => (
                        <Link
                          key={s.session_id}
                          to="/sessions/$sessionId"
                          params={{ sessionId: s.session_id }}
                          className="flex items-center justify-between gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2 hover:bg-accent/40"
                        >
                          <div className="flex min-w-0 items-center gap-2">
                            <ProtocolTag protocol={s.protocol} />
                            <span className="truncate font-mono text-xs">{s.ip}</span>
                            {s.login_success && (
                              <span className="font-mono text-[10px] text-sev-critical">✓</span>
                            )}
                          </div>
                          <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                            {s.ended_at === null ? "● active" : timeAgo(s.started_at)}
                          </span>
                        </Link>
                      ))}
                    </div>
                  )}
                </Panel>
                <Panel title="Detections" subtitle="Against this device">
                  {d.detections.length === 0 ? (
                    <p className="text-xs text-muted-foreground">None.</p>
                  ) : (
                    <div className="max-h-80 space-y-2 overflow-y-auto">
                      {d.detections.map((x) => (
                        <div
                          key={x.id}
                          className="rounded-md border border-border/60 bg-background/40 px-3 py-2"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <p className="truncate text-xs font-semibold">{x.attack_type}</p>
                            <SeverityBadge level={x.severity} />
                          </div>
                          <p className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">
                            {x.details}
                          </p>
                          <Link
                            to="/attackers/$ip"
                            params={{ ip: x.ip }}
                            className="font-mono text-[10px] text-primary hover:underline"
                          >
                            {x.ip}
                          </Link>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
                <Panel
                  title="Credentials tried"
                  subtitle="Default-credential profile of this device"
                >
                  {d.credentials.length === 0 ? (
                    <p className="text-xs text-muted-foreground">None.</p>
                  ) : (
                    <div className="space-y-1.5 font-mono text-xs">
                      {d.credentials.map((c, i) => (
                        <p key={i} className="flex justify-between gap-3">
                          <span className={c.worked ? "text-sev-critical" : ""}>
                            {c.username || "(empty)"}:{c.password || "(empty)"}
                          </span>
                          <span className="text-muted-foreground">×{c.count}</span>
                        </p>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>

              <Panel
                title="Recent Attacks"
                subtitle="Latest events against this device"
                className="mt-4"
              >
                <div className="-m-5 max-h-[30rem] overflow-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="sticky top-0 bg-card">
                      <tr className="border-b text-[10px] uppercase tracking-widest text-muted-foreground">
                        <th className="px-5 py-2.5 font-medium">Time</th>
                        <th className="px-3 py-2.5 font-medium">Source</th>
                        <th className="px-3 py-2.5 font-medium">Protocol</th>
                        <th className="px-3 py-2.5 font-medium">Type</th>
                        <th className="px-5 py-2.5 font-medium">Detail</th>
                      </tr>
                    </thead>
                    <tbody className="font-mono">
                      {d.events.map((e) => (
                        <tr key={e.id} className="border-b border-border/50 last:border-0">
                          <td className="whitespace-nowrap px-5 py-2.5 text-muted-foreground">
                            {timeAgo(e.ts)}
                          </td>
                          <td className="px-3 py-2.5">
                            <Link
                              to="/attackers/$ip"
                              params={{ ip: e.ip }}
                              className="text-primary hover:underline"
                            >
                              {e.ip}
                            </Link>
                          </td>
                          <td className="px-3 py-2.5">
                            <ProtocolTag protocol={e.protocol} />
                          </td>
                          <td className="px-3 py-2.5 text-muted-foreground">{e.event_type}</td>
                          <td
                            className="max-w-0 truncate px-5 py-2.5 text-terminal"
                            style={{ maxWidth: 480 }}
                          >
                            {e.session_id ? (
                              <Link
                                to="/sessions/$sessionId"
                                params={{ sessionId: e.session_id }}
                                className="hover:underline"
                                title={`session ${shortId(e.session_id)}`}
                              >
                                {e.command ??
                                  e.payload ??
                                  (e.username != null
                                    ? `${e.username}:${e.password ?? ""} ${e.success ? "✓" : "✗"}`
                                    : "—")}
                              </Link>
                            ) : (
                              (e.command ?? e.payload ?? "—")
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
            </>
          );
        }}
      </QueryState>
    </div>
  );
}
