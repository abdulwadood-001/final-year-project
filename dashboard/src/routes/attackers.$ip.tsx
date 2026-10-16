import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import {
  Panel,
  StatCard,
  SeverityBadge,
  ProtocolTag,
  timeAgo,
  QueryState,
  DemoGeoTag,
  Tag,
} from "@/components/dashboard/ui";
import { useAttacker, list, fmtBytes, isMalicious, shortId } from "@/lib/api";

export const Route = createFileRoute("/attackers/$ip")({
  head: ({ params }) => ({
    meta: [
      { title: `Attacker ${params.ip} — HoneyBot-IoT` },
      {
        name: "description",
        content: `Activity profile for ${params.ip}: sessions, commands, detections, IOCs, samples.`,
      },
    ],
  }),
  component: AttackerDetail,
});

function Back() {
  return (
    <Link
      to="/attackers"
      className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
    >
      <ArrowLeft className="size-3.5" /> All attackers
    </Link>
  );
}

function AttackerDetail() {
  const { ip } = Route.useParams();
  const q = useAttacker(ip);

  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <Back />
      <QueryState q={q} isEmpty={() => false}>
        {(d) => {
          const a = d.attacker;
          return (
            <>
              <header className="mb-6 mt-3 flex flex-wrap items-center gap-3">
                <h1 className="font-mono text-xl font-bold tracking-tight">{a.ip}</h1>
                <SeverityBadge level={a.threat_level} />
                <span className="text-sm text-muted-foreground">
                  {[a.city, a.country].filter(Boolean).join(", ") || "location unknown"}
                  <DemoGeoTag source={a.geo_source} />
                </span>
                {a.campaign_id && <Tag>{a.campaign_id}</Tag>}
                <div className="flex flex-wrap gap-1">
                  {list(a.protocols).map((p) => (
                    <ProtocolTag key={p} protocol={p} />
                  ))}
                </div>
              </header>
              {a.note && <p className="mb-4 text-xs text-muted-foreground">{a.note}</p>}

              <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
                <StatCard
                  label="Threat score"
                  value={`${a.threat_score}/100`}
                  tone={a.threat_score >= 70 ? "critical" : "default"}
                />
                <StatCard label="Sessions" value={a.sessions ?? d.sessions.length} />
                <StatCard label="Auth attempts" value={a.auth_attempts ?? 0} />
                <StatCard
                  label="Logins won"
                  value={a.auth_success ?? 0}
                  tone={(a.auth_success ?? 0) > 0 ? "critical" : "default"}
                />
                <StatCard label="Commands" value={a.commands ?? 0} />
                <StatCard
                  label="Samples dropped"
                  value={d.samples.length}
                  tone={d.samples.some((s) => isMalicious(s.yara_result)) ? "critical" : "default"}
                />
              </div>

              {d.campaign && (
                <Panel
                  title={`Campaign ${d.campaign.campaign_id}`}
                  subtitle={d.campaign.description}
                  className="mt-4"
                >
                  <div className="flex flex-wrap gap-1.5">
                    {d.campaign.ips.map((x) => (
                      <Link
                        key={x}
                        to="/attackers/$ip"
                        params={{ ip: x }}
                        className="font-mono text-xs text-primary hover:underline"
                      >
                        {x}
                      </Link>
                    ))}
                  </div>
                  <p className="mt-3 text-[10px] uppercase tracking-widest text-muted-foreground">
                    shared credentials
                  </p>
                  <p className="mt-1 break-all font-mono text-[11px] text-muted-foreground">
                    {d.campaign.credentials.slice(0, 20).join("  ·  ")}
                  </p>
                </Panel>
              )}

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <Panel title="Detections" subtitle="Rules this IP triggered">
                  {d.detections.length === 0 ? (
                    <p className="text-xs text-muted-foreground">No detections.</p>
                  ) : (
                    <div className="max-h-[28rem] space-y-2 overflow-y-auto">
                      {d.detections.map((x) => (
                        <div
                          key={x.id}
                          className="rounded-md border border-border/60 bg-background/40 px-3 py-2.5"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <p className="text-xs font-semibold">{x.attack_type}</p>
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-muted-foreground">
                                {timeAgo(x.timestamp)}
                              </span>
                              <SeverityBadge level={x.severity} />
                            </div>
                          </div>
                          <p className="mt-1 text-[11px] text-muted-foreground">{x.details}</p>
                          <div className="mt-1.5 flex flex-wrap gap-1">
                            {(x.mitre ?? []).map((m, i) => (
                              <span
                                key={m}
                                className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground"
                              >
                                {m} · {x.mitre_names?.[i] ?? ""}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>

                <Panel title="Sessions" subtitle="Connections from this IP">
                  <div className="max-h-[28rem] space-y-2 overflow-y-auto">
                    {d.sessions.map((s) => (
                      <Link
                        key={s.session_id}
                        to="/sessions/$sessionId"
                        params={{ sessionId: s.session_id }}
                        className="flex items-center justify-between gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2 hover:bg-accent/40"
                      >
                        <div className="flex items-center gap-2">
                          <ProtocolTag protocol={s.protocol} />
                          <span className="font-mono text-xs text-primary">
                            {shortId(s.session_id)}…
                          </span>
                          <span className="text-[11px] text-muted-foreground">{s.device}</span>
                          {s.login_success && (
                            <span className="font-mono text-[10px] text-sev-critical">login ✓</span>
                          )}
                        </div>
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {s.ended_at === null ? "● active" : timeAgo(s.started_at)}
                        </span>
                      </Link>
                    ))}
                  </div>
                </Panel>
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-3">
                <Panel title="Credentials tried" subtitle="By this attacker">
                  {d.credentials.length === 0 ? (
                    <p className="text-xs text-muted-foreground">None.</p>
                  ) : (
                    <div className="max-h-72 space-y-1.5 overflow-y-auto font-mono text-xs">
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
                <Panel title="IOCs" subtitle="Indicators attributed to this IP">
                  {d.iocs.length === 0 ? (
                    <p className="text-xs text-muted-foreground">None.</p>
                  ) : (
                    <div className="max-h-72 space-y-1.5 overflow-y-auto">
                      {d.iocs.map((i) => (
                        <p
                          key={`${i.type}${i.value}`}
                          className="truncate font-mono text-xs text-terminal"
                          title={i.value}
                        >
                          <span className="mr-2 text-[10px] uppercase text-muted-foreground">
                            {i.type}
                          </span>
                          {i.value}
                        </p>
                      ))}
                    </div>
                  )}
                </Panel>
                <Panel title="Malware samples" subtitle="Files this IP dropped">
                  {d.samples.length === 0 ? (
                    <p className="text-xs text-muted-foreground">None.</p>
                  ) : (
                    <div className="max-h-72 space-y-2 overflow-y-auto">
                      {d.samples.map((s) => (
                        <Link
                          key={`${s.sha256}${s.ts}`}
                          to="/malware"
                          search={{ sha: s.sha256 }}
                          className="block rounded-md border border-border/60 bg-background/40 px-3 py-2 hover:bg-accent/40"
                        >
                          <p className="truncate font-mono text-[11px]">{s.sha256.slice(0, 24)}…</p>
                          <p className="mt-0.5 text-[10px] text-muted-foreground">
                            {s.arch ?? s.mime_type} · {fmtBytes(s.size)} · via {s.source}
                          </p>
                          <p
                            className={`mt-0.5 font-mono text-[10px] ${isMalicious(s.yara_result) ? "text-sev-critical" : "text-muted-foreground"}`}
                          >
                            YARA: {s.yara_result ?? "pending"}
                          </p>
                        </Link>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>

              <Panel
                title="Event Log"
                subtitle="Raw events from this source (newest first)"
                className="mt-4"
              >
                <div className="-m-5 max-h-[32rem] overflow-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="sticky top-0 bg-card">
                      <tr className="border-b text-[10px] uppercase tracking-widest text-muted-foreground">
                        <th className="px-5 py-2.5 font-medium">Time</th>
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
                            <ProtocolTag protocol={e.protocol} />
                          </td>
                          <td className="px-3 py-2.5 text-muted-foreground">{e.event_type}</td>
                          <td
                            className="max-w-0 truncate px-5 py-2.5 text-terminal"
                            style={{ maxWidth: 560 }}
                          >
                            {e.command ??
                              e.payload ??
                              (e.username != null
                                ? `${e.username}:${e.password ?? ""} ${e.success ? "✓" : "✗"}`
                                : "—")}
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
