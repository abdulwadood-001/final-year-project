import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Panel,
  PageHeader,
  SeverityBadge,
  ProtocolTag,
  QueryState,
  DemoGeoTag,
  Tag,
} from "@/components/dashboard/ui";
import { useTopAttackers, useCreds, useCommands, useCampaigns, list } from "@/lib/api";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/attackers/")({
  head: pageHead(
    "Attackers",
    "Ranked attacker profiles with cross-protocol correlation, threat scores and credentials.",
  ),
  component: Attackers,
});

function Attackers() {
  const attackers = useTopAttackers(200);
  const creds = useCreds(12);
  const commands = useCommands(12);
  const campaigns = useCampaigns();

  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <PageHeader
        title="Attackers"
        subtitle="Cross-protocol correlation per source IP, ranked by threat score"
      />

      <Panel
        title="Top Attackers"
        subtitle="Threat score combines worst detection, breadth of techniques, logins won and payload downloads"
      >
        <QueryState
          q={attackers}
          empty="No attackers correlated yet — the intel engine runs every 30 s."
        >
          {(rows) => (
            <div className="-m-5 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b text-[10px] uppercase tracking-widest text-muted-foreground">
                    <th className="px-5 py-2.5 font-medium">IP / Location</th>
                    <th className="px-3 py-2.5 font-medium">Threat</th>
                    <th className="px-3 py-2.5 font-medium">Protocols</th>
                    <th className="px-3 py-2.5 text-right font-medium">Events</th>
                    <th className="px-3 py-2.5 text-right font-medium">Sessions</th>
                    <th className="px-3 py-2.5 text-right font-medium">Auth</th>
                    <th className="px-3 py-2.5 text-right font-medium">Success</th>
                    <th className="px-3 py-2.5 text-right font-medium">Cmds</th>
                    <th className="px-3 py-2.5 text-right font-medium">DLs</th>
                    <th className="px-5 py-2.5 font-medium">Campaign</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {rows.map((a) => (
                    <tr
                      key={a.ip}
                      className="border-b border-border/50 last:border-0 hover:bg-accent/40"
                    >
                      <td className="px-5 py-3">
                        <Link
                          to="/attackers/$ip"
                          params={{ ip: a.ip }}
                          className="text-primary hover:underline"
                        >
                          {a.ip}
                        </Link>
                        <p className="mt-0.5 font-sans text-[11px] text-muted-foreground">
                          {[a.city, a.country].filter(Boolean).join(", ") || "unknown"}
                          <DemoGeoTag source={a.geo_source} />
                        </p>
                      </td>
                      <td className="px-3 py-3">
                        <SeverityBadge level={a.threat_level} />
                        <p className="mt-1 text-[10px] text-muted-foreground">
                          {a.threat_score}/100
                        </p>
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex flex-wrap gap-1">
                          {list(a.protocols).map((p) => (
                            <ProtocolTag key={p} protocol={p} />
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-3 text-right tabular-nums">
                        {a.attempts ?? a.events ?? 0}
                      </td>
                      <td className="px-3 py-3 text-right tabular-nums">{a.sessions ?? 0}</td>
                      <td className="px-3 py-3 text-right tabular-nums">{a.auth_attempts ?? 0}</td>
                      <td className="px-3 py-3 text-right tabular-nums text-sev-critical">
                        {a.auth_success ?? 0}
                      </td>
                      <td className="px-3 py-3 text-right tabular-nums">{a.commands ?? 0}</td>
                      <td className="px-3 py-3 text-right tabular-nums">{a.downloads ?? 0}</td>
                      <td className="px-5 py-3 text-muted-foreground">{a.campaign_id ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </QueryState>
      </Panel>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="Top Credentials" subtitle="Most-tried username/password pairs">
          <QueryState q={creds} empty="No login attempts yet.">
            {(rows) => (
              <div className="space-y-2">
                {rows.map((c, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2"
                  >
                    <p className="min-w-0 truncate font-mono text-xs">
                      {c.username || "(empty)"}
                      <span className="text-muted-foreground">:</span>
                      {c.password || "(empty)"}
                    </p>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="font-mono text-[11px] text-muted-foreground">
                        ×{c.count}
                      </span>
                      {c.worked ? (
                        <span className="rounded border border-sev-critical/30 bg-sev-critical/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-sev-critical">
                          WORKED
                        </span>
                      ) : (
                        <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                          failed
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </QueryState>
        </Panel>

        <Panel title="Top Commands" subtitle="Post-exploitation shell activity">
          <QueryState q={commands} empty="No shell commands yet.">
            {(rows) => (
              <div className="space-y-2">
                {rows.map((c, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2"
                  >
                    <p
                      className="min-w-0 truncate font-mono text-xs text-terminal"
                      title={c.command}
                    >
                      {c.command}
                    </p>
                    <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                      ×{c.count}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </QueryState>
        </Panel>

        <Panel
          title="Campaigns"
          subtitle="IPs sharing the same credential wordlist (Jaccard ≥ 0.6)"
        >
          <QueryState q={campaigns} empty="No coordinated campaigns identified yet.">
            {(rows) => (
              <div className="space-y-2">
                {rows.map((c) => (
                  <div
                    key={c.campaign_id}
                    className="rounded-md border border-border/60 bg-background/40 px-3 py-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <Tag>{c.campaign_id}</Tag>
                      <span className="font-mono text-[11px] text-muted-foreground">
                        {c.ips.length} IPs
                      </span>
                    </div>
                    <p className="mt-1.5 text-[11px] text-muted-foreground">{c.description}</p>
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {c.ips.slice(0, 8).map((ip) => (
                        <Link
                          key={ip}
                          to="/attackers/$ip"
                          params={{ ip }}
                          className="font-mono text-[10px] text-primary hover:underline"
                        >
                          {ip}
                        </Link>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </QueryState>
        </Panel>
      </div>
    </div>
  );
}
