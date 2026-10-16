import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, ArrowDownLeft, ArrowUpRight } from "lucide-react";
import {
  Panel,
  StatCard,
  ProtocolTag,
  timeAgo,
  QueryState,
  SeverityBadge,
} from "@/components/dashboard/ui";
import { useSession, shortId, fmtBytes, isMalicious, fmtTime } from "@/lib/api";
import { toReplay } from "@/lib/replay";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/sessions/$sessionId")({
  head: ({ params }) => ({
    meta: [
      { title: `Session ${params.sessionId.slice(0, 8)} — HoneyBot-IoT` },
      {
        name: "description",
        content:
          "Attacker session replay: auth attempts, commands, responses and captured payloads.",
      },
    ],
  }),
  component: SessionDetail,
});

const toneClass = {
  critical: "text-sev-critical",
  high: "text-sev-high",
  ok: "text-primary",
  muted: "text-muted-foreground",
} as const;

function SessionDetail() {
  const { sessionId } = Route.useParams();
  const q = useSession(sessionId);

  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <Link
        to="/sessions"
        className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="size-3.5" /> All sessions
      </Link>
      <QueryState q={q} isEmpty={() => false}>
        {(d) => {
          const s = d.session;
          const lines = toReplay(d.events, s.protocol);
          const duration = s.ended_at
            ? Math.round((new Date(s.ended_at).getTime() - new Date(s.started_at).getTime()) / 1000)
            : null;
          return (
            <>
              <header className="mb-6 mt-3 flex flex-wrap items-center gap-3">
                <h1 className="font-mono text-xl font-bold tracking-tight">
                  Session {shortId(s.session_id)}…
                </h1>
                <ProtocolTag protocol={s.protocol} />
                <span className="font-mono text-xs text-muted-foreground">
                  {s.ended_at === null ? "● active" : `closed after ${duration}s`}
                </span>
                <span className="font-mono text-[11px] text-muted-foreground">
                  {fmtTime(s.started_at)}
                </span>
              </header>

              <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
                <div className="rounded-lg border bg-card p-4">
                  <p className="text-[11px] font-medium uppercase tracking-widest text-muted-foreground">
                    Source
                  </p>
                  <Link
                    to="/attackers/$ip"
                    params={{ ip: s.ip }}
                    className="mt-1.5 block truncate font-mono text-lg font-semibold text-primary hover:underline"
                  >
                    {s.ip}
                  </Link>
                  <p className="mt-1 text-xs text-muted-foreground">port {s.src_port ?? "?"}</p>
                </div>
                <StatCard compact label="Target" value={`${s.device}:${s.dst_port ?? "?"}`} />
                <StatCard label="Started" value={timeAgo(s.started_at)} />
                <StatCard label="Auth attempts" value={s.auth_attempts} />
                <StatCard
                  compact
                  label="Login"
                  value={s.login_success ? `success (${s.username ?? "?"})` : "failed"}
                  tone={s.login_success ? "critical" : "default"}
                />
                <StatCard label="Commands" value={s.commands} />
              </div>

              {s.client_version && (
                <p className="mt-4 rounded-md border border-border/60 bg-card px-3 py-2 font-mono text-xs text-muted-foreground">
                  client: <span className="text-foreground">{s.client_version}</span>
                </p>
              )}

              {(d.detections.length > 0 || d.samples.length > 0) && (
                <div className="mt-4 grid gap-4 lg:grid-cols-2">
                  <Panel title="Detections" subtitle="Raised for this session">
                    {d.detections.length === 0 ? (
                      <p className="text-xs text-muted-foreground">
                        None linked to this session (IP-level detections are on the attacker page).
                      </p>
                    ) : (
                      <div className="space-y-2">
                        {d.detections.map((x) => (
                          <div
                            key={x.id}
                            className="rounded-md border border-border/60 bg-background/40 px-3 py-2"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <p className="text-xs font-semibold">{x.attack_type}</p>
                              <SeverityBadge level={x.severity} />
                            </div>
                            <p className="mt-1 text-[11px] text-muted-foreground">{x.details}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </Panel>
                  <Panel title="Captured samples" subtitle="Quarantined payloads from this session">
                    {d.samples.length === 0 ? (
                      <p className="text-xs text-muted-foreground">None.</p>
                    ) : (
                      <div className="space-y-2">
                        {d.samples.map((x) => (
                          <Link
                            key={x.sha256}
                            to="/malware"
                            search={{ sha: x.sha256 }}
                            className="block rounded-md border border-border/60 bg-background/40 px-3 py-2 hover:bg-accent/40"
                          >
                            <p className="truncate font-mono text-[11px]">
                              {x.filename ?? "(unnamed)"} · {x.sha256.slice(0, 20)}…
                            </p>
                            <p className="mt-0.5 text-[10px] text-muted-foreground">
                              {x.arch ?? x.mime_type} · {fmtBytes(x.size)}
                            </p>
                            <p
                              className={`mt-0.5 font-mono text-[10px] ${isMalicious(x.yara_result) ? "text-sev-critical" : "text-muted-foreground"}`}
                            >
                              YARA: {x.yara_result ?? "pending"}
                            </p>
                          </Link>
                        ))}
                      </div>
                    )}
                  </Panel>
                </div>
              )}

              <Panel
                title="Replay"
                subtitle="Every exchange in order — attacker input (↙) vs honeypot output (↗)"
                className="mt-4"
              >
                {lines.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    No events recorded for this session yet.
                  </p>
                ) : (
                  <div className="space-y-1.5 font-mono text-xs">
                    {lines.map((e, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2"
                      >
                        <span className="mt-0.5 shrink-0">
                          {e.dir === "in" ? (
                            <ArrowDownLeft className="size-3.5 text-sev-high" />
                          ) : (
                            <ArrowUpRight className="size-3.5 text-primary" />
                          )}
                        </span>
                        <span className="w-20 shrink-0 pt-px text-[10px] text-muted-foreground">
                          {new Date(e.ts).toLocaleTimeString()}
                        </span>
                        <span className="w-28 shrink-0 truncate rounded border border-border px-1.5 py-0.5 text-center text-[10px] text-muted-foreground">
                          {e.type}
                        </span>
                        <div className="min-w-0 flex-1">
                          <p
                            className={cn(
                              "whitespace-pre-wrap break-all",
                              e.tone
                                ? toneClass[e.tone]
                                : e.dir === "in"
                                  ? "text-terminal"
                                  : "text-muted-foreground",
                            )}
                          >
                            {e.detail}
                          </p>
                          {e.mitre && e.mitre.length > 1 && (
                            <div className="mt-1 flex flex-wrap gap-1">
                              {e.mitre.map((m) => (
                                <span
                                  key={m.id}
                                  title={m.name}
                                  className="rounded border border-primary/30 bg-primary/10 px-1 py-px text-[9px] text-primary"
                                >
                                  {m.id}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </Panel>
            </>
          );
        }}
      </QueryState>
    </div>
  );
}
