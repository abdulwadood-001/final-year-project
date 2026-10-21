import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  Panel,
  PageHeader,
  SeverityBadge,
  ProtocolTag,
  timeAgo,
  QueryState,
  Pills,
  Tag,
} from "@/components/dashboard/ui";
import { useDetections, useMitre, useIocs } from "@/lib/api";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/detections")({
  head: pageHead("Detections", "Rule-based attack detections tagged with MITRE ATT&CK techniques."),
  component: Detections,
});

type Sev = "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

function Detections() {
  const [sev, setSev] = useState<Sev>("ALL");
  const [type, setType] = useState<string>("");
  const dets = useDetections({
    limit: 300,
    ...(sev !== "ALL" ? { severity: sev } : {}),
    ...(type ? { attack_type: type } : {}),
  });
  const allTypes = useDetections({ limit: 500 });
  const mitre = useMitre();
  const iocs = useIocs(undefined, 12);
  const types = [...new Set((allTypes.data ?? []).map((d) => d.attack_type))].sort();

  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <PageHeader
        title="Detections"
        subtitle="Rule-engine classifications with MITRE ATT&CK (Enterprise + ICS) tagging"
      />

      <div className="grid gap-4 xl:grid-cols-3">
        <Panel
          title="Detection Feed"
          subtitle="Newest first · live"
          className="xl:col-span-2"
          action={
            <Pills<Sev>
              value={sev}
              onChange={setSev}
              options={(["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((v) => ({
                value: v,
                label: v === "ALL" ? "All" : v,
              }))}
            />
          }
        >
          {types.length > 0 && (
            <div className="mb-4 flex flex-wrap gap-1">
              <button
                onClick={() => setType("")}
                className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${type === "" ? "border-primary/40 text-primary" : "border-border text-muted-foreground"}`}
              >
                all types
              </button>
              {types.map((t) => (
                <button
                  key={t}
                  onClick={() => setType(t === type ? "" : t)}
                  className={`rounded border px-1.5 py-0.5 font-mono text-[10px] ${type === t ? "border-primary/40 bg-primary/10 text-primary" : "border-border text-muted-foreground hover:text-foreground"}`}
                >
                  {t}
                </button>
              ))}
            </div>
          )}
          <QueryState
            q={dets}
            empty="No detections match — the intel engine evaluates new traffic every 30 s."
          >
            {(rows) => (
              <div className="space-y-3">
                {rows.map((d) => (
                  <article
                    key={d.id}
                    className="rounded-md border border-border/60 bg-background/40 p-4"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge level={d.severity} />
                      <h3 className="text-sm font-semibold">{d.attack_type}</h3>
                      {d.alerted && <Tag className="border-sev-high/40 text-sev-high">alerted</Tag>}
                      <span
                        className="ml-auto text-[11px] text-muted-foreground"
                        title={d.timestamp}
                      >
                        {timeAgo(d.timestamp)}
                      </span>
                    </div>
                    <p className="mt-1.5 text-xs text-muted-foreground">{d.details}</p>
                    <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                      <Link
                        to="/attackers/$ip"
                        params={{ ip: d.ip }}
                        className="font-mono text-[11px] text-primary hover:underline"
                      >
                        {d.ip}
                      </Link>
                      {d.protocol && <ProtocolTag protocol={d.protocol} />}
                      {d.device && <Tag>{d.device}</Tag>}
                      {d.session_id && (
                        <Link
                          to="/sessions/$sessionId"
                          params={{ sessionId: d.session_id }}
                          className="font-mono text-[10px] text-muted-foreground hover:text-primary"
                        >
                          session ↗
                        </Link>
                      )}
                      <span className="mx-1 text-border">|</span>
                      {(d.mitre ?? []).map((m, i) => (
                        <span
                          key={m}
                          title={d.mitre_names?.[i] ?? ""}
                          className="rounded border border-primary/30 bg-primary/10 px-1.5 py-0.5 font-mono text-[10px] font-medium text-primary"
                        >
                          {m} · {d.mitre_names?.[i] ?? ""}
                        </span>
                      ))}
                    </div>
                  </article>
                ))}
              </div>
            )}
          </QueryState>
        </Panel>

        <div className="space-y-4">
          <Panel title="MITRE ATT&CK Ranking" subtitle="Techniques by detection count">
            <QueryState q={mitre} empty="No techniques observed yet.">
              {(rows) => {
                const max = rows[0]?.detections ?? 1;
                return (
                  <div className="space-y-2.5">
                    {rows.slice(0, 15).map((m) => (
                      <div key={m.technique}>
                        <div className="flex items-baseline justify-between gap-2">
                          <p className="font-mono text-xs">
                            {m.technique}{" "}
                            <span className="font-sans text-muted-foreground">{m.name}</span>
                          </p>
                          <span className="font-mono text-[11px] text-muted-foreground">
                            {m.detections}
                          </span>
                        </div>
                        <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-muted">
                          <div
                            className="h-full rounded-full bg-primary"
                            style={{ width: `${(m.detections / max) * 100}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                );
              }}
            </QueryState>
          </Panel>

          <Panel
            title="Indicators of Compromise"
            subtitle="Latest extracted URLs, hosts and hashes"
            action={
              <Link to="/iocs" className="text-xs text-primary hover:underline">
                all IOCs →
              </Link>
            }
          >
            <QueryState q={iocs} empty="No IOCs yet.">
              {(rows) => (
                <div className="space-y-2">
                  {rows.map((ioc) => (
                    <div
                      key={`${ioc.type}${ioc.value}`}
                      className="rounded-md border border-border/60 bg-background/40 px-3 py-2"
                    >
                      <div className="flex items-center gap-2">
                        <span className="rounded border border-sev-high/30 bg-sev-high/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase text-sev-high">
                          {ioc.type}
                        </span>
                        <span className="ml-auto font-mono text-[10px] text-muted-foreground">
                          ×{ioc.hits}
                        </span>
                      </div>
                      <p className="mt-1.5 break-all font-mono text-[11px]">{ioc.value}</p>
                      <p className="mt-1 text-[10px] text-muted-foreground">
                        {ioc.context ?? ""} {ioc.protocol ? `· via ${ioc.protocol}` : ""}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </QueryState>
          </Panel>
        </div>
      </div>
    </div>
  );
}
