import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import {
  Panel,
  PageHeader,
  StatCard,
  SeverityBadge,
  timeAgo,
  QueryState,
  Pills,
  DownloadButton,
  Tag,
} from "@/components/dashboard/ui";
import { useReport, useAlerts, useMlSummary } from "@/lib/api";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/reports")({
  head: pageHead("Reports & Alerts", "Threat summary reports, exports and the alert delivery log."),
  component: Reports,
});

type Win = "24" | "168" | "720";
const SEV_COLOR: Record<string, string> = {
  CRITICAL: "var(--color-sev-critical)",
  HIGH: "var(--color-sev-high)",
  MEDIUM: "var(--color-sev-medium)",
  LOW: "var(--color-sev-low)",
};
const STATUS_STYLE: Record<string, string> = {
  sent: "border-primary/40 text-primary",
  failed: "border-sev-critical/40 text-sev-critical",
  suppressed: "border-border text-muted-foreground",
  disabled: "border-sev-medium/40 text-sev-medium",
};

function Reports() {
  const [win, setWin] = useState<Win>("24");
  const report = useReport(Number(win));
  const alerts = useAlerts();
  const ml = useMlSummary();

  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <PageHeader
        title="Reports & Alerts"
        subtitle="Threat summaries (also e-mailed daily / weekly when SMTP is configured), exports and alert delivery"
        action={
          <Pills<Win>
            value={win}
            onChange={setWin}
            options={[
              { value: "24", label: "Last 24 h" },
              { value: "168", label: "7 days" },
              { value: "720", label: "30 days" },
            ]}
          />
        }
      />

      <QueryState q={report} isEmpty={() => false}>
        {(r) => {
          const sev = Object.entries(r.detections_by_severity).map(([name, value]) => ({
            name,
            value,
          }));
          return (
            <>
              <Panel
                title="Analyst summary"
                subtitle={`Generated ${timeAgo(r.generated_at)} · rule-based (LLM narrator arrives with Module 8)`}
                action={
                  <div className="flex flex-wrap gap-2">
                    <DownloadButton href={`/api/report.pdf?hours=${win}`}>
                      PDF report
                    </DownloadButton>
                    <DownloadButton href={`/api/export/stix?hours=${win}`}>STIX 2.1</DownloadButton>
                    <DownloadButton href={`/api/export/events.csv?hours=${win}`}>
                      Events CSV
                    </DownloadButton>
                  </div>
                }
              >
                <p className="text-sm leading-relaxed">{r.summary}</p>
              </Panel>

              <div className="mt-4 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
                {[
                  ["Events", r.totals["events"]],
                  ["Sessions", r.totals["sessions"]],
                  ["Source IPs", r.totals["unique_ips"]],
                  ["Logins", r.totals["auth_attempts"]],
                  ["Logins won", r.totals["successful_logins"]],
                  ["Detections", r.totals["detections"]],
                  ["Samples", r.totals["samples"]],
                  ["Alerts sent", r.totals["alerts_sent"]],
                ].map(([label, value]) => (
                  <StatCard
                    key={String(label)}
                    label={String(label)}
                    value={Number(value ?? 0).toLocaleString()}
                  />
                ))}
              </div>

              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                <Panel title="Detections by severity">
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart data={sev} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                        <XAxis
                          dataKey="name"
                          tick={{ fontSize: 10, fill: "var(--color-muted-foreground)" }}
                          tickLine={false}
                          axisLine={false}
                        />
                        <YAxis
                          tick={{ fontSize: 10, fill: "var(--color-muted-foreground)" }}
                          tickLine={false}
                          axisLine={false}
                          allowDecimals={false}
                        />
                        <Tooltip
                          cursor={{ fill: "var(--color-accent)" }}
                          contentStyle={{
                            background: "var(--color-popover)",
                            border: "1px solid var(--color-border)",
                            borderRadius: 8,
                            fontSize: 12,
                          }}
                        />
                        <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                          {sev.map((s) => (
                            <Cell key={s.name} fill={SEV_COLOR[s.name]} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </Panel>
                <Panel title="Detections by type">
                  {r.detections_by_type.length === 0 ? (
                    <p className="text-xs text-muted-foreground">No detections in this window.</p>
                  ) : (
                    <div className="space-y-1.5">
                      {r.detections_by_type.map((t) => (
                        <div
                          key={t.attack_type}
                          className="flex items-center justify-between gap-3 font-mono text-xs"
                        >
                          <span className="truncate">{t.attack_type}</span>
                          <span className="flex items-center gap-2">
                            <SeverityBadge level={t.max_severity} />
                            <span className="w-10 text-right text-muted-foreground">{t.count}</span>
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>
            </>
          );
        }}
      </QueryState>

      <Panel
        title="Machine-learning dataset (Module 8 · WBS 10.1)"
        subtitle="One feature vector per session with a weak label from the rule engine — training data for the XGBoost / Isolation Forest models"
        className="mt-4"
        action={<DownloadButton href="/api/ml/dataset.csv">Dataset CSV</DownloadButton>}
      >
        <QueryState q={ml} isEmpty={() => false}>
          {(m) => {
            const max = Math.max(1, ...Object.values(m.classes));
            return (
              <div className="grid gap-4 lg:grid-cols-2">
                <div className="space-y-2">
                  <p className="text-xs text-muted-foreground">
                    {m.sessions.toLocaleString()} labelled sessions (last 30 days)
                  </p>
                  {Object.entries(m.classes).map(([c, n]) => (
                    <div key={c} className="flex items-center gap-3">
                      <span className="w-32 shrink-0 font-mono text-xs">{c}</span>
                      <div className="h-4 flex-1 overflow-hidden rounded bg-muted">
                        <div
                          className="h-full bg-primary/60"
                          style={{ width: `${(n / max) * 100}%` }}
                        />
                      </div>
                      <span className="w-12 text-right font-mono text-xs text-muted-foreground">
                        {n}
                      </span>
                    </div>
                  ))}
                </div>
                <div>
                  <p className="mb-2 text-[10px] uppercase tracking-widest text-muted-foreground">
                    {m.features.length} features
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {m.features.map((f) => (
                      <Tag key={f}>{f}</Tag>
                    ))}
                  </div>
                </div>
              </div>
            );
          }}
        </QueryState>
      </Panel>

      <Panel
        title="Alert log"
        subtitle="Every notification decision: sent, de-duplicated (suppressed), failed or disabled (no credentials)"
        className="mt-4"
      >
        <QueryState
          q={alerts}
          empty="No alerts yet — alerts fire for detections at or above the thresholds in alerts/alerts.yaml."
        >
          {(rows) => (
            <div className="-m-5 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b text-[10px] uppercase tracking-widest text-muted-foreground">
                    <th className="px-5 py-2.5 font-medium">Time</th>
                    <th className="px-3 py-2.5 font-medium">Channel</th>
                    <th className="px-3 py-2.5 font-medium">Status</th>
                    <th className="px-3 py-2.5 font-medium">Severity</th>
                    <th className="px-3 py-2.5 font-medium">Type</th>
                    <th className="px-3 py-2.5 font-medium">IP</th>
                    <th className="px-5 py-2.5 font-medium">Note</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {rows.map((a) => (
                    <tr key={a.id} className="border-b border-border/50 last:border-0">
                      <td className="whitespace-nowrap px-5 py-2.5 text-muted-foreground">
                        {timeAgo(a.ts)}
                      </td>
                      <td className="px-3 py-2.5">{a.channel}</td>
                      <td className="px-3 py-2.5">
                        <span
                          className={`rounded border px-1.5 py-0.5 text-[10px] ${STATUS_STYLE[a.status] ?? "border-border"}`}
                        >
                          {a.status}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        <SeverityBadge level={a.severity} />
                      </td>
                      <td className="px-3 py-2.5">{a.attack_type}</td>
                      <td className="px-3 py-2.5">
                        {a.ip && a.ip !== "-" ? (
                          <Link
                            to="/attackers/$ip"
                            params={{ ip: a.ip }}
                            className="text-primary hover:underline"
                          >
                            {a.ip}
                          </Link>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td
                        className="max-w-0 truncate px-5 py-2.5 text-muted-foreground"
                        style={{ maxWidth: 320 }}
                        title={a.error ?? ""}
                      >
                        {a.error ?? ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </QueryState>
      </Panel>
    </div>
  );
}
