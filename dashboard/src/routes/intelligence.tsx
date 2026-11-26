import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";
import {
  Panel,
  PageHeader,
  StatCard,
  QueryState,
  Tag,
  DataTable,
  TH,
  timeAgo,
} from "@/components/dashboard/ui";
import {
  useMlModel,
  useMlRisk,
  useMlForecast,
  useMlPredictions,
  useMlPrediction,
  useMlFlow,
  shortId,
} from "@/lib/api";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/intelligence")({
  head: pageHead(
    "AI Threat Intelligence",
    "Module 8: ML classification, anomaly, risk and LLM narratives.",
  ),
  component: Intelligence,
});

const CLASS_COLOR: Record<string, string> = {
  malware_delivery: "var(--color-sev-critical)",
  botnet_c2: "var(--color-sev-high)",
  protocol_exploit: "var(--color-sev-high)",
  brute_force: "var(--color-sev-medium)",
  port_scan: "var(--color-sev-low)",
  normal: "var(--color-muted-foreground)",
};

function riskColor(r: number) {
  if (r >= 70) return "var(--color-sev-critical)";
  if (r >= 40) return "var(--color-sev-high)";
  if (r >= 20) return "var(--color-sev-medium)";
  return "var(--color-sev-low)";
}

function Intelligence() {
  const model = useMlModel();
  const risk = useMlRisk();
  const forecast = useMlForecast();
  const preds = useMlPredictions(0);
  const [openSession, setOpenSession] = useState<string | null>(null);
  const detail = useMlPrediction(openSession);
  const flow = useMlFlow();

  const cv = model.data?.cv;

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Threat Intelligence"
        subtitle="Module 8 — XGBoost classifier, Isolation Forest anomaly detector, LSTM risk forecast and LLM threat narratives."
      />

      {/* model status */}
      <QueryState q={model}>
        {(m) =>
          !m.trained ? (
            <Panel title="Model">
              <p className="text-sm text-muted-foreground">
                No model trained yet. Run <code>python -m ml.train</code> (or start the{" "}
                <code>ml_api</code> service, which trains a synthetic baseline on first boot).
              </p>
            </Panel>
          ) : (
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <StatCard label="Model" value={m.version ?? "xgboost"} />
              <StatCard
                label="CV accuracy"
                value={cv ? `${(cv.accuracy_mean * 100).toFixed(1)}%` : "—"}
                hint={cv ? `±${(cv.accuracy_std * 100).toFixed(1)}% · ${cv.folds}-fold` : ""}
              />
              <StatCard label="Training sessions" value={m.n_samples?.toLocaleString() ?? "—"} />
              <StatCard label="Classes" value={m.classes?.length ?? 6} />
            </div>
          )
        }
      </QueryState>

      {/* predictive per-device risk forecast (LSTM, M8-FE-4) */}
      <Panel
        title="Predictive risk — next 24 h"
        subtitle="LSTM forecast of attack-escalation risk per device, with contributing factors."
      >
        <QueryState q={forecast}>
          {(rows) =>
            rows.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No forecast yet — run a detection pass.
              </p>
            ) : (
              <div className="grid gap-4 md:grid-cols-3">
                {rows.map((f) => (
                  <div key={f.device} className="rounded-lg border border-border p-4">
                    <div className="flex items-center justify-between">
                      <span className="font-medium capitalize">{f.device}</span>
                      <Tag className="uppercase">{f.model}</Tag>
                    </div>
                    <div
                      className="mt-2 text-3xl font-semibold"
                      style={{ color: riskColor(f.risk) }}
                    >
                      {f.risk.toFixed(0)}
                      <span className="text-base text-muted-foreground">/100</span>
                    </div>
                    <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
                      {f.factors?.slice(0, 3).map((x, i) => (
                        <li key={i}>• {x}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            )
          }
        </QueryState>
      </Panel>

      {/* class distribution + per-device risk */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Sessions by attack class">
          <QueryState q={risk}>
            {(r) => (
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={r.by_class} layout="vertical" margin={{ left: 24 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="ml_class" width={120} tick={{ fontSize: 11 }} />
                  <Tooltip />
                  <Bar dataKey="n" radius={4}>
                    {r.by_class.map((c) => (
                      <Cell
                        key={c.ml_class}
                        fill={CLASS_COLOR[c.ml_class] ?? "var(--color-primary)"}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </QueryState>
        </Panel>

        <Panel title="Average risk by device (24 h)">
          <QueryState q={risk}>
            {(r) => (
              <DataTable
                head={
                  <>
                    <TH>Device</TH>
                    <TH>Avg risk</TH>
                    <TH>Max</TH>
                    <TH>High-risk</TH>
                  </>
                }
              >
                {r.by_device.map((d) => (
                  <tr key={d.device} className="border-t border-border">
                    <td className="px-3 py-2 capitalize">{d.device}</td>
                    <td className="px-3 py-2 font-medium" style={{ color: riskColor(d.avg_risk) }}>
                      {d.avg_risk?.toFixed(0)}
                    </td>
                    <td className="px-3 py-2">{d.max_risk?.toFixed(0)}</td>
                    <td className="px-3 py-2">{d.high_risk_sessions}</td>
                  </tr>
                ))}
              </DataTable>
            )}
          </QueryState>
        </Panel>
      </div>

      {/* network-flow IDS (multi-protocol IoT traffic model) */}
      <Panel
        title="Network-flow IDS"
        subtitle="1-second traffic windows from the honeypot's own PCAPs, classified by the IoT flow model."
      >
        <QueryState q={flow}>
          {(f) => (
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {f.summary.map((s) => (
                  <Tag key={s.label}>
                    {s.label}: {s.windows} windows · {s.ips} IPs
                  </Tag>
                ))}
              </div>
              {f.recent.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No scan or flood windows detected yet.
                </p>
              ) : (
                <DataTable
                  head={
                    <>
                      <TH>Window</TH>
                      <TH>Label</TH>
                      <TH>Conf.</TH>
                      <TH>IP</TH>
                      <TH>Device</TH>
                    </>
                  }
                >
                  {f.recent.slice(0, 20).map((r, i) => (
                    <tr key={i} className="border-t border-border">
                      <td className="px-3 py-2 text-xs text-muted-foreground">
                        {timeAgo(r.window_start)}
                      </td>
                      <td className="px-3 py-2">
                        <Tag>{r.label}</Tag>
                      </td>
                      <td className="px-3 py-2">{(r.confidence * 100).toFixed(0)}%</td>
                      <td className="px-3 py-2 font-mono text-xs">{r.ip}</td>
                      <td className="px-3 py-2 capitalize">{r.device ?? "—"}</td>
                    </tr>
                  ))}
                </DataTable>
              )}
            </div>
          )}
        </QueryState>
      </Panel>

      {/* classified sessions + narrative drawer */}
      <Panel
        title="AI-classified sessions"
        subtitle="Click a session for the LLM threat narrative."
      >
        <QueryState q={preds}>
          {(rows) => (
            <DataTable
              head={
                <>
                  <TH>Risk</TH>
                  <TH>Class</TH>
                  <TH>Conf.</TH>
                  <TH>Anomaly</TH>
                  <TH>IP</TH>
                  <TH>Device</TH>
                  <TH>When</TH>
                </>
              }
            >
              {rows.map((p) => (
                <tr
                  key={p.session_id}
                  className="cursor-pointer border-t border-border hover:bg-muted/40"
                  onClick={() => setOpenSession(p.session_id === openSession ? null : p.session_id)}
                >
                  <td className="px-3 py-2 font-semibold" style={{ color: riskColor(p.risk) }}>
                    {p.risk.toFixed(0)}
                  </td>
                  <td className="px-3 py-2">
                    <Tag className="capitalize">{p.ml_class.replace(/_/g, " ")}</Tag>
                  </td>
                  <td className="px-3 py-2">{(p.confidence * 100).toFixed(0)}%</td>
                  <td className="px-3 py-2">{(p.anomaly * 100).toFixed(0)}</td>
                  <td className="px-3 py-2 font-mono text-xs">
                    <Link to="/attackers/$ip" params={{ ip: p.ip }} className="hover:underline">
                      {p.ip}
                    </Link>
                  </td>
                  <td className="px-3 py-2 capitalize">{p.device ?? "—"}</td>
                  <td className="px-3 py-2 text-xs text-muted-foreground">
                    {timeAgo(p.predicted_at)}
                  </td>
                </tr>
              ))}
            </DataTable>
          )}
        </QueryState>

        {openSession && (
          <div className="mt-4 rounded-lg border border-primary/30 bg-muted/30 p-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-sm font-medium">
                Threat narrative — session {shortId(openSession)}
              </span>
              <button
                className="text-xs text-muted-foreground hover:underline"
                onClick={() => setOpenSession(null)}
              >
                close
              </button>
            </div>
            <QueryState q={detail}>
              {(d) => (
                <p className="whitespace-pre-wrap text-sm leading-relaxed">
                  {d.narrative ?? "No narrative stored for this session."}
                </p>
              )}
            </QueryState>
          </div>
        )}
      </Panel>
    </div>
  );
}
