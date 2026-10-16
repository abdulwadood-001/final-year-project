import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Cell,
} from "recharts";
import { RefreshCw } from "lucide-react";
import {
  Panel,
  PageHeader,
  StatCard,
  SeverityBadge,
  ProtocolTag,
  LiveDot,
  timeAgo,
  QueryState,
  DemoGeoTag,
  Pills,
} from "@/components/dashboard/ui";
import { WorldMap } from "@/components/dashboard/world-map";
import {
  useStats,
  useRecent,
  useTimeline,
  useMap,
  useTopAttackers,
  PROTOCOLS,
  runDetectionPass,
} from "@/lib/api";
import { useLive } from "@/lib/live";
import { pageHead } from "@/lib/head";
import { useQueryClient } from "@tanstack/react-query";

export const Route = createFileRoute("/")({
  head: pageHead("Overview", "Live overview of attacks against the HoneyBot-IoT honeynet."),
  component: Overview,
});

const PROTOCOL_COLORS: Record<string, string> = {
  ssh: "var(--color-chart-1)",
  telnet: "var(--color-chart-2)",
  http: "var(--color-chart-3)",
  mqtt: "var(--color-chart-4)",
  rtsp: "var(--color-chart-5)",
};

const tooltipStyle = {
  contentStyle: {
    background: "var(--color-popover)",
    border: "1px solid var(--color-border)",
    borderRadius: 8,
    fontSize: 12,
  },
  labelStyle: { color: "var(--color-foreground)" },
};

function Overview() {
  const stats = useStats();
  const [hours, setHours] = useState<"24" | "72" | "168">("24");
  const timeline = useTimeline(Number(hours));
  const recent = useRecent(40);
  const map = useMap();
  const top = useTopAttackers(8);
  const live = useLive();
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);

  const s = stats.data;
  const protocolBars = PROTOCOLS.map((p) => ({
    name: p.toUpperCase(),
    value: s?.sessions[p] ?? 0,
  }));
  const timelineData = (timeline.data ?? []).map((t) => ({
    ...t,
    label: new Date(t.hour).toLocaleString(
      [],
      hours === "24"
        ? { hour: "2-digit", minute: "2-digit" }
        : { weekday: "short", hour: "2-digit" },
    ),
  }));

  const detectNow = async () => {
    setBusy(true);
    try {
      await runDetectionPass();
      await qc.invalidateQueries();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <PageHeader
        title="Threat Overview"
        subtitle="Honeynet activity across all 3 emulated devices and 5 protocols"
        action={
          <div className="flex items-center gap-2">
            <button
              onClick={detectNow}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-md border bg-card px-3 py-1.5 text-xs text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-50"
              title="Run the threat-intelligence engine now (normally every 30 s)"
            >
              <RefreshCw className={`size-3.5 ${busy ? "animate-spin" : ""}`} /> Detect now
            </button>
            <div className="flex items-center gap-2 rounded-md border bg-card px-3 py-1.5 text-xs text-muted-foreground">
              <LiveDot /> {live.status === "live" ? "Live" : "Polling"} · {s?.active_sessions ?? 0}{" "}
              active sessions
            </div>
          </div>
        }
      />

      <QueryState q={stats} isEmpty={() => false}>
        {(st) => (
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4 xl:grid-cols-7">
            <StatCard
              label="Total Events"
              value={st.total_events.toLocaleString()}
              hint={`${st.events_24h.toLocaleString()} in 24h`}
            />
            <StatCard
              label="Unique Attackers"
              value={st.unique_ips}
              hint={`${st.total_sessions.toLocaleString()} sessions`}
            />
            <StatCard
              label="Detections"
              value={st.detections}
              hint={`${st.alerts_sent} alerts sent`}
            />
            <StatCard
              label="Critical"
              value={st.critical}
              tone={st.critical ? "critical" : "default"}
              hint="needs review"
            />
            <StatCard
              label="Successful Logins"
              value={st.successful_logins}
              hint={`${st.commands.toLocaleString()} commands run`}
            />
            <StatCard
              label="Malware Samples"
              value={st.samples}
              tone={st.malicious_samples ? "critical" : "default"}
              hint={`${st.malicious_samples} matched YARA`}
            />
            <StatCard label="IOCs Captured" value={st.iocs} hint="URLs · IPs · hashes" />
          </div>
        )}
      </QueryState>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Panel
          title="Attack Timeline"
          subtitle="Events per hour by protocol"
          className="min-w-0 xl:col-span-2"
          action={
            <Pills
              value={hours}
              onChange={setHours}
              options={[
                { value: "24", label: "24h" },
                { value: "72", label: "3d" },
                { value: "168", label: "7d" },
              ]}
            />
          }
        >
          <div className="h-64 w-full min-w-0">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timelineData} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="var(--color-border)"
                  vertical={false}
                />
                <XAxis
                  dataKey="label"
                  tick={{ fontSize: 10, fill: "var(--color-muted-foreground)" }}
                  tickLine={false}
                  axisLine={false}
                  minTickGap={24}
                />
                <YAxis
                  tick={{ fontSize: 10, fill: "var(--color-muted-foreground)" }}
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                />
                <Tooltip {...tooltipStyle} />
                {Object.keys(PROTOCOL_COLORS).map((p) => (
                  <Area
                    key={p}
                    type="monotone"
                    dataKey={p}
                    name={p.toUpperCase()}
                    stackId="1"
                    stroke={PROTOCOL_COLORS[p]}
                    fill={PROTOCOL_COLORS[p]}
                    fillOpacity={0.25}
                    strokeWidth={1.5}
                  />
                ))}
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Sessions by Protocol" subtitle="All time">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={protocolBars}
                layout="vertical"
                margin={{ top: 4, right: 12, left: 8, bottom: 0 }}
              >
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="var(--color-border)"
                  horizontal={false}
                />
                <XAxis
                  type="number"
                  tick={{ fontSize: 10, fill: "var(--color-muted-foreground)" }}
                  tickLine={false}
                  axisLine={false}
                  allowDecimals={false}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  tick={{
                    fontSize: 11,
                    fill: "var(--color-foreground)",
                    fontFamily: "var(--font-mono)",
                  }}
                  tickLine={false}
                  axisLine={false}
                  width={56}
                />
                <Tooltip {...tooltipStyle} cursor={{ fill: "var(--color-accent)" }} />
                <Bar dataKey="value" name="sessions" radius={[0, 4, 4, 0]}>
                  {protocolBars.map((b) => (
                    <Cell key={b.name} fill={PROTOCOL_COLORS[b.name.toLowerCase()]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Panel
          title="Attack Origins"
          subtitle="GeoIP of observed attackers · heat = activity"
          className="min-w-0 xl:col-span-2"
        >
          <QueryState
            q={map}
            empty="No located attackers yet (run deploy/get_geoip.sh for real GeoIP, or GEO_DEMO_MODE=true in the lab)."
          >
            {(pts) => <WorldMap points={pts} />}
          </QueryState>
        </Panel>

        <Panel title="Top Threats" subtitle="Highest threat score">
          <QueryState q={top} empty="No attackers correlated yet.">
            {(rows) => (
              <div className="space-y-3">
                {rows.map((a) => (
                  <div key={a.ip} className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <Link
                        to="/attackers/$ip"
                        params={{ ip: a.ip }}
                        className="truncate font-mono text-xs text-primary hover:underline"
                      >
                        {a.ip}
                      </Link>
                      <p className="truncate text-[11px] text-muted-foreground">
                        {[a.city, a.country].filter(Boolean).join(", ") || "location unknown"}
                        <DemoGeoTag source={a.geo_source} />
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="font-mono text-xs text-muted-foreground">
                        {a.threat_score}
                      </span>
                      <SeverityBadge level={a.threat_level} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </QueryState>
        </Panel>
      </div>

      <Panel
        title="Live Event Feed"
        subtitle="Most recent attacker interactions"
        className="mt-4"
        action={
          <span className="flex items-center gap-1.5 text-xs text-primary">
            <LiveDot /> {live.status === "live" ? "streaming" : "polling"}
          </span>
        }
      >
        <QueryState
          q={recent}
          empty="No attacker activity yet — run the simulator or wait for real traffic."
        >
          {(rows) => (
            <div className="-m-5 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b text-[10px] uppercase tracking-widest text-muted-foreground">
                    <th className="px-5 py-2.5 font-medium">Time</th>
                    <th className="px-3 py-2.5 font-medium">Source IP</th>
                    <th className="px-3 py-2.5 font-medium">Protocol</th>
                    <th className="px-3 py-2.5 font-medium">Device</th>
                    <th className="px-3 py-2.5 font-medium">Event</th>
                    <th className="px-5 py-2.5 font-medium">Detail</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {rows.slice(0, 40).map((e, i) => (
                    <tr
                      key={e.id ?? `${e.ts}-${i}`}
                      className="border-b border-border/50 last:border-0 hover:bg-accent/40"
                    >
                      <td className="whitespace-nowrap px-5 py-2.5 text-muted-foreground">
                        {timeAgo(e.ts)}
                      </td>
                      <td className="whitespace-nowrap px-3 py-2.5">
                        <Link
                          to="/attackers/$ip"
                          params={{ ip: e.ip }}
                          className="hover:text-primary hover:underline"
                        >
                          {e.ip}
                        </Link>
                        {e.country_code && (
                          <span className="ml-1.5 text-muted-foreground">[{e.country_code}]</span>
                        )}
                      </td>
                      <td className="px-3 py-2.5">
                        <ProtocolTag protocol={e.protocol} />
                      </td>
                      <td className="px-3 py-2.5 text-muted-foreground">{e.device}</td>
                      <td className="px-3 py-2.5">
                        <span
                          className={
                            e.event_type === "auth"
                              ? e.success
                                ? "text-sev-critical"
                                : "text-sev-medium"
                              : "text-foreground"
                          }
                        >
                          {e.event_type}
                          {e.event_type === "auth" ? (e.success ? " ✓" : " ✗") : ""}
                        </span>
                      </td>
                      <td
                        className="max-w-0 truncate px-5 py-2.5 text-muted-foreground"
                        style={{ maxWidth: 420 }}
                      >
                        {e.session_id ? (
                          <Link
                            to="/sessions/$sessionId"
                            params={{ sessionId: e.session_id }}
                            className="hover:text-foreground"
                          >
                            {e.command ??
                              (e.username != null
                                ? `${e.username}:${e.password ?? ""}`
                                : e.payload) ??
                              "—"}
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
          )}
        </QueryState>
      </Panel>
    </div>
  );
}
