// Device-specific panels for /devices/$device, driven by GET /api/devices/{device}.
import {
  Lock,
  LockOpen,
  Battery,
  Thermometer,
  Gauge,
  Droplets,
  Video,
  Circle,
  DoorClosed,
  DoorOpen,
  Siren,
} from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import { Panel, timeAgo } from "@/components/dashboard/ui";
import type { DeviceDetail, StateChange } from "@/lib/api";

const num = (v: string | undefined, d = 0) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};

/** One-line status shown on the device cards. */
export function headline(
  device: string,
  st: Record<string, string>,
): { text: string; tone: string } | null {
  if (device === "smartlock") {
    const open = st["lock_state"] === "unlocked";
    return {
      text: open ? "UNLOCKED" : "LOCKED",
      tone: open ? "text-sev-critical" : "text-primary",
    };
  }
  if (device === "sensor") {
    const alarm = st["alarm"] && st["alarm"] !== "none";
    return {
      text: alarm ? `ALARM · ${st["alarm"]}` : `${st["temperature"] ?? "?"} °C · normal`,
      tone: alarm ? "text-sev-critical" : "text-primary",
    };
  }
  if (device === "cctv") {
    const off = st["recording"] === "off";
    return {
      text: off
        ? "RECORDING DISABLED"
        : st["motion"] === "true"
          ? "RECORDING · motion"
          : "RECORDING",
      tone: off ? "text-sev-critical" : "text-primary",
    };
  }
  return null;
}

function ChangeLog({ changes, empty }: { changes: StateChange[]; empty: string }) {
  if (!changes.length) return <p className="text-xs text-muted-foreground">{empty}</p>;
  return (
    <div className="max-h-64 space-y-1.5 overflow-y-auto font-mono text-xs">
      {changes.map((c, i) => {
        const [via, ip] = c.actor.includes(":") ? c.actor.split(/:(.*)/s) : [c.actor, ""];
        return (
          <p
            key={i}
            className="flex justify-between gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2"
          >
            <span className="w-16 shrink-0 text-muted-foreground">{timeAgo(c.ts)}</span>
            <span className="min-w-0 flex-1 truncate text-terminal">
              {Object.entries(c.fields)
                .map(([k, v]) => `${k}=${v}`)
                .join(" ")}
            </span>
            <span className="shrink-0 uppercase text-muted-foreground">{via}</span>
            <span className="shrink-0 text-primary">{ip || ""}</span>
          </p>
        );
      })}
    </div>
  );
}

function CameraView({ d }: { d: DeviceDetail }) {
  const st = d.state;
  const recording = st["recording"] !== "off";
  const cams = ["CH1 · Front Door", "CH2 · Parking Lot", "CH3 · Loading Bay", "CH4 · Warehouse"];
  const logins = d.web_logins ?? {};
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel
        title="Camera Feeds"
        subtitle={`Decoy channels of ${st["model"] ?? "the camera"} — RTSP signalling only, no real video`}
      >
        <div className="grid grid-cols-2 gap-3">
          {cams.map((c, i) => (
            <div
              key={c}
              className="relative aspect-video overflow-hidden rounded-md border bg-background"
            >
              <div className="bg-grid absolute inset-0 opacity-60" />
              <div className="absolute inset-0 flex items-center justify-center">
                <Video className="size-8 text-muted-foreground/40" />
              </div>
              <div className="absolute left-2 top-2 flex items-center gap-1.5 rounded bg-card/80 px-1.5 py-0.5 font-mono text-[10px]">
                <Circle
                  className={`size-2 ${recording ? "fill-sev-critical text-sev-critical animate-pulse-dot" : "fill-muted text-muted-foreground"}`}
                />
                {recording ? "REC" : "OFF"}
              </div>
              {i === 0 && st["motion"] === "true" && (
                <div className="absolute right-2 top-2 rounded bg-sev-high/20 px-1.5 py-0.5 font-mono text-[10px] text-sev-high">
                  MOTION
                </div>
              )}
              <p className="absolute bottom-2 left-2 font-mono text-[10px] text-terminal">{c}</p>
            </div>
          ))}
        </div>
        <div className="mt-4 grid grid-cols-3 gap-2 font-mono text-xs">
          <p className="rounded-md border bg-background/40 p-2">
            viewers <span className="float-right text-terminal">{st["viewers"] ?? 0}</span>
          </p>
          <p className="rounded-md border bg-background/40 p-2">
            streams opened <span className="float-right text-terminal">{d.stream_opens ?? 0}</span>
          </p>
          <p className="rounded-md border bg-background/40 p-2">
            last motion{" "}
            <span className="float-right text-terminal">{timeAgo(st["last_motion"] || null)}</span>
          </p>
        </div>
        <div className="mt-3 rounded-md border bg-background/40 p-3 font-mono text-xs">
          <p className="mb-1 text-[10px] uppercase tracking-widest text-muted-foreground">
            Web panel (HTTP :8080 / HTTPS :8443)
          </p>
          <p className="text-muted-foreground">
            Boa web login · {(logins["success"] ?? 0) + (logins["failed"] ?? 0)} attempts ·{" "}
            <span className="text-sev-critical">{logins["success"] ?? 0} successful</span>
          </p>
        </div>
      </Panel>
      <div className="space-y-4">
        <Panel
          title="Stream paths probed"
          subtitle="RTSP routes requested by attackers (Cameradar-style enumeration)"
        >
          {(d.stream_paths ?? []).length === 0 ? (
            <p className="text-xs text-muted-foreground">No RTSP requests yet.</p>
          ) : (
            <div className="space-y-1.5 font-mono text-xs">
              {(d.stream_paths ?? []).map((p) => (
                <p
                  key={p.path}
                  className="flex justify-between gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-1.5"
                >
                  <span className="truncate text-terminal">{p.path}</span>
                  <span className="shrink-0 text-muted-foreground">
                    {p.requests} req · {p.ips} IPs
                  </span>
                </p>
              ))}
            </div>
          )}
        </Panel>
        <Panel
          title="Attacker changes"
          subtitle="e.g. recording disabled over MQTT camera/cmd (Denial of View)"
        >
          <ChangeLog changes={d.changes} empty="No attacker-made changes." />
        </Panel>
      </div>
    </div>
  );
}

function LockView({ d }: { d: DeviceDetail }) {
  const st = d.state;
  const unlocked = st["lock_state"] === "unlocked";
  const doorOpen = st["door"] === "open";
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Panel
        title="Lock Control"
        subtitle="Emulated SL-200 door lock — state shared by SSH lockctl, HTTP REST and MQTT lock/cmd"
      >
        <div className="flex items-center gap-6">
          <div
            className={`flex size-24 items-center justify-center rounded-full border-2 ${unlocked ? "border-sev-critical/50 bg-sev-critical/10" : "border-primary/50 bg-primary/10"}`}
          >
            {unlocked ? (
              <LockOpen className="size-10 text-sev-critical" />
            ) : (
              <Lock className="size-10 text-primary" />
            )}
          </div>
          <div className="space-y-2 text-sm">
            <p
              className={`font-mono text-lg font-bold ${unlocked ? "text-sev-critical" : "text-primary"}`}
            >
              {unlocked ? "UNLOCKED" : "LOCKED"}
            </p>
            <p className="flex items-center gap-2 text-muted-foreground">
              <Battery className="size-4" /> Battery {st["battery"] ?? "?"}%
            </p>
            <p className="flex items-center gap-2 text-muted-foreground">
              {doorOpen ? <DoorOpen className="size-4" /> : <DoorClosed className="size-4" />} Door{" "}
              {st["door"] ?? "?"} · auto-lock {st["auto_lock"] ?? "?"}
            </p>
            <p className="font-mono text-xs text-muted-foreground">
              fw {st["firmware"]} · last {st["last_action"] || "—"} by {st["last_actor"] || "—"}{" "}
              {st["last_change"] ? `(${timeAgo(st["last_change"])})` : ""}
            </p>
          </div>
        </div>
      </Panel>
      <Panel
        title="Lock / unlock log"
        subtitle="Every state change with protocol and source IP (auto-lock re-locks after 60 s)"
      >
        <ChangeLog changes={d.changes} empty="Nobody has operated the lock yet." />
      </Panel>
    </div>
  );
}

function SensorView({ d }: { d: DeviceDetail }) {
  const st = d.state;
  const tThr = num(st["temp_threshold"], 80);
  const pThr = num(st["pressure_threshold"], 150);
  const gauges = [
    {
      label: "Temperature",
      value: num(st["temperature"]),
      unit: "°C",
      max: Math.max(tThr * 1.25, 100),
      thr: tThr,
      icon: Thermometer,
    },
    {
      label: "Pressure",
      value: num(st["pressure"]),
      unit: "kPa",
      max: Math.max(pThr * 1.1, 160),
      thr: pThr,
      icon: Gauge,
    },
    {
      label: "Humidity",
      value: num(st["humidity"]),
      unit: "%",
      max: 100,
      thr: null,
      icon: Droplets,
    },
  ];
  const history = (d.history ?? []).map((h) => ({
    ...h,
    t: new Date(h.ts).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }),
  }));
  const alarm = st["alarm"] && st["alarm"] !== "none";
  return (
    <div className="space-y-4">
      <Panel
        title="Sensor Readings"
        subtitle="Live ISN-4000 telemetry — also published on MQTT sensor/* and the HMI on :8082"
        action={
          alarm ? (
            <span className="flex items-center gap-1.5 font-mono text-xs text-sev-critical">
              <Siren className="size-4" /> {st["alarm"]}
            </span>
          ) : undefined
        }
      >
        <div className="grid grid-cols-3 gap-3">
          {gauges.map((g) => (
            <div key={g.label} className="rounded-md border bg-background/40 p-3">
              <p className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-muted-foreground">
                <g.icon className="size-3.5" /> {g.label}
              </p>
              <p
                className={`mt-2 font-mono text-xl font-semibold ${g.thr != null && g.value > g.thr ? "text-sev-critical" : ""}`}
              >
                {g.value.toFixed(1)}
                <span className="ml-1 text-xs text-muted-foreground">{g.unit}</span>
              </p>
              <div className="relative mt-2 h-1.5 rounded bg-secondary">
                <div
                  className="h-full rounded bg-primary"
                  style={{ width: `${Math.min(100, (g.value / g.max) * 100)}%` }}
                />
                {g.thr != null && (
                  <div
                    className="absolute -top-1 h-3.5 w-0.5 bg-sev-critical"
                    style={{ left: `${Math.min(100, (g.thr / g.max) * 100)}%` }}
                  />
                )}
              </div>
              {g.thr != null && (
                <p className="mt-1 font-mono text-[10px] text-muted-foreground">
                  threshold {g.thr}
                  {g.unit}
                </p>
              )}
            </div>
          ))}
        </div>
        <div className="mt-4 h-56">
          {history.length < 2 ? (
            <p className="text-xs text-muted-foreground">
              Collecting telemetry history (one sample every 5 s)…
            </p>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="var(--color-border)"
                  vertical={false}
                />
                <XAxis
                  dataKey="t"
                  tick={{ fontSize: 10, fill: "var(--color-muted-foreground)" }}
                  tickLine={false}
                  axisLine={false}
                  minTickGap={40}
                />
                <YAxis
                  tick={{ fontSize: 10, fill: "var(--color-muted-foreground)" }}
                  tickLine={false}
                  axisLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "var(--color-popover)",
                    border: "1px solid var(--color-border)",
                    borderRadius: 8,
                    fontSize: 12,
                  }}
                />
                <ReferenceLine
                  y={tThr}
                  stroke="var(--color-sev-critical)"
                  strokeDasharray="4 4"
                  label={{
                    value: "temp threshold",
                    fontSize: 10,
                    fill: "var(--color-sev-critical)",
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="temperature"
                  name="°C"
                  stroke="var(--color-chart-2)"
                  dot={false}
                  strokeWidth={1.5}
                  isAnimationActive={false}
                />
                <Line
                  type="monotone"
                  dataKey="humidity"
                  name="% RH"
                  stroke="var(--color-chart-4)"
                  dot={false}
                  strokeWidth={1.5}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </Panel>
      <div className="grid gap-4 lg:grid-cols-2">
        <Panel
          title="Configuration"
          subtitle="Writable over Telnet sensorctl, MQTT sensor/config/set and the HMI"
        >
          <div className="space-y-1.5 font-mono text-xs">
            {["temp_threshold", "pressure_threshold", "interval", "mode", "plc_link"].map((k) => (
              <p
                key={k}
                className="flex justify-between gap-3 rounded-md border border-border/60 bg-background/40 px-3 py-2"
              >
                <span className="text-muted-foreground">{k}</span>
                <span className="text-terminal">{st[k] ?? "—"}</span>
              </p>
            ))}
          </div>
        </Panel>
        <Panel
          title="Unauthorised changes"
          subtitle="ICS T0836 Modify Parameter / T0855 Unauthorized Command"
        >
          <ChangeLog changes={d.changes} empty="No configuration changes by attackers." />
        </Panel>
      </div>
    </div>
  );
}

export function DeviceSpecificView({ device, data }: { device: string; data: DeviceDetail }) {
  if (device === "cctv") return <CameraView d={data} />;
  if (device === "smartlock") return <LockView d={data} />;
  if (device === "sensor") return <SensorView d={data} />;
  return null;
}
