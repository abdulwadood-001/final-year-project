import { type ReactNode } from "react";
import { AlertTriangle, Download, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { protoLabel } from "@/lib/api";

export function Panel({
  title,
  subtitle,
  action,
  children,
  className,
}: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("rounded-lg border bg-card", className)}>
      {title && (
        <header className="flex items-center justify-between gap-4 border-b px-5 py-3.5">
          <div>
            <h2 className="text-sm font-semibold tracking-wide">{title}</h2>
            {subtitle && <p className="mt-0.5 text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          {action}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  subtitle,
  action,
}: {
  title: string;
  subtitle?: string;
  action?: ReactNode;
}) {
  return (
    <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 className="font-mono text-xl font-bold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-muted-foreground">{subtitle}</p>}
      </div>
      {action}
    </header>
  );
}

export function StatCard({
  label,
  value,
  hint,
  tone = "default",
  compact = false,
}: {
  label: string;
  value: string | number;
  hint?: string;
  tone?: "default" | "critical" | "ok";
  /** smaller, wrapping value for text such as "sensor:2323" or "success (admin)" */
  compact?: boolean;
}) {
  return (
    <div className="rounded-lg border bg-card p-4">
      <p className="text-[11px] font-medium uppercase tracking-widest text-muted-foreground">
        {label}
      </p>
      <p
        title={String(value)}
        className={cn(
          "mt-1.5 font-mono font-semibold tabular-nums",
          compact ? "break-all text-base leading-snug" : "truncate text-2xl",
          tone === "critical" && "text-sev-critical",
          tone === "ok" && "text-primary",
        )}
      >
        {value}
      </p>
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

const sevStyles: Record<string, string> = {
  CRITICAL: "bg-sev-critical/15 text-sev-critical border-sev-critical/30",
  HIGH: "bg-sev-high/15 text-sev-high border-sev-high/30",
  MEDIUM: "bg-sev-medium/15 text-sev-medium border-sev-medium/30",
  LOW: "bg-sev-low/15 text-sev-low border-sev-low/30",
};

export function SeverityBadge({ level }: { level: string | null | undefined }) {
  const l = level ?? "LOW";
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold tracking-wider",
        sevStyles[l] ?? sevStyles["LOW"],
      )}
    >
      {l}
    </span>
  );
}

export function ProtocolTag({ protocol }: { protocol: string | null | undefined }) {
  return (
    <span className="inline-flex rounded border border-border bg-secondary px-1.5 py-0.5 font-mono text-[10px] font-medium text-secondary-foreground">
      {protoLabel(protocol).toUpperCase()}
    </span>
  );
}

export function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex rounded border border-border bg-secondary px-1.5 py-0.5 font-mono text-[10px] text-secondary-foreground",
        className,
      )}
    >
      {children}
    </span>
  );
}

/** Marks rows whose location came from GEO_DEMO_MODE (lab/private IPs). */
export function DemoGeoTag({ source }: { source: string | null | undefined }) {
  if (source !== "demo") return null;
  return (
    <span
      title="Lab/private IP: demo location from GEO_DEMO_MODE, not a real GeoIP lookup"
      className="ml-1.5 rounded border border-sev-medium/40 px-1 py-px font-mono text-[9px] font-semibold text-sev-medium"
    >
      DEMO
    </span>
  );
}

export function timeAgo(iso: string | null | undefined) {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return "—";
  const s = Math.max(0, (Date.now() - t) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function LiveDot({ className }: { className?: string }) {
  return (
    <span className="relative flex size-2">
      <span
        className={cn(
          "absolute inline-flex size-2 rounded-full bg-primary animate-pulse-dot",
          className,
        )}
      />
    </span>
  );
}

/** Loading / error / empty wrapper for a react-query result. */
export function QueryState<T>({
  q,
  empty,
  children,
  isEmpty,
}: {
  q: { data: T | undefined; isLoading: boolean; isError: boolean; error: unknown };
  empty?: string;
  isEmpty?: (d: T) => boolean;
  children: (data: T) => ReactNode;
}) {
  if (q.isLoading) {
    return (
      <div className="flex items-center gap-2 py-6 text-xs text-muted-foreground">
        <Loader2 className="size-3.5 animate-spin" /> loading…
      </div>
    );
  }
  if (q.isError || q.data === undefined) {
    return (
      <div className="flex items-start gap-2 rounded-md border border-sev-critical/30 bg-sev-critical/10 px-3 py-2.5 text-xs text-sev-critical">
        <AlertTriangle className="mt-px size-3.5 shrink-0" />
        <span>{q.error instanceof Error ? q.error.message : "could not load data"}</span>
      </div>
    );
  }
  const d = q.data;
  const emptyNow = isEmpty ? isEmpty(d) : Array.isArray(d) && d.length === 0;
  if (emptyNow)
    return <p className="py-4 text-xs text-muted-foreground">{empty ?? "Nothing recorded yet."}</p>;
  return <>{children(d)}</>;
}

export function Pills<T extends string>({
  value,
  options,
  onChange,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
}) {
  return (
    <div className="flex flex-wrap gap-1">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          onClick={() => onChange(o.value)}
          className={cn(
            "rounded-md border px-2.5 py-1 text-xs transition-colors",
            value === o.value
              ? "border-primary/40 bg-primary/15 text-primary"
              : "border-border text-muted-foreground hover:bg-accent hover:text-foreground",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function DownloadButton({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      download
      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-secondary px-3 py-1.5 text-xs font-medium text-secondary-foreground transition-colors hover:bg-accent"
    >
      <Download className="size-3.5" />
      {children}
    </a>
  );
}

export const TH = ({
  children,
  right,
  className,
}: {
  children?: ReactNode;
  right?: boolean;
  className?: string;
}) => (
  <th
    className={cn("px-3 py-2.5 font-medium first:pl-5 last:pr-5", right && "text-right", className)}
  >
    {children}
  </th>
);

export function DataTable({ head, children }: { head: ReactNode; children: ReactNode }) {
  return (
    <div className="-m-5 overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead>
          <tr className="border-b text-[10px] uppercase tracking-widest text-muted-foreground">
            {head}
          </tr>
        </thead>
        <tbody className="font-mono">{children}</tbody>
      </table>
    </div>
  );
}
