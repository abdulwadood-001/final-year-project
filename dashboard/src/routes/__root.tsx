import { useEffect, useState, type FormEvent } from "react";
import type { QueryClient } from "@tanstack/react-query";
import {
  Outlet,
  Link,
  createRootRouteWithContext,
  useNavigate,
  useRouter,
  useRouterState,
  type ErrorComponentProps,
} from "@tanstack/react-router";
import {
  Activity,
  Bug,
  Crosshair,
  FileText,
  Fingerprint,
  LayoutDashboard,
  MonitorSmartphone,
  ScrollText,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { useStats } from "@/lib/api";
import { LiveProvider, useLive } from "@/lib/live";
import { SeverityBadge } from "@/components/dashboard/ui";

const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/attackers", label: "Attackers", icon: Crosshair },
  { to: "/detections", label: "Detections", icon: ShieldAlert },
  { to: "/devices", label: "Devices", icon: MonitorSmartphone },
  { to: "/sessions", label: "Sessions", icon: ScrollText },
  { to: "/malware", label: "Malware", icon: Bug },
  { to: "/iocs", label: "IOCs & MITRE", icon: Fingerprint },
  { to: "/reports", label: "Reports & Alerts", icon: FileText },
] as const;

function NotFoundComponent() {
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <div className="max-w-md text-center">
        <h1 className="text-7xl font-bold text-foreground">404</h1>
        <h2 className="mt-4 text-xl font-semibold text-foreground">Page not found</h2>
        <p className="mt-2 text-sm text-muted-foreground">This dashboard page does not exist.</p>
        <Link
          to="/"
          className="mt-6 inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          Back to overview
        </Link>
      </div>
    </div>
  );
}

function ErrorComponent({ error, reset }: ErrorComponentProps) {
  const router = useRouter();
  useEffect(() => console.error(error), [error]);
  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <div className="max-w-md text-center">
        <h1 className="text-xl font-semibold tracking-tight text-foreground">
          This page didn't load
        </h1>
        <p className="mt-2 font-mono text-xs text-muted-foreground">
          {error instanceof Error ? error.message : String(error)}
        </p>
        <button
          onClick={() => {
            void router.invalidate();
            reset();
          }}
          className="mt-6 inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          Try again
        </button>
      </div>
    </div>
  );
}

export const Route = createRootRouteWithContext<{ queryClient: QueryClient }>()({
  component: RootComponent,
  notFoundComponent: NotFoundComponent,
  errorComponent: ErrorComponent,
});

/** SPA replacement for Start's <HeadContent>: use the deepest route's head() title. */
function useDocumentTitle() {
  const matches = useRouterState({ select: (s) => s.matches });
  useEffect(() => {
    for (let i = matches.length - 1; i >= 0; i--) {
      const meta = (matches[i] as { meta?: ({ title?: string } | undefined)[] } | undefined)?.meta;
      const title = meta?.find((m) => m?.title)?.title;
      if (title) {
        document.title = title;
        return;
      }
    }
    document.title = "HoneyBot-IoT — Honeypot Threat Dashboard";
  }, [matches]);
}

function SearchBox({ onDone }: { onDone?: () => void }) {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (q.trim().length < 2) return;
    void navigate({ to: "/search", search: { q: q.trim() } });
    onDone?.();
  };
  return (
    <form onSubmit={submit} className="relative">
      <Search className="pointer-events-none absolute left-2.5 top-2 size-3.5 text-muted-foreground" />
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="IP, command, credential…"
        aria-label="Search events"
        className="w-full rounded-md border border-border bg-background py-1.5 pl-8 pr-2 text-xs outline-none placeholder:text-muted-foreground focus:border-primary/50"
      />
    </form>
  );
}

function StatusFooter() {
  const { status, eventsPerMin } = useLive();
  const stats = useStats();
  const up = stats.data?.services_up;
  const total = stats.data?.services_total;
  return (
    <div className="space-y-2 border-t p-4 text-xs text-muted-foreground">
      <div className="flex items-center gap-2">
        <span className="relative flex size-2">
          <span
            className={cn(
              "absolute size-2 rounded-full",
              status === "live"
                ? "animate-pulse-dot bg-primary"
                : status === "connecting"
                  ? "bg-sev-medium"
                  : "bg-sev-critical",
            )}
          />
        </span>
        {status === "live"
          ? `live · ${eventsPerMin} events/min`
          : status === "connecting"
            ? "connecting…"
            : "live feed offline · polling"}
      </div>
      <div className="flex items-center gap-2">
        <span
          className={cn(
            "size-2 rounded-full",
            up != null && up === total ? "bg-primary" : "bg-sev-high",
          )}
        />
        {stats.isError
          ? "API unreachable"
          : up == null
            ? "checking services…"
            : `${up}/${total} services online`}
      </div>
      <p className="font-mono text-[10px] text-muted-foreground/60">
        milestone 70% · v{stats.data?.version ?? "0.7"}
      </p>
    </div>
  );
}

function Toasts() {
  const { toasts, dismiss } = useLive();
  if (!toasts.length) return null;
  return (
    <div className="fixed bottom-4 right-4 z-50 flex w-80 flex-col gap-2">
      {toasts.map(({ id, detection: d }) => (
        <div key={id} className="rounded-lg border border-sev-critical/40 bg-popover p-3 shadow-xl">
          <div className="flex items-center gap-2">
            <SeverityBadge level={d.severity} />
            <p className="truncate text-xs font-semibold">{d.attack_type}</p>
            <button
              onClick={() => dismiss(id)}
              className="ml-auto text-muted-foreground hover:text-foreground"
              aria-label="dismiss"
            >
              <X className="size-3.5" />
            </button>
          </div>
          <p className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">{d.details}</p>
          <Link
            to="/attackers/$ip"
            params={{ ip: d.ip }}
            className="mt-1 inline-block font-mono text-[11px] text-primary hover:underline"
          >
            {d.ip}
          </Link>
        </div>
      ))}
    </div>
  );
}

function RootComponent() {
  useDocumentTitle();
  const [mobileSearch, setMobileSearch] = useState(false);
  return (
    <LiveProvider>
      <div className="flex min-h-screen bg-background">
        <aside className="fixed inset-y-0 left-0 z-20 hidden w-56 flex-col border-r bg-card/60 md:flex">
          <div className="flex items-center gap-2.5 border-b px-5 py-4">
            <div className="flex size-8 items-center justify-center rounded-md bg-primary/15">
              <Activity className="size-4 text-primary" />
            </div>
            <div>
              <p className="font-mono text-sm font-bold leading-none tracking-tight">
                HoneyBot-IoT
              </p>
              <p className="mt-1 text-[10px] uppercase tracking-widest text-muted-foreground">
                Honeynet SOC
              </p>
            </div>
          </div>
          <div className="px-3 pt-3">
            <SearchBox />
          </div>
          <nav className="flex-1 space-y-0.5 overflow-y-auto p-3">
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                activeOptions={{ exact: item.to === "/" }}
                className="flex items-center gap-2.5 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
                activeProps={{ className: "bg-accent text-primary font-medium hover:text-primary" }}
              >
                <item.icon className="size-4" />
                {item.label}
              </Link>
            ))}
          </nav>
          <StatusFooter />
        </aside>

        {/* Mobile top bar */}
        <div className="fixed inset-x-0 top-0 z-20 border-b bg-card/90 px-3 py-2 backdrop-blur md:hidden">
          <div className="flex items-center justify-between gap-2">
            <p className="font-mono text-sm font-bold">HoneyBot-IoT</p>
            <button
              onClick={() => setMobileSearch((v) => !v)}
              className="rounded-md p-2 text-muted-foreground hover:bg-accent"
              aria-label="search"
            >
              <Search className="size-4" />
            </button>
          </div>
          {mobileSearch && (
            <div className="pb-2">
              <SearchBox onDone={() => setMobileSearch(false)} />
            </div>
          )}
          <nav className="flex gap-1 overflow-x-auto">
            {NAV.map((item) => (
              <Link
                key={item.to}
                to={item.to}
                activeOptions={{ exact: item.to === "/" }}
                title={item.label}
                className="rounded-md p-2 text-muted-foreground hover:bg-accent"
                activeProps={{ className: "bg-accent text-primary" }}
              >
                <item.icon className="size-4" />
              </Link>
            ))}
          </nav>
        </div>

        <main className="min-w-0 flex-1 pt-24 md:ml-56 md:pt-0">
          <Outlet />
        </main>
        <Toasts />
      </div>
    </LiveProvider>
  );
}
