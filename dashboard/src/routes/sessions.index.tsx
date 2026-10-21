import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  Panel,
  PageHeader,
  ProtocolTag,
  timeAgo,
  QueryState,
  Pills,
} from "@/components/dashboard/ui";
import { useSessions, PROTOCOLS, shortId } from "@/lib/api";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/sessions/")({
  head: pageHead(
    "Sessions",
    "Every attacker connection to the honeynet, with auth attempts, commands and client fingerprints.",
  ),
  component: Sessions,
});

type Proto = "ALL" | (typeof PROTOCOLS)[number];

function Sessions() {
  const [proto, setProto] = useState<Proto>("ALL");
  const [active, setActive] = useState(false);
  const q = useSessions({ limit: 300, active, ...(proto !== "ALL" ? { protocol: proto } : {}) });

  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <PageHeader
        title="Sessions"
        subtitle="One row per attacker connection, across all five protocols"
      />

      <Panel
        title="Recent Sessions"
        subtitle="Newest connections first · click a session for its full replay"
        action={
          <div className="flex flex-wrap items-center gap-2">
            <Pills<Proto>
              value={proto}
              onChange={setProto}
              options={[
                { value: "ALL", label: "All" },
                ...PROTOCOLS.map((p) => ({ value: p, label: p })),
              ]}
            />
            <label className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={active}
                onChange={(e) => setActive(e.target.checked)}
                className="accent-[var(--primary)]"
              />
              active only
            </label>
          </div>
        }
      >
        <QueryState q={q} empty="No sessions match.">
          {(rows) => (
            <div className="-m-5 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b text-[10px] uppercase tracking-widest text-muted-foreground">
                    <th className="px-5 py-2.5 font-medium">Session</th>
                    <th className="px-3 py-2.5 font-medium">Source</th>
                    <th className="px-3 py-2.5 font-medium">Protocol</th>
                    <th className="px-3 py-2.5 font-medium">Device</th>
                    <th className="px-3 py-2.5 font-medium">Started</th>
                    <th className="px-3 py-2.5 font-medium">Status</th>
                    <th className="px-3 py-2.5 text-right font-medium">Auth</th>
                    <th className="px-3 py-2.5 text-right font-medium">Cmds</th>
                    <th className="px-5 py-2.5 font-medium">Client</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {rows.map((s) => (
                    <tr
                      key={s.session_id}
                      className="border-b border-border/50 last:border-0 hover:bg-accent/40"
                    >
                      <td className="px-5 py-3">
                        <Link
                          to="/sessions/$sessionId"
                          params={{ sessionId: s.session_id }}
                          className="text-primary hover:underline"
                        >
                          {shortId(s.session_id)}…
                        </Link>
                      </td>
                      <td className="whitespace-nowrap px-3 py-3">
                        <Link
                          to="/attackers/$ip"
                          params={{ ip: s.ip }}
                          className="hover:text-primary hover:underline"
                        >
                          {s.ip}
                        </Link>
                        <span className="ml-1.5 text-muted-foreground">:{s.src_port ?? "?"}</span>
                      </td>
                      <td className="px-3 py-3">
                        <ProtocolTag protocol={s.protocol} />
                      </td>
                      <td className="px-3 py-3 text-muted-foreground">{s.device}</td>
                      <td
                        className="whitespace-nowrap px-3 py-3 text-muted-foreground"
                        title={s.started_at}
                      >
                        {timeAgo(s.started_at)}
                      </td>
                      <td className="px-3 py-3">
                        {s.ended_at === null ? (
                          <span className="text-primary">● active</span>
                        ) : (
                          <span className="text-muted-foreground">closed</span>
                        )}
                      </td>
                      <td className="px-3 py-3 text-right tabular-nums">
                        {s.auth_attempts}
                        {s.login_success && <span className="ml-1 text-sev-critical">✓</span>}
                      </td>
                      <td className="px-3 py-3 text-right tabular-nums">{s.commands}</td>
                      <td
                        className="max-w-0 truncate px-5 py-3 text-muted-foreground"
                        style={{ maxWidth: 240 }}
                        title={s.client_version ?? ""}
                      >
                        {s.client_version || "—"}
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
