import { createFileRoute, Link } from "@tanstack/react-router";
import { Panel, PageHeader, ProtocolTag, timeAgo, QueryState } from "@/components/dashboard/ui";
import { useSearch } from "@/lib/api";
import { pageHead } from "@/lib/head";

type Search = { q?: string };

export const Route = createFileRoute("/search")({
  head: pageHead(
    "Search",
    "Full-text search over attacker commands and payloads, plus exact IP / credential match.",
  ),
  validateSearch: (s: Record<string, unknown>): Search =>
    typeof s["q"] === "string" ? { q: s["q"] } : {},
  component: SearchPage,
});

function SearchPage() {
  const { q = "" } = Route.useSearch();
  const res = useSearch(q);
  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <PageHeader
        title="Search"
        subtitle={
          q
            ? `Results for “${q}” — commands & payloads (full-text), IP, username or password`
            : "Type at least 2 characters in the sidebar search box"
        }
      />
      {q.trim().length >= 2 && (
        <Panel title="Matching events" subtitle="newest first, up to 300">
          <QueryState q={res} empty="No events match.">
            {(rows) => (
              <div className="-m-5 overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b text-[10px] uppercase tracking-widest text-muted-foreground">
                      <th className="px-5 py-2.5 font-medium">Time</th>
                      <th className="px-3 py-2.5 font-medium">Source</th>
                      <th className="px-3 py-2.5 font-medium">Protocol</th>
                      <th className="px-3 py-2.5 font-medium">Type</th>
                      <th className="px-5 py-2.5 font-medium">Detail</th>
                    </tr>
                  </thead>
                  <tbody className="font-mono">
                    {rows.map((e, i) => (
                      <tr
                        key={i}
                        className="border-b border-border/50 last:border-0 hover:bg-accent/40"
                      >
                        <td className="whitespace-nowrap px-5 py-2.5 text-muted-foreground">
                          {timeAgo(e.ts)}
                        </td>
                        <td className="px-3 py-2.5">
                          <Link
                            to="/attackers/$ip"
                            params={{ ip: e.ip }}
                            className="text-primary hover:underline"
                          >
                            {e.ip}
                          </Link>
                        </td>
                        <td className="px-3 py-2.5">
                          <ProtocolTag protocol={e.protocol} />
                        </td>
                        <td className="px-3 py-2.5 text-muted-foreground">{e.event_type}</td>
                        <td
                          className="max-w-0 truncate px-5 py-2.5 text-terminal"
                          style={{ maxWidth: 560 }}
                        >
                          {e.session_id ? (
                            <Link
                              to="/sessions/$sessionId"
                              params={{ sessionId: e.session_id }}
                              className="hover:underline"
                            >
                              {e.command ??
                                e.payload ??
                                (e.username != null ? `${e.username}:${e.password ?? ""}` : "—")}
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
      )}
    </div>
  );
}
