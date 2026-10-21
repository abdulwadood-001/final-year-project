import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import {
  Panel,
  PageHeader,
  ProtocolTag,
  timeAgo,
  QueryState,
  Pills,
  DownloadButton,
} from "@/components/dashboard/ui";
import { useIocs, useMitre } from "@/lib/api";
import { pageHead } from "@/lib/head";

export const Route = createFileRoute("/iocs")({
  head: pageHead(
    "IOCs & MITRE",
    "Indicators of compromise captured by the honeynet and MITRE ATT&CK technique coverage.",
  ),
  component: Iocs,
});

const typeStyles: Record<string, string> = {
  url: "border-sev-high/30 bg-sev-high/15 text-sev-high",
  domain: "border-sev-medium/30 bg-sev-medium/15 text-sev-medium",
  ipv4: "border-sev-critical/30 bg-sev-critical/15 text-sev-critical",
  sha256: "border-sev-low/30 bg-sev-low/15 text-sev-low",
};

type T = "" | "url" | "domain" | "ipv4" | "sha256";

function Iocs() {
  const [type, setType] = useState<T>("");
  const iocs = useIocs(type || undefined, 500);
  const mitre = useMitre();

  return (
    <div className="bg-grid min-h-screen p-4 md:p-6">
      <PageHeader
        title="IOCs & MITRE ATT&CK"
        subtitle="Indicators captured from attacker tooling (never fetched), and technique coverage"
        action={
          <div className="flex gap-2">
            <DownloadButton href="/api/export/stix?hours=168">STIX 2.1 (7 days)</DownloadButton>
            <DownloadButton href="/api/export/stix?hours=720">STIX 2.1 (30 days)</DownloadButton>
          </div>
        }
      />

      <Panel
        title="Indicators of Compromise"
        subtitle="hits = distinct sightings (events, detections or captured samples)"
        action={
          <Pills<T>
            value={type}
            onChange={setType}
            options={[
              { value: "", label: "All" },
              { value: "url", label: "URLs" },
              { value: "domain", label: "Domains" },
              { value: "ipv4", label: "IPs" },
              { value: "sha256", label: "Hashes" },
            ]}
          />
        }
      >
        <QueryState q={iocs} empty="No indicators of this type yet.">
          {(rows) => (
            <div className="-m-5 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b text-[10px] uppercase tracking-widest text-muted-foreground">
                    <th className="px-5 py-2.5 font-medium">Type</th>
                    <th className="px-3 py-2.5 font-medium">Value</th>
                    <th className="px-3 py-2.5 font-medium">Context</th>
                    <th className="px-3 py-2.5 font-medium">Source</th>
                    <th className="px-3 py-2.5 font-medium">Protocol</th>
                    <th className="px-3 py-2.5 text-right font-medium">Hits</th>
                    <th className="px-5 py-2.5 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {rows.map((i) => (
                    <tr
                      key={`${i.type}${i.value}`}
                      className="border-b border-border/50 last:border-0 hover:bg-accent/40"
                    >
                      <td className="px-5 py-3">
                        <span
                          className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${typeStyles[i.type] ?? ""}`}
                        >
                          {i.type}
                        </span>
                      </td>
                      <td
                        className="max-w-0 truncate px-3 py-3 text-terminal"
                        style={{ maxWidth: 360 }}
                        title={i.value}
                      >
                        {i.type === "sha256" ? (
                          <Link to="/malware" search={{ sha: i.value }} className="hover:underline">
                            {i.value}
                          </Link>
                        ) : (
                          i.value
                        )}
                      </td>
                      <td
                        className="max-w-0 truncate px-3 py-3 font-sans text-muted-foreground"
                        style={{ maxWidth: 280 }}
                        title={i.context ?? ""}
                      >
                        {i.context ?? "—"}
                      </td>
                      <td className="px-3 py-3">
                        {i.source_ip ? (
                          <Link
                            to="/attackers/$ip"
                            params={{ ip: i.source_ip }}
                            className="text-primary hover:underline"
                          >
                            {i.source_ip}
                          </Link>
                        ) : (
                          "—"
                        )}
                      </td>
                      <td className="px-3 py-3">
                        {i.protocol ? <ProtocolTag protocol={i.protocol} /> : "—"}
                      </td>
                      <td className="px-3 py-3 text-right tabular-nums">{i.hits}</td>
                      <td className="whitespace-nowrap px-5 py-3 text-muted-foreground">
                        {timeAgo(i.last_seen)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </QueryState>
      </Panel>

      <Panel
        title="MITRE ATT&CK Coverage"
        subtitle="Techniques observed (Enterprise T1xxx · ICS T0xxx), ranked by detections"
        className="mt-4"
      >
        <QueryState q={mitre} empty="No techniques observed yet.">
          {(rows) => {
            const max = rows[0]?.detections ?? 1;
            return (
              <div className="space-y-2">
                {rows.map((m) => (
                  <div key={m.technique} className="flex items-center gap-3">
                    <a
                      href={`https://attack.mitre.org/techniques/${m.technique.replace(".", "/")}/`}
                      target="_blank"
                      rel="noreferrer"
                      className="w-20 shrink-0 font-mono text-xs text-primary hover:underline"
                    >
                      {m.technique}
                    </a>
                    <div className="h-6 flex-1 overflow-hidden rounded-md border border-border/60 bg-background/40">
                      <div
                        className="flex h-full items-center bg-primary/20 pl-2"
                        style={{ width: `${Math.max(8, (m.detections / max) * 100)}%` }}
                      >
                        <span className="whitespace-nowrap text-[11px]">{m.name}</span>
                      </div>
                    </div>
                    <span className="w-28 shrink-0 text-right font-mono text-[11px] text-muted-foreground">
                      {m.detections} det · {m.ips} IPs
                    </span>
                  </div>
                ))}
              </div>
            );
          }}
        </QueryState>
      </Panel>
    </div>
  );
}
