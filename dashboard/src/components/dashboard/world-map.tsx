// Offline attack-origin map (scope M5 "Geographic Visualization … heatmap overlays").
// Rendered with d3-geo from the bundled Natural-Earth 110m atlas, so it works on an
// isolated honeynet with no tile server and under a strict Content-Security-Policy.
import { useMemo, useState } from "react";
import { geoNaturalEarth1, geoPath, geoGraticule10 } from "d3-geo";
import { feature } from "topojson-client";
import type { FeatureCollection, Geometry } from "geojson";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import type { MapPoint } from "@/lib/api";
import { list } from "@/lib/api";

const W = 960;
const H = 470;

const THREAT_COLOR: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

const topo = world as unknown as Topology<{ countries: GeometryCollection }>;
const land = feature(topo, topo.objects.countries) as unknown as FeatureCollection<Geometry>;

export function WorldMap({ points }: { points: MapPoint[] }) {
  const [hover, setHover] = useState<MapPoint | null>(null);
  const { path, project, grid } = useMemo(() => {
    const projection = geoNaturalEarth1().fitExtent(
      [
        [4, 4],
        [W - 4, H - 4],
      ],
      { type: "Sphere" },
    );
    return { path: geoPath(projection), project: projection, grid: geoGraticule10() };
  }, []);

  const max = Math.max(1, ...points.map((p) => p.events || 0));
  const r = (n: number) => 3 + 11 * Math.sqrt((n || 0) / max);
  const placed = points
    .map((p) => ({ p, xy: project([p.lon, p.lat]) }))
    .filter((x): x is { p: MapPoint; xy: [number, number] } => !!x.xy);

  return (
    <div className="relative">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full"
        role="img"
        aria-label="Attack origin map"
      >
        <defs>
          <radialGradient id="heat">
            <stop offset="0%" stopColor="var(--sev-critical)" stopOpacity="0.45" />
            <stop offset="60%" stopColor="var(--sev-high)" stopOpacity="0.12" />
            <stop offset="100%" stopColor="var(--sev-high)" stopOpacity="0" />
          </radialGradient>
        </defs>
        <path d={path({ type: "Sphere" }) ?? ""} fill="var(--background)" stroke="var(--border)" />
        <path
          d={path(grid) ?? ""}
          fill="none"
          stroke="var(--border)"
          strokeOpacity={0.35}
          strokeWidth={0.5}
        />
        {land.features.map((f, i) => (
          <path
            key={i}
            d={path(f) ?? ""}
            fill="var(--secondary)"
            stroke="var(--border)"
            strokeWidth={0.5}
          />
        ))}
        {/* heat layer: wide soft blobs where attacks concentrate */}
        {placed.map(({ p, xy }) => (
          <circle key={`h-${p.ip}`} cx={xy[0]} cy={xy[1]} r={r(p.events) * 4} fill="url(#heat)" />
        ))}
        {placed.map(({ p, xy }) => (
          <g
            key={p.ip}
            onMouseEnter={() => setHover(p)}
            onMouseLeave={() => setHover(null)}
            className="cursor-pointer"
          >
            {p.threat_level === "CRITICAL" && (
              <circle
                cx={xy[0]}
                cy={xy[1]}
                r={r(p.events) + 4}
                fill="none"
                stroke={THREAT_COLOR["CRITICAL"]}
                strokeOpacity={0.6}
              >
                <animate
                  attributeName="r"
                  from={r(p.events)}
                  to={r(p.events) + 10}
                  dur="1.8s"
                  repeatCount="indefinite"
                />
                <animate
                  attributeName="stroke-opacity"
                  from="0.7"
                  to="0"
                  dur="1.8s"
                  repeatCount="indefinite"
                />
              </circle>
            )}
            <circle
              cx={xy[0]}
              cy={xy[1]}
              r={r(p.events)}
              fill={THREAT_COLOR[p.threat_level] ?? THREAT_COLOR["LOW"]}
              fillOpacity={0.85}
              stroke="var(--background)"
              strokeWidth={1}
            />
          </g>
        ))}
      </svg>
      {hover && (
        <div className="pointer-events-none absolute left-3 top-3 rounded-md border bg-popover px-3 py-2 font-mono text-[11px] shadow-lg">
          <p className="font-semibold">{hover.ip}</p>
          <p className="text-muted-foreground">
            {hover.city ? `${hover.city}, ` : ""}
            {hover.country ?? "unknown"}
            {hover.geo_source === "demo" ? " · DEMO location" : ""}
          </p>
          <p>
            {hover.events} events · {hover.threat_level} ({hover.threat_score}/100)
          </p>
          <p className="text-muted-foreground">{list(hover.protocols).join(", ")}</p>
        </div>
      )}
    </div>
  );
}
