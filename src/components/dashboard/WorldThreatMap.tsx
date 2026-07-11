import { useMemo, useState } from "react";
import { ComposableMap, Geographies, Geography } from "react-simple-maps";
import { Globe2 } from "lucide-react";
import worldTopology from "world-atlas/countries-110m.json";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useGeoTargeting } from "@/hooks/useGeoTargeting";

interface WorldThreatMapProps {
  onSelectCountry: (countryCode: string) => void;
}

// Sequential, single-hue by magnitude (the same "cold tactics stay quiet"
// intensity ramp AttackTacticHeatmap.tsx already uses for the same reason:
// a choropleth is a magnitude-by-geography job, not an identity one, so one
// hue that gets more intense with count is the whole color story -- no
// categorical palette needed).
function fillForCount(count: number, maxCount: number) {
  if (count === 0 || maxCount === 0) return "rgba(109,91,255,0.08)";
  const intensity = count / maxCount;
  return `rgba(255, 41, 92, ${0.55 + intensity * 0.45})`;
}

/** Choropleth of ransomware-campaign country targeting -- see server/correlate.js#computeGeoTargeting. Countries matched to map shapes via numericId (ISO 3166-1 numeric, the same id world-atlas's topojson uses). Clicking a country jumps to Ransomware Data filtered by it. */
export function WorldThreatMap({ onSelectCountry }: WorldThreatMapProps) {
  const { data, isLoading, isError } = useGeoTargeting();
  const [hovered, setHovered] = useState<string | null>(null);

  const countByNumericId = useMemo(() => {
    const map = new Map<string, { count: number; countryCode: string }>();
    for (const c of data?.countries ?? []) map.set(String(Number(c.numericId)), { count: c.count, countryCode: c.countryCode });
    return map;
  }, [data]);

  const maxCount = useMemo(() => Math.max(0, ...(data?.countries ?? []).map((c) => c.count)), [data]);
  const topCountries = (data?.countries ?? []).slice(0, 5);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Globe2 className="h-4 w-4 text-primary" />
          Geographic Distribution
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <Skeleton className="h-56 w-full" />
        ) : isError || !data ? (
          <ErrorState message="Geographic Distribution is unavailable right now." />
        ) : data.countries.length === 0 ? (
          <EmptyState message="No geo-tagged ransomware campaigns yet." />
        ) : (
          <>
            <div className="h-56 w-full overflow-hidden rounded-lg">
              <ComposableMap projection="geoEqualEarth" width={800} height={400} style={{ width: "100%", height: "100%" }}>
                <Geographies geography={worldTopology}>
                  {({ geographies }) =>
                    geographies.map((geo) => {
                      const match = countByNumericId.get(String(Number(geo.id)));
                      const count = match?.count ?? 0;
                      return (
                        <Geography
                          key={geo.rsmKey}
                          geography={geo}
                          onClick={() => match && onSelectCountry(match.countryCode)}
                          onMouseEnter={() => setHovered(match ? `${geo.properties.name}: ${count} campaign${count === 1 ? "" : "s"}` : geo.properties.name)}
                          onMouseLeave={() => setHovered(null)}
                          style={{
                            default: { fill: fillForCount(count, maxCount), stroke: "rgba(255,255,255,0.14)", strokeWidth: 0.5, outline: "none" },
                            hover: {
                              fill: match ? "#ff5c7f" : "rgba(109,91,255,0.18)",
                              stroke: "rgba(255,255,255,0.25)",
                              strokeWidth: 0.5,
                              outline: "none",
                              cursor: match ? "pointer" : "default",
                            },
                            pressed: { fill: "#ff2b5c", stroke: "rgba(255,255,255,0.25)", strokeWidth: 0.5, outline: "none" },
                          }}
                        />
                      );
                    })
                  }
                </Geographies>
              </ComposableMap>
            </div>
            <p className="mt-1.5 h-4 text-xs text-muted">{hovered}</p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {topCountries.map((c) => (
                <button
                  key={c.countryCode}
                  type="button"
                  onClick={() => onSelectCountry(c.countryCode)}
                  className="rounded-full border border-white/10 bg-white/[0.03] px-2 py-0.5 text-xs transition-colors hover:border-primary/40"
                >
                  {c.countryCode} <span className="text-muted">({c.count})</span>
                </button>
              ))}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
