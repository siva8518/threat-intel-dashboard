import { useState } from "react";
import { ExternalLink, Flame } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "./ErrorState";
import { useAttackTacticHeatmap } from "@/hooks/useAttackTacticHeatmap";
import type { AttackTacticHeatmapCell } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

// Heat intensity uses the same "critical" red the rest of the app already
// uses for severity -- a cell's background opacity scales with its
// intensity (0-1, relative to the hottest tactic today), so cold tactics
// stay visually quiet instead of competing for attention.
function cellStyle(intensity: number) {
  if (intensity === 0) return {};
  return { backgroundColor: `rgba(251, 63, 94, ${0.1 + intensity * 0.55})` };
}

function TacticCell({ cell, selected, onClick }: { cell: AttackTacticHeatmapCell; selected: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={cell.total === 0}
      style={cellStyle(cell.intensity)}
      className={cn(
        "flex flex-col items-start gap-1 rounded-lg border p-2.5 text-left transition-colors",
        cell.total === 0 ? "cursor-default border-white/[0.06] bg-white/[0.02] opacity-50" : "border-critical/20 hover:border-critical/50",
        selected && "border-critical ring-1 ring-critical",
      )}
    >
      <span className="text-[11px] font-semibold capitalize text-foreground">{cell.tactic}</span>
      <span className="text-lg font-bold tabular-nums text-foreground">{cell.total}</span>
    </button>
  );
}

/**
 * A per-tactic (kill-chain stage) view of the same technique-frequency data
 * behind the "ATT&CK Techniques Observed" table below -- see
 * server/correlate.js#computeAttackTacticHeatmap for why this needs its own
 * query instead of reusing that table's (top-15-capped) data.
 */
export function AttackTacticHeatmap() {
  const { data, isLoading, isError, error } = useAttackTacticHeatmap();
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);

  const selected = data?.find((c) => c.tactic === selectedTactic) ?? null;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <Flame className="h-4 w-4 text-primary" />
          MITRE ATT&amp;CK Tactic Heat Map{" "}
          <span
            className="text-muted"
            title="Derived from a curated malware-to-technique map plus techniques automatically extracted from news article text -- not a live telemetry feed"
          >
            (best-effort, see tooltip)
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {isLoading ? (
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-5">
            {Array.from({ length: 15 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={(error as Error).message} />
        ) : (
          <>
            <div className="grid grid-cols-3 gap-2 sm:grid-cols-5">
              {(data ?? []).map((cell) => (
                <TacticCell
                  key={cell.tactic}
                  cell={cell}
                  selected={selectedTactic === cell.tactic}
                  onClick={() => setSelectedTactic(selectedTactic === cell.tactic ? null : cell.tactic)}
                />
              ))}
            </div>

            {selected && selected.techniques.length > 0 && (
              <div className="rounded-lg border border-white/10 bg-white/[0.02] p-3">
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted capitalize">
                  Top techniques &middot; {selected.tactic}
                </p>
                <ul className="space-y-1.5">
                  {selected.techniques.map((t) => (
                    <li key={t.id} className="flex items-center justify-between gap-2 text-xs">
                      <a href={t.url} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-primary hover:underline">
                        <span className="font-mono">{t.id}</span> {t.name}
                        <ExternalLink className="h-3 w-3 shrink-0" />
                      </a>
                      <span className="shrink-0 tabular-nums text-muted">{t.count}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
