// MITRE ATT&CK techniques grouped by tactic, behind a tactic breadcrumb/tab
// bar -- a full 14-15-tactic flat list (every tactic's techniques stacked
// vertically, one after another) was forcing a long scroll for any entity
// with broad technique coverage. Clicking a tactic swaps which one's
// techniques render below, so the page only ever shows one tactic's worth
// at a time. Shared by EntitySections.tsx's "MITRE ATT&CK Activity" section
// and InvestigationGraph.tsx's node detail panel so both stay in sync
// instead of maintaining two copies of the same grouping/rendering logic.
import { useState } from "react";
import { groupByTactic, type AttackTechniqueSummary } from "@/investigation/attackTactics";
import { cn } from "@/lib/utils";

type Technique = AttackTechniqueSummary & { observedVia?: string };

export function AttackTechniquesByTactic({ techniques, compact = false }: { techniques: Technique[]; compact?: boolean }) {
  const groups = groupByTactic(techniques);
  const [selected, setSelected] = useState<string | null>(null);
  if (groups.length === 0) return null;
  const active = groups.find((g) => g.tactic === selected) ?? groups[0];

  return (
    <div className={compact ? "space-y-2" : "space-y-2.5"}>
      <div className="flex flex-wrap items-center gap-1 border-b border-white/[0.06] pb-2">
        {groups.map((g, i) => (
          <span key={g.tactic} className="flex items-center gap-1">
            {i > 0 && <span className="text-[10px] text-muted">/</span>}
            <button
              type="button"
              onClick={() => setSelected(g.tactic)}
              className={cn(
                "rounded px-1.5 py-0.5 text-[11px] font-medium transition-colors",
                g.tactic === active.tactic ? "bg-primary/10 text-primary" : "text-muted hover:text-foreground",
              )}
            >
              {g.label} <span className="opacity-70">({g.items.length})</span>
            </button>
          </span>
        ))}
      </div>
      <div className={compact ? "flex flex-wrap gap-1" : "grid grid-cols-1 gap-1.5 sm:grid-cols-2"}>
        {active.items.map((t) =>
          compact ? (
            <span key={t.id} title={t.name} className="rounded border border-white/[0.08] bg-white/[0.03] px-1.5 py-0.5 font-mono text-[10px] text-foreground">
              {t.id}
            </span>
          ) : (
            <div key={t.id} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2 text-xs">
              <span className="font-mono font-semibold text-foreground">{t.id}</span> <span className="text-foreground">{t.name}</span>
              {t.observedVia && <p className="mt-0.5 text-muted">{t.observedVia}</p>}
            </div>
          ),
        )}
      </div>
    </div>
  );
}
