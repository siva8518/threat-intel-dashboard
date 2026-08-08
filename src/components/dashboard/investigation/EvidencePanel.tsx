// The ONE place raw, per-source evidence renders -- see
// server/investigation/evidence.js#buildEvidenceCards for how each card was
// built. Every QUERIED source gets its own card, always, including an
// explicit "No Finding" card for a source that returned a successful lookup
// but reported no notable signal -- a silent source is never compressed into
// another source's sentence and never silently read as "clean". "Should I
// Care?" below never restates these individual findings; it only
// synthesizes what the combined picture means.
import { Section } from "../reportPrimitives";
import { Badge } from "@/components/ui/badge";
import type { EvidenceReconciliation, EvidenceCard } from "@/types/threat-intel";

type Visual = { variant: "critical" | "high" | "medium" | "low" | "cyan" | "muted"; label: string; dot: string };

// Color coding is derived from polarity + level TOGETHER, not either alone
// -- this is what keeps a strong clean/benign finding from ever reading as
// "risk" and keeps pure ownership/infrastructure context (ASN, RDAP, crt.sh,
// CVSS/EPSS) visually distinct (blue) from an actual clean verdict (green)
// or an actual malicious one (red).
function cardVisual(card: EvidenceCard): Visual {
  if (card.level === "UNKNOWN") return { variant: "muted", label: "No Finding", dot: "bg-white/25" };
  if (card.level === "CONTEXT") return { variant: "cyan", label: "Infrastructure Context", dot: "bg-accent-cyan" };
  if (card.polarity === "benign") return { variant: "low", label: "Clean / Benign Signal", dot: "bg-low" };
  if (card.polarity === "malicious") return card.level === "HIGH" ? { variant: "critical", label: "Malicious", dot: "bg-critical" } : { variant: "high", label: "Likely Malicious", dot: "bg-high" };
  if (card.polarity === "suspicious") return { variant: "medium", label: "Suspicious", dot: "bg-medium" };
  return { variant: "muted", label: "Neutral", dot: "bg-white/25" };
}

export function EvidencePanel({ evidence }: { evidence: EvidenceReconciliation }) {
  if (evidence.cards.length === 0) return null;

  const withFindings = evidence.cards.filter((c) => c.level !== "UNKNOWN").length;
  const silent = evidence.cards.length - withFindings;

  return (
    <Section title="Intelligence Evidence -- Source by Source">
      <p className="mb-3 text-xs text-muted">
        {evidence.cards.length} source(s) queried -- {withFindings} with a finding, {silent} with no finding
        {evidence.independentSourceCount < evidence.sourceCount ? `. ${evidence.independentSourceCount} independent source famil${evidence.independentSourceCount === 1 ? "y" : "ies"} behind ${evidence.sourceCount} finding(s) -- some findings share an underlying source, not independent confirmation.` : "."}
        {evidence.hasConflict && " Sources disagree on this indicator -- see the conflicting findings below and the Combined Intelligence Assessment for how that's weighed."}
      </p>
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
        {evidence.cards.map((card, i) => {
          const visual = cardVisual(card);
          return (
            <div key={`${card.source}-${i}`} className="relative overflow-hidden rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5 pl-3">
              <span className={`absolute left-0 top-0 h-full w-1 ${visual.dot}`} />
              <div className="mb-1 flex flex-wrap items-center justify-between gap-1.5">
                <span className="text-xs font-semibold text-foreground">{card.source}</span>
                <Badge variant={visual.variant}>{visual.label}</Badge>
              </div>
              <p className="mb-1 text-[10px] font-semibold uppercase tracking-wide text-muted">{card.evidenceType}</p>
              <p className={"text-xs " + (card.level === "UNKNOWN" ? "italic text-muted" : "text-foreground")}>{card.finding}</p>
              {card.reason && <p className="mt-1 text-[11px] text-muted">{card.reason}</p>}
              {card.lastSeen && <p className="mt-1 text-[10px] text-muted">Last seen: {new Date(card.lastSeen).toLocaleString()}</p>}
            </div>
          );
        })}
      </div>
    </Section>
  );
}
