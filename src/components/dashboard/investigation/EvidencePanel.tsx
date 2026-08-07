// The ONE place raw, per-source, category-tagged evidence renders -- see
// server/investigation/evidence.js for how each item was classified.
// "Should I Care?" above only carries the verdict engine's own synthesized
// reasoning sentence, not a hand-picked evidence subset, so this panel is
// the single source for "which sources actually said what."
import { Section } from "../reportPrimitives";
import type { EvidenceReconciliation, EvidenceCategory } from "@/types/threat-intel";

const CATEGORY_LABEL: Record<EvidenceCategory, string> = {
  direct: "Direct",
  corroborating: "Corroborating",
  attribution: "Attribution",
  indirect: "Indirect",
  negative: "Negative (Clean/Benign Signal)",
  conflicting: "Conflicting",
  contextual: "Contextual (Not Evidence of Maliciousness)",
};

// Strongest/most decision-relevant categories first; contextual last since
// it never contributes to the verdict on its own (see evidence.js).
const CATEGORY_ORDER: EvidenceCategory[] = ["conflicting", "direct", "corroborating", "attribution", "indirect", "negative", "contextual"];

export function EvidencePanel({ evidence }: { evidence: EvidenceReconciliation }) {
  if (evidence.items.length === 0) return null;

  const groups = CATEGORY_ORDER.map((category) => [category, evidence.items.filter((i) => i.category === category)] as const).filter(([, items]) => items.length > 0);

  return (
    <Section title="Evidence">
      <p className="mb-3 text-xs text-muted">
        {evidence.sourceCount} evidence item(s) from {evidence.independentSourceCount} independent source(s)
        {evidence.hasConflict ? " -- includes conflicting evidence, see below." : "."}
      </p>
      <div className="space-y-3">
        {groups.map(([category, items]) => (
          <div key={category}>
            <div className={"mb-1 text-xs font-semibold " + (category === "conflicting" ? "text-accent-cyan" : "text-foreground")}>{CATEGORY_LABEL[category]}</div>
            <ul className="space-y-1">
              {items.map((item, i) => (
                <li key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2 text-xs text-foreground">
                  <span className="font-semibold">{item.source}: </span>
                  {item.claim}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Section>
  );
}
