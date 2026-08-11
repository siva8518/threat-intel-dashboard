// Concrete, entity-type-specific next steps -- computed server-side by
// server/investigation/actionability.js as the final "Actionable Guidance"
// stage of the shared platform-wide intelligence assessment pipeline (see
// server/investigation/verdictEngine.js for the stages before it), from the
// same evidence/verdict this search already resolved. Replaces the previous
// frontend-only src/lib/recommendedActions.ts, which computed its own
// separate, verdict-shaped-differently recommendations client-side --
// keeping one source of truth for "what should each team do" instead of two
// independently-drifting engines.
import { ShieldCheck, Wrench, Telescope, Siren, Crosshair, ShieldAlert, GitCompareArrows } from "lucide-react";
import { Section } from "../reportPrimitives";
import { Badge } from "@/components/ui/badge";
import type { ActionabilityGuidance, ActionabilityAction, ConflictingIntelligenceGuidance } from "@/types/threat-intel";

const ROLE_META: Record<ActionabilityAction["role"], { label: string; icon: typeof ShieldCheck }> = {
  socAnalyst: { label: "SOC Analyst", icon: ShieldCheck },
  threatHunter: { label: "Threat Hunter", icon: Crosshair },
  detectionEngineer: { label: "Detection Engineering", icon: Wrench },
  incidentResponse: { label: "Incident Response", icon: Siren },
  threatIntel: { label: "Threat Intelligence", icon: Telescope },
  vulnerabilityManagement: { label: "Vulnerability Management", icon: ShieldAlert },
};
const ROLE_ORDER: Array<ActionabilityAction["role"]> = ["socAnalyst", "threatHunter", "detectionEngineer", "incidentResponse", "threatIntel", "vulnerabilityManagement"];

function priorityVariant(priority: string): "critical" | "high" | "medium" | "low" {
  const p = priority.toLowerCase();
  if (p.includes("critical")) return "critical";
  if (p.includes("high")) return "high";
  if (p.includes("monitor")) return "low";
  return "medium";
}

/**
 * The specific fix for the reported "VirusTotal = malicious, MISP = benign,
 * therefore = monitor" flattening -- walks the analyst through Threat
 * Intelligence -> Conflicting Signals -> Environmental Evidence -> Analyst
 * Decision instead of collapsing a real disagreement into one generic
 * "add to watchlist" line. Every field is real, server-computed evidence
 * (server/investigation/actionability.js#conflictingIntelligenceGuidance),
 * never AI-authored.
 */
function ConflictingIntelligenceBanner({ guidance }: { guidance: ConflictingIntelligenceGuidance }) {
  return (
    <div className="mb-4 rounded-xl border border-amber-500/25 bg-amber-500/[0.04] p-4">
      <div className="mb-2 flex items-center gap-1.5">
        <GitCompareArrows className="h-4 w-4 text-amber-400" />
        <span className="text-sm font-semibold text-foreground">Assessment: {guidance.assessment}</span>
      </div>
      <p className="mb-1 text-xs text-foreground/90">{guidance.threatIntelligenceSummary}</p>
      <p className="mb-3 text-xs text-muted">{guidance.conflictingSignalNote}</p>

      <div className="mb-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
        {guidance.reasoningChain.map((stage, i) => (
          <div key={i} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5">
            <p className="mb-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted">
              {i + 1}. {stage.stage}
            </p>
            <p className="text-xs text-foreground/90">{stage.summary}</p>
          </div>
        ))}
      </div>

      <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted">Recommended SOC Actions</p>
      <ol className="mb-3 list-decimal space-y-1 pl-4 text-xs text-foreground/90">
        {guidance.recommendedActions.map((a, i) => (
          <li key={i}>{a}</li>
        ))}
      </ol>

      <p className="mb-1.5 text-[10px] font-semibold uppercase tracking-wide text-muted">Analyst Decision</p>
      <div className="mb-3 overflow-x-auto rounded-lg border border-white/[0.06]">
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-white/[0.06] text-muted">
              <th className="px-3 py-2 font-semibold uppercase tracking-wide">Finding</th>
              <th className="px-3 py-2 font-semibold uppercase tracking-wide">Priority</th>
            </tr>
          </thead>
          <tbody>
            {guidance.analystDecision.map((row, i) => (
              <tr key={i} className="border-b border-white/[0.04] last:border-0">
                <td className="px-3 py-2 text-foreground/90">{row.finding}</td>
                <td className="px-3 py-2">
                  <Badge variant={priorityVariant(row.priority)}>{row.priority}</Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <p className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5 text-xs text-muted">
        <span className="font-semibold text-foreground/90">Key Intelligence Note: </span>
        {guidance.keyIntelligenceNote}
      </p>
    </div>
  );
}

export function RecommendedActionsPanel({ guidance }: { guidance: ActionabilityGuidance }) {
  const visibleRoles = ROLE_ORDER.filter((role) => !guidance.notApplicable.includes(role));
  if (visibleRoles.length === 0 && !guidance.conflictingIntelligence) return null;

  return (
    <Section title="Recommended Actions">
      {guidance.conflictingIntelligence && <ConflictingIntelligenceBanner guidance={guidance.conflictingIntelligence} />}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {visibleRoles.map((role) => {
          const { label, icon: Icon } = ROLE_META[role];
          const actions = guidance.actions.filter((a) => a.role === role);
          return (
            <div key={role} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
              <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-foreground">
                <Icon className="h-3.5 w-3.5 text-primary" />
                {label}
              </div>
              {actions.length > 0 ? (
                <ul className="space-y-1.5 text-xs text-muted">
                  {actions.map((a, i) => (
                    <li key={i} className="text-foreground/90">
                      {a.action}
                      <span className="block text-[10px] text-muted">{a.rationale}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-muted">No specific action for this role on this indicator.</p>
              )}
            </div>
          );
        })}
      </div>
      {guidance.huntingQueries.length > 0 && <p className="mt-3 text-xs text-muted">{guidance.huntingQueries.length} prebuilt hunting quer{guidance.huntingQueries.length === 1 ? "y" : "ies"} available -- see Detection &amp; Hunting below.</p>}
    </Section>
  );
}
