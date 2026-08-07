// Concrete, entity-type-specific next steps -- computed server-side by
// server/investigation/actionability.js as the final "Actionable Guidance"
// stage of the shared platform-wide intelligence assessment pipeline (see
// server/investigation/verdictEngine.js for the stages before it), from the
// same evidence/verdict this search already resolved. Replaces the previous
// frontend-only src/lib/recommendedActions.ts, which computed its own
// separate, verdict-shaped-differently recommendations client-side --
// keeping one source of truth for "what should each team do" instead of two
// independently-drifting engines.
import { ShieldCheck, Wrench, Telescope, Siren, Crosshair, ShieldAlert } from "lucide-react";
import { Section } from "../reportPrimitives";
import type { ActionabilityGuidance, ActionabilityAction } from "@/types/threat-intel";

const ROLE_META: Record<ActionabilityAction["role"], { label: string; icon: typeof ShieldCheck }> = {
  socAnalyst: { label: "SOC Analyst", icon: ShieldCheck },
  threatHunter: { label: "Threat Hunter", icon: Crosshair },
  detectionEngineer: { label: "Detection Engineering", icon: Wrench },
  incidentResponse: { label: "Incident Response", icon: Siren },
  threatIntel: { label: "Threat Intelligence", icon: Telescope },
  vulnerabilityManagement: { label: "Vulnerability Management", icon: ShieldAlert },
};
const ROLE_ORDER: Array<ActionabilityAction["role"]> = ["socAnalyst", "threatHunter", "detectionEngineer", "incidentResponse", "threatIntel", "vulnerabilityManagement"];

export function RecommendedActionsPanel({ guidance }: { guidance: ActionabilityGuidance }) {
  const visibleRoles = ROLE_ORDER.filter((role) => !guidance.notApplicable.includes(role));
  if (visibleRoles.length === 0) return null;

  return (
    <Section title="Recommended Actions">
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
