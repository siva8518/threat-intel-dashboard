// Instant, deterministic per-team next steps -- see src/lib/recommendedActions.ts
// for why this exists alongside (not instead of) the LLM-generated
// AiInvestigationReport.operationalGuidance: that panel is real but
// on-demand and can take up to a minute, so it can't be the answer an
// analyst sees the moment a search resolves.
import { ShieldCheck, Wrench, Telescope, Siren } from "lucide-react";
import { Section } from "../reportPrimitives";
import type { RecommendedActions } from "@/lib/recommendedActions";

const TEAMS: Array<{ key: keyof RecommendedActions; label: string; icon: typeof ShieldCheck }> = [
  { key: "soc", label: "SOC Analyst", icon: ShieldCheck },
  { key: "detectionEngineering", label: "Detection Engineering", icon: Wrench },
  { key: "threatIntelligence", label: "Threat Intelligence", icon: Telescope },
  { key: "incidentResponse", label: "Incident Response", icon: Siren },
];

export function RecommendedActionsPanel({ actions }: { actions: RecommendedActions }) {
  return (
    <Section title="Recommended Actions">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {TEAMS.map(({ key, label, icon: Icon }) => (
          <div key={key} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
            <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold text-foreground">
              <Icon className="h-3.5 w-3.5 text-primary" />
              {label}
            </div>
            <ul className="space-y-1.5 text-xs text-muted">
              {actions[key].map((line, i) => (
                <li key={i} className="text-foreground/90">
                  {line}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </Section>
  );
}
