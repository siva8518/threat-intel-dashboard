// Malware Family / Threat Actor / Campaign Name Indicator-Specific
// Intelligence -- extends TriageConsole.tsx's NameMatchView with the
// detection-rule cross-reference server/investigation/entityModule.js adds.
import { Badge } from "@/components/ui/badge";
import { Section } from "../reportPrimitives";
import type { MalwareIntelligenceEntity, ThreatActorIntelligenceEntity, CampaignIntelligenceEntity, ThreatActor, DetectionRuleRef } from "@/types/threat-intel";

function typeLabel(type: ThreatActor["type"]): string {
  if (type === "ransomware") return "Ransomware group";
  if (type === "otx-tagged") return "OTX-tagged actor";
  return `${type} (news-tracked)`;
}

interface EntityModuleData {
  malware: Array<{ entity: MalwareIntelligenceEntity; detectionRules: DetectionRuleRef[] }>;
  actors: ThreatActorIntelligenceEntity[];
  campaigns: CampaignIntelligenceEntity[];
  ransomwareOnly: ThreatActor[];
  total: number;
}

export function EntityIntelligenceSection({
  query,
  data,
  onOpenMalware,
  onOpenActor,
  onOpenCampaign,
}: {
  query: string;
  data: EntityModuleData;
  onOpenMalware: (entity: MalwareIntelligenceEntity, detectionRules: DetectionRuleRef[]) => void;
  onOpenActor: (name: string) => void;
  onOpenCampaign: () => void;
}) {
  if (data.total === 0) {
    return <p className="text-sm text-muted">No malware family, threat actor, or campaign matches "{query}" in this platform's own tracked intelligence.</p>;
  }
  return (
    <div className="space-y-4">
      {data.malware.length > 0 && (
        <Section title="Malware Families">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {data.malware.map(({ entity, detectionRules }) => (
              <button
                key={entity.id}
                type="button"
                onClick={() => onOpenMalware(entity, detectionRules)}
                className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-left text-xs hover:border-primary/40"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-foreground">{entity.name}</span>
                  {entity.verified && <Badge variant="low">Confirmed</Badge>}
                </div>
                <p className="mt-1 text-muted">
                  {entity.iocSightings} live indicator(s) · {entity.mentionCount} article{entity.mentionCount === 1 ? "" : "s"}
                  {detectionRules.length > 0 ? ` · ${detectionRules.length} detection rule(s) available` : ""}
                </p>
              </button>
            ))}
          </div>
        </Section>
      )}
      {data.actors.length > 0 && (
        <Section title="Threat Actors">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {data.actors.map((a) => (
              <button key={a.id} type="button" onClick={() => onOpenActor(a.name)} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-left text-xs hover:border-primary/40">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-foreground">{a.name}</span>
                  <Badge variant="danger">{a.type}</Badge>
                </div>
                <p className="mt-1 text-muted">
                  {a.targetedIndustries.slice(0, 3).join(", ") || "Targeted industries not reported"} · {a.mentionCount} article{a.mentionCount === 1 ? "" : "s"}
                </p>
              </button>
            ))}
          </div>
        </Section>
      )}
      {data.ransomwareOnly.length > 0 && (
        <Section title="Ransomware / OTX-Tagged Groups (no news profile yet)">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {data.ransomwareOnly.map((a) => (
              <div key={a.name} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-left text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-foreground">{a.name}</span>
                  <Badge variant="danger">{typeLabel(a.type)}</Badge>
                </div>
                <p className="mt-1 text-muted">
                  {a.campaignCount} campaign{a.campaignCount === 1 ? "" : "s"} · last active {new Date(a.lastActivity).toLocaleDateString()}
                </p>
              </div>
            ))}
          </div>
        </Section>
      )}
      {data.campaigns.length > 0 && (
        <Section title="Campaigns">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {data.campaigns.map((c) => (
              <button key={c.id} type="button" onClick={onOpenCampaign} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-left text-xs hover:border-primary/40">
                <span className="font-mono font-semibold text-foreground">{c.name}</span>
                <p className="mt-1 text-muted">
                  {c.associatedActors.slice(0, 2).join(", ") || "No actor attribution yet"} · {c.mentionCount} article{c.mentionCount === 1 ? "" : "s"}
                </p>
              </button>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}
