// Malware Family / Threat Actor / Campaign / Ransomware Group
// Indicator-Specific Intelligence -- the entity-centric correlation dossier
// (see server/investigation/entityCorrelation.js#buildEntityDossier). Used
// for BOTH `name`-type searches (malware/actor/campaign name) and
// `ransomwareGroup`-type searches (a real ransomware.live/RansomWatch/
// RansomLook group name) -- both now assemble the exact same dossier shape,
// so "Clop" gets the same correlation depth as "LockBit"/"APT29" instead of
// the old two-disjoint-paths gap. Answers "what does this platform know
// about this entity, how is it connected, what campaigns/CVEs/infrastructure
// are associated, who has it targeted, what should I investigate next" --
// not just "is this entity malicious."
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Section } from "../reportPrimitives";
import type {
  MalwareIntelligenceEntity,
  ThreatActorIntelligenceEntity,
  CampaignIntelligenceEntity,
  ThreatActor,
  DetectionRuleRef,
  EntityDossier,
  CampaignHistoryEntry,
  AssociatedCveEntry,
  IocInventoryBucket,
  VictimTargetingSummary,
  RelationshipConfidenceLabel,
} from "@/types/threat-intel";

function typeLabel(type: ThreatActor["type"]): string {
  if (type === "ransomware") return "Ransomware group";
  if (type === "otx-tagged") return "OTX-tagged actor";
  return `${type} (news-tracked)`;
}

// DIRECT/STRONG/MODERATE/WEAK/CONTEXTUAL -- the same 5-value confidence
// scale server/investigation/relationshipConfidenceLabel.js derives for
// graph edges, reused here for CVE relationships (which aren't graph edges)
// so the analyst sees one consistent vocabulary everywhere on this page.
const CONFIDENCE_BADGE: Record<RelationshipConfidenceLabel, "critical" | "high" | "medium" | "low" | "cyan"> = {
  DIRECT: "critical",
  STRONG: "high",
  MODERATE: "medium",
  WEAK: "low",
  CONTEXTUAL: "cyan",
};

interface EntityModuleData {
  // `name`-type fields
  malware?: Array<{ entity: MalwareIntelligenceEntity; detectionRules: DetectionRuleRef[] }>;
  actors?: ThreatActorIntelligenceEntity[];
  campaigns?: CampaignIntelligenceEntity[];
  ransomwareOnly?: ThreatActor[];
  total?: number;
  // `ransomwareGroup`-type fields
  group?: string;
  victimCount?: number;
  victims?: Array<{ group: string; victim: string; sector: string; country: string; discoveredDate: string; sourceUrl: string | null }>;
  note?: string;
  // Shared by both -- the entity-centric correlation dossier.
  dossier?: EntityDossier;
}

function EntityOverview({ dossier }: { dossier: EntityDossier }) {
  const counts: Array<[string, number]> = [
    ["Malware Families", dossier.malwareFamilyCount],
    ["Campaigns", dossier.campaignCount],
    ["CVEs", dossier.cveCount],
    ["IOCs", dossier.iocCount],
    ["Victims", dossier.victimCount],
    ["Threat Reports", dossier.threatReportCount],
  ];
  return (
    <Section title="Entity Overview">
      <div className="space-y-2.5">
        {dossier.aliases.length > 0 && (
          <p className="text-xs text-muted">
            Known aliases: <span className="font-mono text-foreground">{dossier.aliases.join(", ")}</span>
          </p>
        )}
        {dossier.sourceType !== "verified-profile" && (
          <p className="rounded-lg border border-medium/20 bg-medium/[0.05] p-2 text-xs text-medium">
            {dossier.sourceType === "ransomware-tracker-only"
              ? "Matched a real ransomware-tracker group name with disclosed victims, but no verified malware/actor/campaign profile exists in this platform's own entity stores yet."
              : "No verified profile or victim-tracker match found for this name -- limited correlation available below."}
          </p>
        )}
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
          {counts.map(([label, count]) => (
            <div key={label} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5">
              <p className="text-[10px] uppercase tracking-wide text-muted">{label}</p>
              <p className="mt-0.5 text-sm font-semibold text-foreground">{count}</p>
            </div>
          ))}
        </div>
        {dossier.victimsTargeting.byIndustry.length > 0 && (
          <p className="text-xs text-muted">
            Top targeted industries: <span className="text-foreground">{dossier.victimsTargeting.byIndustry.slice(0, 5).map((i) => `${i.industry} (${i.count})`).join(", ")}</span>
          </p>
        )}
        {dossier.victimsTargeting.byCountry.length > 0 && (
          <p className="text-xs text-muted">
            Top targeted countries: <span className="text-foreground">{dossier.victimsTargeting.byCountry.slice(0, 5).map((c) => `${c.country} (${c.count})`).join(", ")}</span>
          </p>
        )}
      </div>
    </Section>
  );
}

function CampaignHistorySection({ campaigns, onOpenCampaign }: { campaigns: CampaignHistoryEntry[]; onOpenCampaign: () => void }) {
  const groups: Array<[string, CampaignHistoryEntry[]]> = [
    ["Current / Recent", campaigns.filter((c) => c.bucket === "current")],
    ["Historical", campaigns.filter((c) => c.bucket === "historical")],
    ["Undated", campaigns.filter((c) => c.bucket === "undated")],
  ].filter(([, items]) => items.length > 0) as Array<[string, CampaignHistoryEntry[]]>;

  return (
    <Section title="Campaign History">
      <div className="space-y-3">
        {groups.map(([label, items]) => (
          <div key={label}>
            <p className="mb-1.5 text-xs font-semibold text-foreground">{label}</p>
            <div className="space-y-2">
              {items.map((c) => (
                <button
                  key={c.name}
                  type="button"
                  onClick={onOpenCampaign}
                  className="block w-full rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-left text-xs hover:border-primary/40"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-mono font-semibold text-foreground">{c.name}</span>
                    <span className="text-muted">
                      {c.firstSeen ? new Date(c.firstSeen).toLocaleDateString() : "date unknown"}
                      {c.lastSeen && c.lastSeen !== c.firstSeen ? ` – ${new Date(c.lastSeen).toLocaleDateString()}` : ""}
                    </span>
                  </div>
                  <div className="mt-1.5 space-y-1 text-muted">
                    {c.targetedIndustries.length > 0 && (
                      <p>
                        Industries: <span className="text-foreground">{c.targetedIndustries.slice(0, 5).join(", ")}</span>
                      </p>
                    )}
                    {c.targetedCountries.length > 0 && (
                      <p>
                        Countries: <span className="text-foreground">{c.targetedCountries.slice(0, 5).join(", ")}</span>
                      </p>
                    )}
                    {c.initialAccessTechniques.length > 0 && (
                      <p>
                        Initial access: <span className="font-mono text-foreground">{c.initialAccessTechniques.map((t) => `${t.id} ${t.name}`).join(", ")}</span>
                      </p>
                    )}
                    {c.associatedMalware.length > 0 && (
                      <p>
                        Malware: <span className="text-foreground">{c.associatedMalware.join(", ")}</span>
                      </p>
                    )}
                    {c.cveIds.length > 0 && (
                      <p>
                        CVEs: <span className="font-mono text-foreground">{c.cveIds.join(", ")}</span>
                      </p>
                    )}
                    <p>
                      Victims: <span className="text-foreground">{c.victimCount}</span> · IOCs: <span className="text-foreground">{c.iocCount}</span>
                    </p>
                    {c.sources.length > 0 && (
                      <p>
                        Source: <span className="text-foreground">{c.sources.join(", ")}</span>
                      </p>
                    )}
                  </div>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Section>
  );
}

function AssociatedCvesSection({ cves }: { cves: AssociatedCveEntry[] }) {
  return (
    <Section title="Associated CVEs">
      <div className="space-y-2">
        {cves.map((c) => (
          <div key={c.cveId} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono font-semibold text-foreground">{c.cveId}</span>
              <Badge variant={CONFIDENCE_BADGE[c.confidenceLabel]}>{c.confidenceLabel}</Badge>
            </div>
            {c.exploitationContext && <p className="mt-1 text-muted">{c.exploitationContext}</p>}
            {c.campaignRelationship.length > 0 && (
              <p className="mt-1 text-muted">
                Campaign(s): <span className="text-foreground">{c.campaignRelationship.join(", ")}</span>
              </p>
            )}
            <p className="mt-1 text-muted">{c.source}</p>
          </div>
        ))}
      </div>
    </Section>
  );
}

/** The user's explicit "Clop: IPs 34, Domains 72, ..." requirement -- real counts per type, click a count to see the actual indicators, click an indicator to pivot into its own investigation (preserving the relationship chain: entity → malware family → IOC). */
function IocInventorySection({ buckets, onPivotToIndicator }: { buckets: IocInventoryBucket[]; onPivotToIndicator: (value: string) => void }) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const activeBucket = buckets.find((b) => b.indicatorType === expanded);
  return (
    <Section title="Associated Infrastructure — IOC Inventory">
      <div className="flex flex-wrap gap-2">
        {buckets.map((b) => (
          <button
            key={b.indicatorType}
            type="button"
            onClick={() => setExpanded(expanded === b.indicatorType ? null : b.indicatorType)}
            className={`rounded-lg border px-3 py-1.5 text-xs hover:border-primary/40 ${expanded === b.indicatorType ? "border-primary/40 bg-primary/[0.06]" : "border-white/10 bg-white/[0.03]"}`}
          >
            <span className="font-semibold uppercase text-foreground">{b.indicatorType}</span>: <span className="font-mono text-primary">{b.count}</span>
          </button>
        ))}
      </div>
      {activeBucket && (
        <div className="mt-2 grid grid-cols-1 gap-1.5 sm:grid-cols-2">
          {activeBucket.items.map((item) => (
            <button
              key={item.indicator}
              type="button"
              onClick={() => onPivotToIndicator(item.indicator)}
              title={`Via malware family: ${item.source}`}
              className="rounded-lg border border-primary/20 bg-primary/[0.03] px-2 py-1 text-left font-mono text-[11px] text-primary hover:border-primary/50"
            >
              {item.indicator} →
            </button>
          ))}
          {activeBucket.count > activeBucket.items.length && (
            <p className="text-[11px] text-muted">+{activeBucket.count - activeBucket.items.length} more not shown.</p>
          )}
        </div>
      )}
    </Section>
  );
}

function AttackTechniquesSection({ techniques }: { techniques: EntityDossier["attackTechniques"] }) {
  return (
    <Section title="ATT&amp;CK Techniques">
      <div className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
        {techniques.slice(0, 30).map((t) => (
          <div key={t.id} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2 text-xs">
            <span className="font-mono font-semibold text-foreground">{t.id}</span> <span className="text-foreground">{t.name}</span>
            {t.tactic && <span className="text-muted"> ({t.tactic})</span>}
            <p className="mt-0.5 text-muted">{t.observedVia}</p>
          </div>
        ))}
      </div>
      {techniques.length > 30 && <p className="mt-1 text-xs text-muted">+{techniques.length - 30} more.</p>}
    </Section>
  );
}

function VictimsTargetingSection({ summary }: { summary: VictimTargetingSummary }) {
  return (
    <Section title="Victims / Targeting">
      <div className="space-y-2 text-xs">
        <p className="text-foreground">{summary.totalVictims} total disclosed/tracked victim(s).</p>
        {summary.byIndustry.length > 0 && (
          <div>
            <p className="mb-1 font-semibold text-foreground">By Industry</p>
            <div className="flex flex-wrap gap-1.5">
              {summary.byIndustry.slice(0, 10).map((i) => (
                <Badge key={i.industry} variant="muted">
                  {i.industry} ({i.count})
                </Badge>
              ))}
            </div>
          </div>
        )}
        {summary.byCountry.length > 0 && (
          <div>
            <p className="mb-1 font-semibold text-foreground">By Country</p>
            <div className="flex flex-wrap gap-1.5">
              {summary.byCountry.slice(0, 10).map((c) => (
                <Badge key={c.country} variant="muted">
                  {c.country} ({c.count})
                </Badge>
              ))}
            </div>
          </div>
        )}
        {summary.sample.length > 0 && (
          <div>
            <p className="mb-1 font-semibold text-foreground">Sample Victims</p>
            <ul className="space-y-0.5 text-muted">
              {summary.sample.slice(0, 10).map((v, i) => (
                <li key={i}>
                  {v.victim}
                  {v.sector ? ` — ${v.sector}` : ""}
                  {v.country ? ` (${v.country})` : ""}
                  {v.discoveredDate ? `, ${new Date(v.discoveredDate).toLocaleDateString()}` : ""} <span className="italic">({v.source})</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Section>
  );
}

export function EntityIntelligenceSection({
  data,
  onOpenMalware,
  onOpenActor,
  onOpenCampaign,
  onPivotToIndicator,
}: {
  data: EntityModuleData;
  onOpenMalware: (entity: MalwareIntelligenceEntity, detectionRules: DetectionRuleRef[]) => void;
  onOpenActor: (name: string) => void;
  onOpenCampaign: () => void;
  onPivotToIndicator: (value: string) => void;
}) {
  const d = data.dossier;
  const hasLegacyMatch = (data.total ?? 0) > 0 || (data.victimCount ?? 0) > 0;
  const hasDossierMatch = Boolean(d) && d!.malwareFamilyCount + d!.campaignCount + d!.cveCount + d!.iocCount + d!.victimCount + d!.threatReportCount + d!.attackTechniques.length + d!.aliases.length > 0;
  // No local "no match" message here -- the Search Coverage panel above
  // already reports this honestly alongside every other layer this search
  // checked (see server/investigation/coverage.js), so this section simply
  // renders nothing when nothing at all was found, instead of a second,
  // narrower "no results" message with no visibility into what else was
  // searched.
  if (!hasLegacyMatch && !hasDossierMatch) return null;

  return (
    <div className="space-y-4">
      {d && <EntityOverview dossier={d} />}
      {d && d.campaigns.length > 0 && <CampaignHistorySection campaigns={d.campaigns} onOpenCampaign={onOpenCampaign} />}
      {(data.malware?.length ?? 0) > 0 && (
        <Section title="Associated Malware">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {data.malware!.map(({ entity, detectionRules }) => (
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
      {d && d.associatedCves.length > 0 && <AssociatedCvesSection cves={d.associatedCves} />}
      {d && d.iocInventory.length > 0 && <IocInventorySection buckets={d.iocInventory} onPivotToIndicator={onPivotToIndicator} />}
      {d && d.attackTechniques.length > 0 && <AttackTechniquesSection techniques={d.attackTechniques} />}
      {d && d.victimsTargeting.totalVictims > 0 && <VictimsTargetingSection summary={d.victimsTargeting} />}
      {(data.actors?.length ?? 0) > 0 && (
        <Section title="Threat Actors">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {data.actors!.map((a) => (
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
      {(data.ransomwareOnly?.length ?? 0) > 0 && (
        <Section title="Ransomware / OTX-Tagged Groups (no news profile yet)">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {data.ransomwareOnly!.map((a) => (
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
    </div>
  );
}
