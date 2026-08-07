// Malware Family / Threat Actor / Campaign Name investigation module --
// extends TriageConsole.tsx's existing name-search logic (search all three
// entity stores by name/alias) with detection-rule cross-reference
// (SigmaHQ/YARA-Rules, same helper server/correlate.js#detectionRulesFor
// already uses elsewhere) and the ransomware/OTX-only actor bucket for
// groups tracked outside the news-derived ThreatActorIntelligence store.
import * as cache from "../cache.js";
import { detectionRulesFor, mergeThreatActors } from "../correlate.js";
import { ransomwareCampaigns as getRansomwareCampaigns } from "../ransomwareCampaigns.js";
import { searchEntitiesByName } from "./crossReference.js";

export const type = "name";

export async function gather(value) {
  const { malware, actors, campaigns } = searchEntitiesByName(value);

  const otxSignals = cache.getEntry("otx").data?.actorSignals ?? [];
  const merged = mergeThreatActors(getRansomwareCampaigns(), otxSignals, actors);
  const alreadyCovered = new Set(actors.map((a) => a.name.toLowerCase()));
  const q = value.toLowerCase();
  const ransomwareOnly = merged.filter((a) => a.name.toLowerCase().includes(q) && !alreadyCovered.has(a.name.toLowerCase())).slice(0, 10);

  const ruleIndex = cache.getEntry("detection-rules").data?.index;
  const malwareWithRules = malware.map((m) => ({ entity: m, detectionRules: detectionRulesFor(m.name, ruleIndex) }));

  const total = malware.length + actors.length + campaigns.length + ransomwareOnly.length;

  // Preferred primary match order -- malware first (most often what a SOC
  // analyst is pivoting from an IOC to check), then a Ransomware/APT actor,
  // then any actor, then a campaign. See server/investigation/evidence.js#nameEntityEvidence
  // and verdictEngine.js, which now read `actors[0]`/`campaigns[0]` directly
  // using this same precedence -- reorder here so both agree.
  const primaryActor = actors.find((a) => a.type === "Ransomware" || a.type === "APT") ?? actors[0];
  const orderedActors = primaryActor ? [primaryActor, ...actors.filter((a) => a !== primaryActor)] : actors;

  return { malware: malwareWithRules, actors: orderedActors, campaigns, ransomwareOnly, total };
}
