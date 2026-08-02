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
import { computeEntityVerdict } from "./verdict.js";

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

  // Best single "primary" match for the Universal Overview verdict --
  // prefer whichever bucket returned a hit, malware first (most often what
  // a SOC analyst is pivoting from an IOC to check).
  let verdict = null;
  if (malware.length > 0) verdict = computeEntityVerdict("malware", malware[0]);
  else if (actors.some((a) => a.type === "Ransomware" || a.type === "APT")) verdict = computeEntityVerdict("actor", actors.find((a) => a.type === "Ransomware" || a.type === "APT"));
  else if (actors.length > 0) verdict = computeEntityVerdict("actor", actors[0]);
  else if (campaigns.length > 0) verdict = computeEntityVerdict("campaign", campaigns[0]);

  return { malware: malwareWithRules, actors, campaigns, ransomwareOnly, total, verdict };
}
