// Malware Family / Threat Actor / Campaign Name investigation module -- a
// thin wrapper over entityCorrelation.js#buildEntityDossier, the shared
// entity-centric correlation engine both this module and
// ransomwareGroupModule.js call, so "Clop" (routed to that module) gets the
// exact same correlation depth as "LockBit"/"APT29" (routed here). Keeps
// this module's own historical return shape (`{malware, actors, campaigns,
// ransomwareOnly, total}`, each malware entry wrapped with its detection
// rules) so EntitySections.tsx's existing card grid keeps working, with the
// full dossier attached as `dossier` for the new rich entity-dossier UI.
import * as cache from "../cache.js";
import { detectionRulesFor } from "../correlate.js";
import { buildEntityDossier } from "./entityCorrelation.js";

export const type = "name";

export async function gather(value) {
  const dossier = await buildEntityDossier(value, { seedType: "name" });
  const { _matchedMalware: malware, _matchedActors: actors, _matchedCampaigns: campaigns, _ransomwareOnly: ransomwareOnly } = dossier;

  const ruleIndex = cache.getEntry("detection-rules").data?.index;
  const malwareWithRules = malware.map((m) => ({ entity: m, detectionRules: detectionRulesFor(m.name, ruleIndex) }));

  const total = malware.length + actors.length + campaigns.length + ransomwareOnly.length;

  // Preferred primary match order -- malware first, then a Ransomware/APT
  // actor, then any actor, then a campaign -- mirrors dossier.primaryEntity's
  // own precedence (entityCorrelation.js#pickPrimaryEntity) so this module's
  // legacy `actors[0]`/`campaigns[0]` readers (evidence.js/verdictEngine.js)
  // agree with the dossier.
  const primaryActor = actors.find((a) => a.type === "Ransomware" || a.type === "APT") ?? actors[0];
  const orderedActors = primaryActor ? [primaryActor, ...actors.filter((a) => a !== primaryActor)] : actors;

  return { malware: malwareWithRules, actors: orderedActors, campaigns, ransomwareOnly, total, dossier };
}
