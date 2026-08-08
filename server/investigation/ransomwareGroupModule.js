// Ransomware Group investigation module -- a search that resolves to a real
// ransomware.live/RansomWatch/RansomLook group name (see detect.js's
// ransomware-group check). Keeps its own real, type-specific victim-tracker
// lookup (the ground truth for "how many disclosed victims does the tracker
// have"), and ADDITIONALLY calls entityCorrelation.js#buildEntityDossier --
// the same shared correlation engine entityModule.js uses -- so "Clop" gets
// the exact same malware/actor/campaign/CVE/IOC/report correlation depth as
// a `name`-type search instead of the old `{group, victimCount, victims,
// crossReference}`-only shape. The real correlation (victims via the
// ransomware tracker directly, and everything else via the dossier) no
// longer depends solely on investigationGraph.js#gatherActor separately
// resolving the same name to an actor entity.
import { ransomwareCampaigns as getRansomwareCampaigns } from "../ransomwareCampaigns.js";
import { crossReferenceIndicator } from "./crossReference.js";
import { buildEntityDossier } from "./entityCorrelation.js";

export const type = "ransomwareGroup";

function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

export async function gather(value) {
  const target = norm(value);
  const victims = getRansomwareCampaigns().filter((c) => norm(c.group) === target);
  const crossReference = crossReferenceIndicator(value);
  const dossier = await buildEntityDossier(value, { seedType: "ransomwareGroup" });

  const note =
    victims.length > 0
      ? `Matched a real ransomware.live/RansomWatch/RansomLook group name with ${victims.length} disclosed victim(s) in this platform's data. See the Investigation Graph above for its full victim/malware/campaign relationships.`
      : "Matched a known ransomware group name, but this platform currently has no disclosed victim record for it.";

  return { group: value, victimCount: victims.length, victims: victims.slice(0, 20), crossReference, note, dossier };
}
