// Ransomware Group investigation module -- a search that resolves to a real
// ransomware.live/RansomWatch/RansomLook group name (see detect.js's
// ransomware-group check). No separate live lookup here -- the real
// correlation (victims, associated malware/actors, campaigns) is computed by
// investigationGraph.js#gatherActor (ransomware groups are actors, see
// resolveGraphTarget in index.js), fetched in the same pass by this search's
// caller. This module just supplies the Universal Overview's verdict and a
// real victim-disclosure count, mirroring artifactModule.js's shape.
import { ransomwareCampaigns as getRansomwareCampaigns } from "../ransomwareCampaigns.js";
import { crossReferenceIndicator } from "./crossReference.js";

export const type = "ransomwareGroup";

function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

export async function gather(value) {
  const target = norm(value);
  const victims = getRansomwareCampaigns().filter((c) => norm(c.group) === target);
  const crossReference = crossReferenceIndicator(value);

  const note =
    victims.length > 0
      ? `Matched a real ransomware.live/RansomWatch/RansomLook group name with ${victims.length} disclosed victim(s) in this platform's data. See the Investigation Graph above for its full victim/malware/campaign relationships.`
      : "Matched a known ransomware group name, but this platform currently has no disclosed victim record for it.";

  return { group: value, victimCount: victims.length, victims: victims.slice(0, 20), crossReference, note };
}
