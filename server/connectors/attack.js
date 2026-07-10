import { ApiError } from "../lib/http.js";

// Official MITRE ATT&CK Enterprise STIX bundle. Large (tens of MB) and
// contains far more than techniques -- this connector also extracts Groups
// (intrusion-set), Software (malware/tool), Campaigns, and the "uses"/
// "attributed-to" relationships between them, which power the Threat Actor
// Profile feature. Every field name below was confirmed against the live
// bundle (not assumed): aliases lives on `aliases` for groups/campaigns but
// `x_mitre_aliases` for software; campaign "name" is genuinely just its code
// (e.g. "C0027"), ATT&CK doesn't give campaigns a separate display name.
const ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
const TIMEOUT_MS = 90_000;

function cleanDescription(text) {
  if (!text) return "";
  return text
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1") // "[text](url)" -> "text"
    .replace(/\(Citation:[^)]*\)/g, "") // strip "(Citation: ...)" footnote markers
    .replace(/\s{2,}/g, " ")
    .trim();
}

function mitreExternalRef(obj) {
  return obj.external_references?.find((r) => r.source_name === "mitre-attack");
}

// Confirmed live against the real bundle: ATT&CK Groups, Software and
// Campaigns often cite the specific CVE they exploited/delivered right in
// their citation text (e.g. Velvet Ant's own citation reads "China-Nexus
// Threat Group 'Velvet Ant' Exploits Cisco Zero-Day (CVE-2024-20399)").
// This is a much stronger, already-free signal than generic NVD keyword
// search on the actor's name, which almost never matches (CVE descriptions
// describe the vulnerability, not who exploited it) -- see actorProfile.js.
function extractCveIds(externalReferences) {
  const ids = new Set();
  for (const ref of externalReferences ?? []) {
    const text = `${ref.description ?? ""} ${ref.url ?? ""}`;
    const matches = text.match(/CVE-\d{4}-\d+/g);
    if (matches) matches.forEach((id) => ids.add(id));
  }
  return Array.from(ids);
}

// Best-effort keyword extraction from group descriptions -- ATT&CK has no
// structured country/motivation/target-industry/active-since fields on
// Groups, so this is a curated, clearly-labeled approximation (see
// ThreatActorProfile UI), not authoritative data.
const COUNTRY_KEYWORDS = [
  ["Russia", "Russian"], ["China", "Chinese"], ["North Korea", "North Korean"], ["Iran", "Iranian"],
  ["Vietnam", "Vietnamese"], ["India", "Indian"], ["Pakistan", "Pakistani"], ["Lebanon", "Lebanese"],
  ["Turkey", "Turkish"], ["Belarus", "Belarusian"], ["South Korea", "South Korean"], ["Syria", "Syrian"],
  ["Ukraine", "Ukrainian"], ["Ukraine", "pro-Ukrainian"], ["Nigeria", "Nigerian"], ["Palestine", "Palestinian"],
];
const MOTIVATION_KEYWORDS = [
  ["espionage", "Espionage"], ["financially motivated", "Financially motivated"], ["financial gain", "Financially motivated"],
  ["cybercrime", "Cybercrime"], ["hacktivis", "Hacktivism"], ["destructive", "Destructive/disruptive attacks"],
  ["sabotage", "Sabotage"], ["ransomware operations", "Ransomware operations"],
];
const INDUSTRY_KEYWORDS = [
  "government", "military", "defense", "financial", "banking", "healthcare", "energy", "telecommunications",
  "technology", "media", "education", "manufacturing", "aerospace", "retail", "hospitality", "critical infrastructure",
  "oil and gas", "transportation", "legal", "non-governmental organizations", "think tank",
];

function extractCountry(description) {
  const lower = description.toLowerCase();
  for (const [label, adjective] of COUNTRY_KEYWORDS) {
    if (lower.includes(label.toLowerCase()) || lower.includes(adjective.toLowerCase())) return label;
  }
  return null;
}

function extractMotivation(description) {
  const lower = description.toLowerCase();
  const found = new Set();
  for (const [keyword, label] of MOTIVATION_KEYWORDS) {
    if (lower.includes(keyword)) found.add(label);
  }
  return Array.from(found);
}

function extractActiveSince(description) {
  const match = description.match(/(?:since|active since|operating since)\s+(?:at least\s+)?(\d{4})/i);
  return match ? match[1] : null;
}

function extractIndustries(description) {
  const lower = description.toLowerCase();
  return INDUSTRY_KEYWORDS.filter((kw) => lower.includes(kw)).map((kw) => kw.replace(/\b\w/g, (c) => c.toUpperCase()));
}

export default {
  id: "attack",
  label: "MITRE ATT&CK",
  intervalMs: 7 * 24 * 60 * 60 * 1000, // weekly -- this is a taxonomy, not live telemetry
  async fetch() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let response;
    try {
      response = await fetch(ATTACK_URL, { signal: controller.signal });
    } catch (error) {
      throw new ApiError(`MITRE ATT&CK is unreachable: ${error.message}`, "MITRE ATT&CK");
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      throw new ApiError(`MITRE ATT&CK responded with ${response.status} ${response.statusText}`, "MITRE ATT&CK", response.status);
    }

    const bundle = await response.json();
    const objects = bundle.objects;

    const techniques = [];
    const groups = [];
    const software = [];
    const campaigns = [];

    for (const obj of objects) {
      if (obj.revoked || obj.x_mitre_deprecated) continue;

      if (obj.type === "attack-pattern") {
        const ref = mitreExternalRef(obj);
        if (!ref?.external_id) continue;
        techniques.push({
          id: ref.external_id,
          stixId: obj.id,
          name: obj.name,
          tactic: obj.kill_chain_phases?.[0]?.phase_name?.replace(/-/g, " ") ?? "unknown",
          url: ref.url ?? `https://attack.mitre.org/techniques/${ref.external_id}`,
        });
      } else if (obj.type === "intrusion-set") {
        const ref = mitreExternalRef(obj);
        if (!ref?.external_id) continue;
        const description = cleanDescription(obj.description);
        groups.push({
          id: obj.id,
          attackId: ref.external_id,
          name: obj.name,
          aliases: (obj.aliases ?? []).filter((a) => a !== obj.name),
          description,
          url: ref.url ?? `https://attack.mitre.org/groups/${ref.external_id}`,
          country: extractCountry(description),
          motivations: extractMotivation(description),
          activeSince: extractActiveSince(description),
          targetIndustries: extractIndustries(description),
          cveIds: extractCveIds(obj.external_references),
          softwareIds: [],
          techniqueIds: new Set(),
          campaignIds: [],
        });
      } else if (obj.type === "malware" || obj.type === "tool") {
        const ref = mitreExternalRef(obj);
        if (!ref?.external_id) continue;
        software.push({
          id: obj.id,
          attackId: ref.external_id,
          name: obj.name,
          aliases: obj.x_mitre_aliases ?? [],
          description: cleanDescription(obj.description),
          type: obj.type,
          url: ref.url ?? `https://attack.mitre.org/software/${ref.external_id}`,
          cveIds: extractCveIds(obj.external_references),
          techniqueIds: new Set(),
        });
      } else if (obj.type === "campaign") {
        const ref = mitreExternalRef(obj);
        if (!ref?.external_id) continue;
        campaigns.push({
          id: obj.id,
          attackId: ref.external_id,
          name: ref.external_id, // ATT&CK campaigns have no separate display name beyond their code
          description: cleanDescription(obj.description),
          firstSeen: obj.first_seen ?? null,
          lastSeen: obj.last_seen ?? null,
          url: ref.url ?? `https://attack.mitre.org/campaigns/${ref.external_id}`,
          cveIds: extractCveIds(obj.external_references),
          groupId: null,
        });
      }
    }

    const groupsById = new Map(groups.map((g) => [g.id, g]));
    const softwareById = new Map(software.map((s) => [s.id, s]));
    const campaignsById = new Map(campaigns.map((c) => [c.id, c]));
    const techniqueByStixId = new Map(techniques.map((t) => [t.stixId, t.id]));

    for (const obj of objects) {
      if (obj.type !== "relationship" || obj.revoked || obj.x_mitre_deprecated) continue;
      const { relationship_type: type, source_ref: src, target_ref: dst } = obj;

      if (type === "uses") {
        const group = groupsById.get(src);
        const softwareItem = softwareById.get(src);
        const techniqueId = techniqueByStixId.get(dst);

        if (group && softwareById.has(dst)) group.softwareIds.push(dst);
        else if (group && techniqueId) group.techniqueIds.add(techniqueId);
        else if (softwareItem && techniqueId) softwareItem.techniqueIds.add(techniqueId);
      } else if (type === "attributed-to") {
        const campaign = campaignsById.get(src);
        const group = groupsById.get(dst);
        if (campaign && group) {
          campaign.groupId = group.id;
          group.campaignIds.push(campaign.id);
        }
      }
    }

    // Fold in techniques inherited via each group's software (ATT&CK's own
    // group pages show this union too, not just directly-linked techniques --
    // confirmed live that direct group->technique links are far sparser than
    // software->technique ones, ~4500 vs ~11000 relationships overall).
    for (const group of groups) {
      for (const softwareId of group.softwareIds) {
        const softwareItem = softwareById.get(softwareId);
        if (!softwareItem) continue;
        for (const techniqueId of softwareItem.techniqueIds) group.techniqueIds.add(techniqueId);
      }
      group.techniqueIds = Array.from(group.techniqueIds);
    }
    for (const softwareItem of software) {
      softwareItem.techniqueIds = Array.from(softwareItem.techniqueIds);
    }

    return { techniques, groups, software, campaigns };
  },
};
