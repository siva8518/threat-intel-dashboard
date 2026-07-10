import { fetchJson } from "../lib/http.js";

const MALPEDIA_BASE = "https://malpedia.caad.fkie.fraunhofer.de/api";

/**
 * Malpedia (Fraunhofer FKIE): free, keyless malware-family/actor reference
 * database (malpedia.caad.fkie.fraunhofer.de). This connector just caches
 * the family/actor name lists -- a reference taxonomy, not live telemetry,
 * same "sync daily" cadence as MITRE ATT&CK. The much richer per-actor
 * family-attribution data is fetched live, on demand, only when a Threat
 * Actor Profile is actually viewed (see getActorDetail below and
 * server/actorProfile.js) -- fetching all 1000+ actors' detail up front on
 * every sync would be needlessly expensive for data that's rarely viewed.
 */
export default {
  id: "malpedia",
  label: "Malpedia",
  intervalMs: 24 * 60 * 60 * 1000,
  async fetch() {
    const [families, actors] = await Promise.all([
      fetchJson(`${MALPEDIA_BASE}/list/families`, { source: "Malpedia" }),
      fetchJson(`${MALPEDIA_BASE}/list/actors`, { source: "Malpedia" }),
    ]);
    return {
      families: Array.isArray(families) ? families : [],
      actors: Array.isArray(actors) ? actors : [],
    };
  },
};

/**
 * Live per-actor detail lookup. Confirmed live shape:
 * `{ families: { "<internal-slug>": { common_name, alt_names, attribution, urls, ... } } }`.
 * `slug` must be one of the names already returned by the cached `actors`
 * list above (e.g. "apt28", "lazarus_group") -- confirmed live these are
 * lowercase with underscores replacing spaces.
 */
export async function getActorDetail(slug) {
  return fetchJson(`${MALPEDIA_BASE}/get/actor/${encodeURIComponent(slug)}`, { source: "Malpedia" });
}
