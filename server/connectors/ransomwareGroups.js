import { fetchJson } from "../lib/http.js";

const RANSOMWARE_GROUPS_URL = "https://api.ransomware.live/v2/groups";

/**
 * ransomware.live's group directory: name + a real per-group profile page
 * URL (e.g. "https://www.ransomware.live/group/thegentlemen"). Used only as
 * a fallback link in server/ransomwareCampaigns.js -- when a specific
 * victim post has no direct page yet (confirmed live: this is common for
 * RansomLook-only entries not yet mirrored by ransomware.live's own
 * per-victim feed), the group's own profile page is still a real, useful
 * link rather than leaving the item unclickable.
 *
 * CONFIRMED LIVE: this endpoint is rate-limited to 1 request/minute -- group
 * metadata changes rarely, so this doesn't need to sync often, but the
 * interval is kept to 30 min (not several hours) rather than the rarely-
 * changing data alone: a boot-time sync that lands within a minute of a
 * previous request (e.g. `node --watch` restarting on any server file edit
 * during dev, each restart re-running every connector's fetch() once) gets a
 * transient 429 -- a short interval lets it self-heal on the next tick
 * instead of leaving the group-page fallback empty for hours.
 */
export default {
  id: "ransomware-groups",
  label: "ransomware.live groups",
  intervalMs: 30 * 60 * 1000,
  async fetch() {
    const data = await fetchJson(RANSOMWARE_GROUPS_URL, { source: "ransomware.live groups" });
    return (Array.isArray(data) ? data : [])
      .filter((g) => g.name && g.url)
      .map((g) => ({ name: g.name, url: g.url }));
  },
};
