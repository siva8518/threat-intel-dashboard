import { ApiError, fetchJson } from "../lib/http.js";

const OTX_BASE = "https://otx.alienvault.com/api/v1";

class OtxNotConfiguredError extends ApiError {
  constructor() {
    super("AlienVault OTX requires a free API key from otx.alienvault.com (set OTX_API_KEY on the server)", "OTX", 401);
  }
}

function authHeaders() {
  if (!process.env.OTX_API_KEY) return null;
  return { "X-OTX-API-KEY": process.env.OTX_API_KEY };
}

const IOC_TYPE_MAP = {
  IPv4: "ip",
  IPv6: "ip",
  domain: "domain",
  hostname: "domain",
  URL: "url",
  "FileHash-MD5": "hash",
  "FileHash-SHA1": "hash",
  "FileHash-SHA256": "hash",
};

/**
 * Recent public OTX pulse activity, normalized into IOCs plus lightweight
 * "actor signal" data pulled from each pulse's adversary/tags/malware_families
 * fields -- OTX pulses are community-submitted, so this is a useful signal,
 * not verified attribution.
 */
export default {
  id: "otx",
  label: "AlienVault OTX",
  intervalMs: 15 * 60 * 1000,
  async fetch() {
    const headers = authHeaders();
    if (!headers) throw new OtxNotConfiguredError();

    let data;
    try {
      data = await fetchJson(`${OTX_BASE}/pulses/activity?limit=20`, { source: "AlienVault OTX", headers });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) throw new OtxNotConfiguredError();
      throw error;
    }

    const iocs = [];
    const actorSignals = [];

    for (const pulse of data.results ?? []) {
      for (const indicator of pulse.indicators ?? []) {
        const type = IOC_TYPE_MAP[indicator.type];
        if (!type) continue;
        iocs.push({
          id: `otx-${indicator.id}`,
          indicator: indicator.indicator,
          indicatorType: type,
          malwareFamily: pulse.malware_families?.join(", ") || "Unknown",
          threatType: pulse.tags?.[0] || "OTX pulse",
          firstSeen: new Date(indicator.created ?? pulse.created).toISOString(),
          source: "OTX",
        });
      }

      if (pulse.adversary) {
        actorSignals.push({
          name: pulse.adversary,
          pulseName: pulse.name,
          malwareFamilies: pulse.malware_families ?? [],
          tags: pulse.tags ?? [],
          date: pulse.created,
        });
      }
    }

    return { iocs, actorSignals };
  },
};

/**
 * Live full-text pulse search, used by the Threat Actor Profile feature
 * (not the bulk-synced `iocs`/`actorSignals` above, which only cover a
 * small rolling "recent activity" window and rarely happen to include any
 * given actor). Confirmed live this is a loose/fuzzy match, not an exact
 * phrase search -- e.g. querying "Velvet Ant" returns 0 pulses that
 * genuinely mention it (out of 20), while querying "APT28" or "Lazarus
 * Group" returns 20/20 genuinely relevant. Callers MUST re-check relevance
 * against the actual pulse name/description themselves (see
 * actorProfile.js's `mentionsActor`) rather than trusting the raw result set.
 */
export async function searchPulses(query, limit = 20) {
  const headers = authHeaders();
  if (!headers) throw new OtxNotConfiguredError();

  // Confirmed live this full-text search is genuinely slow (~16s for a
  // broad query like "Lazarus Group"), right at the edge of http.js's
  // default 15s timeout -- give it more room since it's called live,
  // on-demand, once per profile view, not on a tight polling loop.
  const data = await fetchJson(`${OTX_BASE}/search/pulses?q=${encodeURIComponent(query)}&limit=${limit}`, {
    source: "AlienVault OTX",
    headers,
    timeoutMs: 25_000,
  });
  return data.results ?? [];
}

/** On-demand single-indicator lookup for the IOC Search feature. */
export async function checkIndicator(type, value) {
  const headers = authHeaders();
  if (!headers) throw new OtxNotConfiguredError();

  const section = { ip: "IPv4", domain: "domain", url: "url", hash: "file" }[type];
  if (!section) throw new ApiError(`OTX does not support looking up indicator type "${type}"`, "OTX");

  const path = section === "file" ? `file/${value}` : `${section}/${value}`;
  const data = await fetchJson(`${OTX_BASE}/indicators/${path}/general`, { source: "OTX", headers });

  return {
    source: "OTX",
    pulseCount: data.pulse_info?.count ?? 0,
    tags: data.pulse_info?.pulses?.flatMap((p) => p.tags ?? []).slice(0, 10) ?? [],
    verdict: (data.pulse_info?.count ?? 0) > 0 ? "malicious" : "unknown",
  };
}
