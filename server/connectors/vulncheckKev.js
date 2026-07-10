import { ApiError, fetchJson } from "../lib/http.js";

const VULNCHECK_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev";

class VulncheckNotConfiguredError extends ApiError {
  constructor() {
    super("VulnCheck KEV requires a free Community API key from vulncheck.com (set VULNCHECK_API_KEY on the server)", "VulnCheck KEV", 401);
  }
}

function authHeaders() {
  if (!process.env.VULNCHECK_API_KEY) return null;
  return { Authorization: `Bearer ${process.env.VULNCHECK_API_KEY}` };
}

/**
 * VulnCheck's free Community KEV feed -- confirmed live schema via
 * docs.vulncheck.com/community/vulncheck-kev/schema. Tracks 2,500+ exploited
 * CVEs (130%+ more than CISA's own KEV catalog), each with its own
 * `vulncheck_xdb` array of confirmed PoC/exploit references -- a genuinely
 * different (larger, exploit-linked) dataset from server/connectors/cisaKev.js,
 * not a duplicate, so it's kept as its own connector/route rather than merged
 * into the CISA KEV one. Optional: short-circuits to "not configured" like
 * OTX/AbuseIPDB/etc if no key is set, same established pattern.
 */
export default {
  id: "vulncheck-kev",
  label: "VulnCheck KEV",
  intervalMs: 30 * 60 * 1000,
  async fetch() {
    const headers = authHeaders();
    if (!headers) throw new VulncheckNotConfiguredError();

    let data;
    try {
      data = await fetchJson(VULNCHECK_URL, { source: "VulnCheck KEV", headers });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) throw new VulncheckNotConfiguredError();
      throw error;
    }

    const entries = (data.data ?? []).map((v) => ({
      cveIds: v.cve ?? [],
      vendorProject: v.vendorProject ?? "Unknown",
      product: v.product ?? "Unknown",
      vulnerabilityName: v.vulnerabilityName ?? v.shortDescription ?? "Unknown",
      dateAdded: v.date_added ?? v.cisa_date_added ?? null,
      dueDate: v.dueDate ?? null,
      requiredAction: v.required_action ?? null,
      ransomwareUse: v.knownRansomwareCampaignUse === "Known",
      exploitReferences: (v.vulncheck_xdb ?? []).map((x) => ({ id: x.xdb_id, url: x.xdb_url, type: x.exploit_type })),
    }));

    return { count: entries.length, entries };
  },
};
