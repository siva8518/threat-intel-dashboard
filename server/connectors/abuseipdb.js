import { ApiError, fetchJson } from "../lib/http.js";

const ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2";

class AbuseIpdbNotConfiguredError extends ApiError {
  constructor() {
    super("AbuseIPDB requires a free API key from abuseipdb.com (set ABUSEIPDB_API_KEY on the server)", "AbuseIPDB", 401);
  }
}

function authHeaders() {
  if (!process.env.ABUSEIPDB_API_KEY) return null;
  return { Key: process.env.ABUSEIPDB_API_KEY, Accept: "application/json" };
}

/**
 * AbuseIPDB's free-tier /blacklist endpoint is a genuine bulk feed (unlike
 * VirusTotal/GreyNoise/Shodan's free tiers, which only support one indicator
 * at a time) -- this is what powers "Top Malicious IPs" as a real list.
 */
export default {
  id: "abuseipdb",
  label: "AbuseIPDB",
  intervalMs: 60 * 60 * 1000, // free tier has a modest daily quota; sync hourly
  async fetch() {
    const headers = authHeaders();
    if (!headers) throw new AbuseIpdbNotConfiguredError();

    let data;
    try {
      data = await fetchJson(`${ABUSEIPDB_BASE}/blacklist?confidenceMinimum=75&limit=100`, {
        source: "AbuseIPDB",
        headers,
      });
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) throw new AbuseIpdbNotConfiguredError();
      throw error;
    }

    return (data.data ?? []).map((entry) => ({
      id: `abuseipdb-${entry.ipAddress}`,
      indicator: entry.ipAddress,
      indicatorType: "ip",
      malwareFamily: "Unknown",
      threatType: `Abuse confidence ${entry.abuseConfidenceScore}%`,
      firstSeen: entry.lastReportedAt ? new Date(entry.lastReportedAt).toISOString() : new Date().toISOString(),
      source: "AbuseIPDB",
    }));
  },
};

/** On-demand single-IP reputation lookup for the IOC Search feature. */
export async function checkIndicator(type, value) {
  if (type !== "ip") throw new ApiError("AbuseIPDB only supports IP lookups", "AbuseIPDB");
  const headers = authHeaders();
  if (!headers) throw new AbuseIpdbNotConfiguredError();

  const data = await fetchJson(`${ABUSEIPDB_BASE}/check?ipAddress=${encodeURIComponent(value)}&maxAgeInDays=90`, {
    source: "AbuseIPDB",
    headers,
  });

  const score = data.data?.abuseConfidenceScore ?? 0;
  return {
    source: "AbuseIPDB",
    abuseConfidenceScore: score,
    totalReports: data.data?.totalReports ?? 0,
    countryCode: data.data?.countryCode ?? null,
    verdict: score >= 50 ? "malicious" : score >= 20 ? "suspicious" : "clean",
  };
}
