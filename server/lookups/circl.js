import { fetchJson } from "../lib/http.js";

const CIRCL_URL = "https://cve.circl.lu/api/cve";

// CIRCL's CVE Search -- free, keyless, no registration. Used only as a
// fallback when NVD doesn't have a record (very new CVEs not yet synced
// into NVD, or very old ones NVD has since pruned from its API), not as a
// primary source: confirmed live that its CVE Record v5 payload doesn't
// carry a structured CVSS score/severity the way NVD does (its "metrics"
// field is a free-text vendor assessment, e.g. {"content":{"other":"critical"}},
// not a numeric vector) -- so cvssScore stays null here rather than guessing
// at a number, and severity is best-effort parsed from that free text only
// when it unambiguously names one of NVD's own severity bands.
const SEVERITY_WORDS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function guessSeverity(metrics) {
  const text = JSON.stringify(metrics ?? "").toUpperCase();
  return SEVERITY_WORDS.find((word) => text.includes(word)) ?? "UNKNOWN";
}

/** Fallback CVE lookup by ID. Returns null (not throws) if CIRCL also doesn't have it. */
export async function lookupCve(cveId) {
  const record = await fetchJson(`${CIRCL_URL}/${encodeURIComponent(cveId)}`, { source: "CIRCL" });
  if (!record?.cveMetadata?.cveId) return null;

  const cna = record.containers?.cna ?? {};
  const description = cna.descriptions?.find((d) => d.lang === "en")?.value ?? cna.descriptions?.[0]?.value ?? "";
  const affected = cna.affected?.[0] ?? {};

  return {
    id: record.cveMetadata.cveId,
    severity: guessSeverity(cna.metrics),
    cvssScore: null,
    vendor: affected.vendor ?? "Unknown",
    product: affected.product ?? "Unknown",
    publishedDate: record.cveMetadata.datePublished ?? null,
    description,
    knownExploited: false,
    epssScore: null,
    epssPercentile: null,
    sourceUrl: `https://cve.circl.lu/cve/${record.cveMetadata.cveId}`,
  };
}
