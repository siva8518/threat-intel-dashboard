import { runDiscovery } from "./discovery.js";
import { runEnrichment } from "./enrichment.js";
import { listRepos, loadStore } from "./store.js";

/**
 * Two-tier cadence, deliberately not one connector: GitHub's Search API is
 * rate-limited to 10-30 req/min (the scarce resource), so discovery of new
 * repos runs slow. Content enrichment (README/tree/file fetches) uses the
 * much larger "core" rate-limit pool, so it can run closer to this app's
 * usual 15-min cadence, working through a backlog queue.
 */
export const githubDiscoveryConnector = {
  id: "github-discovery",
  label: "GitHub Intel Discovery",
  intervalMs: 60 * 60 * 1000,
  fetch: runDiscovery,
};

export const githubEnrichmentConnector = {
  id: "github-enrichment",
  label: "GitHub Intel Enrichment",
  intervalMs: 15 * 60 * 1000,
  fetch: runEnrichment,
};

/** Reads the current store directly (not through cache.js) -- used by dashboard routes that need the full up-to-date repo list, not just the last connector-run summary. */
export function getAllGithubRepos() {
  return listRepos(loadStore());
}

/**
 * CVEs ranked by how many enriched repos reference them -- shared by the
 * GitHub Intel stats panel and the Executive Threat Summary's "most
 * exploited CVE" signal, so both read the exact same ranking.
 */
export function computeTopCves(repos, limit = 10) {
  const enriched = repos.filter((r) => r.lastEnrichedAt);
  const cveCounts = {};
  for (const repo of enriched) {
    for (const cveId of repo.extracted?.cveIds ?? []) cveCounts[cveId] = (cveCounts[cveId] ?? 0) + 1;
  }
  return Object.entries(cveCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([cveId, repoCount]) => ({ cveId, repoCount }));
}
