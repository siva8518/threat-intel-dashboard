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
 * CVEs ranked by how many enriched repos reference them, plus -- additively,
 * same pattern as server/correlate.js#computeAttackTechniquesObserved merging
 * in news-derived technique counts -- how many news headlines (across every
 * configured source) name each CVE (server/newsCorrelation.js#getNewsCveCounts).
 * Shared by the GitHub Intel stats panel, the "Top CVEs" widget, and the
 * Executive Threat Summary's "most exploited CVE" signal, so all three read
 * the exact same ranking. `repoCount` stays GitHub-only so existing exploit-
 * PoC semantics aren't diluted; `newsMentionCount` is reported separately so
 * a CVE surfaced purely by news coverage (no PoC repo yet) is still visible
 * and distinguishable from one confirmed to have public exploit code.
 */
export function computeTopCves(repos, limit = 10, newsCveCounts = new Map()) {
  const enriched = repos.filter((r) => r.lastEnrichedAt);
  const cveCounts = {};
  for (const repo of enriched) {
    for (const cveId of repo.extracted?.cveIds ?? []) cveCounts[cveId] = (cveCounts[cveId] ?? 0) + 1;
  }

  const combined = new Map();
  for (const [cveId, repoCount] of Object.entries(cveCounts)) combined.set(cveId, { repoCount, newsMentionCount: 0 });
  for (const [cveId, newsMentionCount] of newsCveCounts) {
    const entry = combined.get(cveId) ?? { repoCount: 0, newsMentionCount: 0 };
    entry.newsMentionCount = newsMentionCount;
    combined.set(cveId, entry);
  }

  return Array.from(combined.entries())
    .sort((a, b) => b[1].repoCount + b[1].newsMentionCount - (a[1].repoCount + a[1].newsMentionCount))
    .slice(0, limit)
    .map(([cveId, counts]) => ({ cveId, ...counts }));
}
