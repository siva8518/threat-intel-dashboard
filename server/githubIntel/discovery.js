import { CATEGORIES } from "./categories.js";
import { searchRepositories } from "./githubClient.js";
import { loadStore, saveStore, upsertRepoMetadata, listRepos } from "./store.js";
import { log } from "../lib/log.js";

const RESULTS_PER_QUERY = 20;

/**
 * Sweeps every category's query variants through the Search API and
 * upserts basic repo metadata into the disk-backed store (see store.js).
 * Deliberately does not fetch content/classify/extract here -- that's
 * enrichment.js's job, on its own faster cadence, so a single slow Search
 * API sweep doesn't also gate content fetching for repos already known.
 * A single query failing (rate limit, transient error) is logged and
 * skipped rather than aborting the whole sweep.
 */
export async function runDiscovery() {
  const store = loadStore();
  let discoveredCount = 0;

  for (const category of CATEGORIES) {
    for (const query of category.queries) {
      try {
        const data = await searchRepositories(query, { perPage: RESULTS_PER_QUERY });
        for (const repo of data.items ?? []) {
          upsertRepoMetadata(store, {
            id: repo.id,
            fullName: repo.full_name,
            url: repo.html_url,
            description: repo.description,
            stars: repo.stargazers_count,
            forks: repo.forks_count,
            lastCommitDate: repo.pushed_at,
            topics: repo.topics ?? [],
            defaultBranch: repo.default_branch,
            discoveredVia: category.id,
          });
          discoveredCount++;
        }
      } catch (error) {
        log.error("github-discovery", `query "${query}" (${category.label}) failed: ${error.message}`);
      }
    }
  }

  saveStore(store);
  return {
    repoCount: listRepos(store).length,
    discoveredThisRun: discoveredCount,
    categories: CATEGORIES.map((c) => ({ id: c.id, label: c.label })),
  };
}
