import { ApiError } from "../lib/http.js";

const GITHUB_API = "https://api.github.com";
const TIMEOUT_MS = 20_000;

// GitHub buckets rate limits separately per "resource" -- confirmed live:
// Search API is 10 req/min unauthenticated / 30 req/min with a token, while
// the "core" resource (repos/contents/trees/readme) is 60/hr unauthenticated
// / 5000/hr with a token. Tracked independently so a tight Search budget
// doesn't falsely throttle README/tree fetches, and vice versa.
const rateLimitState = {
  search: { remaining: 10, reset: 0 },
  core: { remaining: 60, reset: 0 },
};

function authHeaders() {
  const headers = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return headers;
}

/** If the given resource pool is exhausted, waits until GitHub's own reset time rather than hammering into a wall of 403s. */
async function waitForRateLimit(resource) {
  const state = rateLimitState[resource];
  if (state.remaining > 0) return;
  const waitMs = state.reset * 1000 - Date.now();
  if (waitMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, waitMs + 1000));
  }
}

function updateRateLimitState(resource, response) {
  const remaining = response.headers.get("x-ratelimit-remaining");
  const reset = response.headers.get("x-ratelimit-reset");
  if (remaining != null) rateLimitState[resource].remaining = Number(remaining);
  if (reset != null) rateLimitState[resource].reset = Number(reset);
}

async function githubRequest(url, resource) {
  await waitForRateLimit(resource);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response;
  try {
    response = await fetch(url, { headers: authHeaders(), signal: controller.signal });
  } catch (error) {
    throw new ApiError(`GitHub API is unreachable: ${error.message}`, "GitHub", undefined);
  } finally {
    clearTimeout(timeout);
  }

  updateRateLimitState(resource, response);

  if (!response.ok) {
    // 404 is routine here (missing README, deleted repo, empty tree) -- callers handle it, not a hard failure.
    throw new ApiError(`GitHub API responded with ${response.status} ${response.statusText} for ${url}`, "GitHub", response.status);
  }

  return response.json();
}

/** GitHub Search API: repositories matching a query string (supports qualifiers like topic:, in:readme, language:). */
export async function searchRepositories(query, { perPage = 30, page = 1 } = {}) {
  const url = `${GITHUB_API}/search/repositories?q=${encodeURIComponent(query)}&sort=updated&per_page=${perPage}&page=${page}`;
  return githubRequest(url, "search");
}

/** README content, decoded from GitHub's base64 response. Returns null (not throws) if the repo has no README. */
export async function getReadme(owner, repo) {
  try {
    const data = await githubRequest(`${GITHUB_API}/repos/${owner}/${repo}/readme`, "core");
    return Buffer.from(data.content, data.encoding ?? "base64").toString("utf-8");
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

/** Full recursive file listing for one repo. Returns [] (not throws) for an empty/inaccessible tree rather than failing the whole enrichment. */
export async function getTree(owner, repo, branch) {
  try {
    const data = await githubRequest(`${GITHUB_API}/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`, "core");
    return data.tree ?? [];
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return [];
    throw error;
  }
}

/** One file's content by path, decoded from base64. Returns null for files that vanished between the tree listing and this fetch (renames, force-pushes). */
export async function getFileContent(owner, repo, path) {
  try {
    const data = await githubRequest(`${GITHUB_API}/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, "core");
    if (data.encoding !== "base64" || typeof data.content !== "string") return null; // e.g. a directory or a file too large to inline
    return Buffer.from(data.content, "base64").toString("utf-8");
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

export function getRateLimitState() {
  return { search: { ...rateLimitState.search }, core: { ...rateLimitState.core } };
}
