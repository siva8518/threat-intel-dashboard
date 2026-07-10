import { getReadme, getTree, getFileContent } from "./githubClient.js";

const MAX_FILES_FETCHED = 10;
const MAX_FILE_SIZE_BYTES = 200_000; // skip huge files -- unlikely to be a rule/IOC file, costly to fetch/scan for little gain

// Deliberately NOT a full-repo clone (see server/githubIntel/store.js header
// comment for the architecture rationale): the content that actually carries
// extractable intel -- CVE IDs, hashes, IOCs, rule names -- almost always
// lives in the README or one of these file kinds, not buried in general
// source. Bounded to README + tree listing + up to MAX_FILES_FETCHED targeted
// files = at most ~12 API calls per repo, predictable and cheap against the
// "core" rate-limit pool.
const INTERESTING_PATTERNS = [
  /\.ya?ra$/i, // YARA rules
  /(^|\/)rules?\/.*\.ya?ml$/i, // Sigma rules are almost always under a rules/ dir
  /sigma.*\.ya?ml$/i,
  /\.rules$/i, // Suricata/Snort rules
  /(ioc|iocs|indicators?|hashes?|c2|c2s)\.(txt|csv|md|json|yml|yaml)$/i,
  // Confirmed live: PoC-archive repos very commonly organize content as one
  // file/dir per CVE (e.g. "exploits/CVE-2024-1234.py", "CVE-2024-1234/README.md")
  // rather than listing every CVE in the top-level README -- without this,
  // that per-CVE detail is invisible to the extractor.
  /CVE-\d{4}-\d{4,7}/i,
];

function isInteresting(path) {
  return INTERESTING_PATTERNS.some((pattern) => pattern.test(path));
}

/**
 * Gathers the text worth running the extractor/classifier over for one repo:
 * README + up to MAX_FILES_FETCHED files whose path matches a known
 * rule/IOC-file pattern. Returns partial results (whatever it managed to
 * fetch) rather than throwing, since a single missing file/tree shouldn't
 * abort enrichment for the whole repo.
 */
export async function fetchRepoContent(owner, repo, defaultBranch) {
  const readme = await getReadme(owner, repo).catch(() => null);
  const tree = await getTree(owner, repo, defaultBranch).catch(() => []);

  const candidates = tree
    .filter((entry) => entry.type === "blob" && isInteresting(entry.path) && (entry.size ?? 0) <= MAX_FILE_SIZE_BYTES)
    .sort((a, b) => (a.size ?? 0) - (b.size ?? 0)) // smallest first -- cheaper, and rule/IOC files are rarely huge
    .slice(0, MAX_FILES_FETCHED);

  const files = [];
  for (const entry of candidates) {
    const content = await getFileContent(owner, repo, entry.path).catch(() => null);
    if (content != null) files.push({ path: entry.path, content });
  }

  return {
    readme,
    files,
    combinedText: [readme ?? "", ...files.map((f) => f.content)].join("\n\n"),
  };
}
