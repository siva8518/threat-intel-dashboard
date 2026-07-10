import { getTree } from "../githubIntel/githubClient.js";

// Two of the largest free, keyless, community-maintained detection-rule
// repos (Yara-Rules/rules: ~1000+ YARA rules; SigmaHQ/sigma: 3000+ Sigma
// rules, both confirmed live via GitHub). This is a lightweight rule-name
// index, not full rule-content parsing: file paths in both repos are
// consistently organized by malware family / threat category (e.g.
// "malware/RANSOM_Lockbit.yar", "rules/windows/process_creation/proc_creation_win_apt_lockbit.yml"),
// so the filename itself is a reasonably reliable signal of what the rule
// detects, reused the same way server/correlate.js already substring-matches
// malware family names against a curated seed map. Deliberately reuses the
// existing GitHub client (server/githubIntel/githubClient.js) instead of a
// second GitHub API implementation -- same auth/rate-limit handling, one
// tree listing per repo per sync (not per-file), so this stays cheap against
// GitHub's own rate limits even unauthenticated.
const REPOS = [
  { label: "YARA-Rules", owner: "Yara-Rules", repo: "rules", branch: "master", extensions: [".yar", ".yara"] },
  { label: "SigmaHQ", owner: "SigmaHQ", repo: "sigma", branch: "master", extensions: [".yml", ".yaml"] },
];

// Path segments that are structural, not malware/actor names -- filtered out
// so they don't pollute the rule-name index with noise.
const STOPWORDS = new Set([
  "rules", "rule", "windows", "linux", "macos", "generic", "index", "deprecated", "utils",
  "process_creation", "network_connection", "file_event", "registry", "image_load", "test",
  "proc", "creation", "win", "apt", "malware", "cloud", "application", "builtin", "other",
  "clear", "clearing", "shell", "unknown", "logs", "logging", "cmd", "command", "history",
  "syslog", "auditctl", "susp", "suspicious", "activity", "detected", "execution", "executed",
  "elf", "azure", "signin", "signins", "risky", "singlefactorauth", "devices", "device",
]);

function ruleNameCandidates(path, extensions) {
  const ext = extensions.find((e) => path.toLowerCase().endsWith(e));
  if (!ext) return [];
  const filename = path.slice(path.lastIndexOf("/") + 1, path.length - ext.length);
  return filename
    .split(/[_\-.]+/)
    .map((w) => w.trim().toLowerCase())
    .filter((w) => w.length > 2 && !STOPWORDS.has(w) && !/^\d+$/.test(w));
}

/**
 * Periodic sync (not a bulk IOC feed): builds a flat list of {word, path,
 * label} rows from both repos' file trees. server/correlate.js and
 * server/actorProfile.js cross-reference this against malware family/actor
 * names via substring match to answer "is there a public detection rule for
 * this?" -- a genuinely new signal, distinct from anything already tracked.
 */
export default {
  id: "detection-rules",
  label: "YARA/Sigma Rules",
  intervalMs: 6 * 60 * 60 * 1000, // 6h -- these repos change by commits/PRs, not real-time activity
  async fetch() {
    const index = [];
    let totalFiles = 0;

    for (const { label, owner, repo, branch, extensions } of REPOS) {
      const tree = await getTree(owner, repo, branch);
      for (const entry of tree) {
        if (entry.type !== "blob") continue;
        const words = ruleNameCandidates(entry.path, extensions);
        if (words.length === 0) continue;
        totalFiles++;
        const url = `https://github.com/${owner}/${repo}/blob/${branch}/${entry.path}`;
        for (const word of words) index.push({ word, path: entry.path, url, label });
      }
    }

    return { totalFiles, index };
  },
};
