// Threat scoring engine for GitHub-sourced intelligence. A transparent
// weighted heuristic, same philosophy as correlate.js's IOC Search
// `correlatedVerdict` -- documented, tunable constants, not a black box.
// Every score returns its own breakdown so the UI can show *why* a repo/CVE
// scored the way it did, not just a bare number.

// Weights sum to 1.0. CVSS/EPSS/KEV dominate (60% combined) because they're
// the actual real-world-risk signals; GitHub popularity/activity are
// secondary corroboration, not the main driver -- a repo shouldn't score
// high just because it's popular if the underlying CVE is low-severity and
// not exploited.
const WEIGHTS = {
  githubPopularity: 0.1,
  repoActivity: 0.1,
  cvssSeverity: 0.2,
  epss: 0.2,
  kev: 0.2,
  feedCorrelation: 0.15,
  multiRepoCorroboration: 0.05,
};

const ACTIVITY_DECAY_DAYS = 365; // last commit older than this contributes 0

/** Stars are power-law distributed -- log scale so 10->10,000 stars isn't a 1000x jump in score. */
function normalizeStars(stars) {
  if (stars == null) return null;
  return Math.min(Math.log10(stars + 1) / 4, 1);
}

/** 1.0 at "committed today", linearly decaying to 0 at ACTIVITY_DECAY_DAYS+. */
function normalizeActivity(lastCommitDate) {
  if (!lastCommitDate) return null;
  const ageDays = (Date.now() - new Date(lastCommitDate).getTime()) / (24 * 60 * 60 * 1000);
  if (ageDays < 0) return 1;
  return Math.max(1 - ageDays / ACTIVITY_DECAY_DAYS, 0);
}

function normalizeCvss(cvssScore) {
  if (cvssScore == null) return null;
  return Math.min(cvssScore / 10, 1);
}

function normalizeEpss(epssScore) {
  if (epssScore == null) return null;
  return Math.min(Math.max(epssScore, 0), 1);
}

function normalizeKev(knownExploited) {
  if (knownExploited == null) return null;
  return knownExploited ? 1 : 0;
}

/** matchedFeeds / feedsChecked, e.g. an indicator found in ThreatFox + URLHaus out of 4 feeds checked = 0.5. */
function normalizeFeedCorrelation(matchedFeeds, feedsChecked) {
  if (matchedFeeds == null || !feedsChecked) return null;
  return Math.min(matchedFeeds / feedsChecked, 1);
}

/** Same CVE/family referenced across multiple independent repos is a stronger signal than a single PoC -- log scale, same rationale as stars. */
function normalizeCorroboration(repoCount) {
  if (repoCount == null) return null;
  return Math.min(Math.log10(repoCount + 1) / 2, 1);
}

/**
 * Computes a 0-100 threat score from whichever signals are available.
 * Missing signals (e.g. a just-reserved CVE with no CVSS/EPSS yet) are
 * excluded and the remaining weights are renormalized, rather than letting
 * `undefined` silently drag the score toward 0.
 *
 * @param {object} inputs
 * @param {number} [inputs.stars] - GitHub star count
 * @param {string|Date} [inputs.lastCommitDate] - date of the most recent commit
 * @param {number} [inputs.cvssScore] - 0-10
 * @param {number} [inputs.epssScore] - 0-1 probability
 * @param {boolean} [inputs.knownExploited] - CISA KEV inclusion
 * @param {number} [inputs.matchedFeeds] - how many threat feeds matched this indicator
 * @param {number} [inputs.feedsChecked] - how many threat feeds were checked
 * @param {number} [inputs.corroboratingRepoCount] - how many repos reference the same CVE/family
 * @returns {{ score: number, breakdown: Array<{signal: string, normalized: number, weight: number, contribution: number}> }}
 */
function computeThreatScore(inputs) {
  const normalized = {
    githubPopularity: normalizeStars(inputs.stars),
    repoActivity: normalizeActivity(inputs.lastCommitDate),
    cvssSeverity: normalizeCvss(inputs.cvssScore),
    epss: normalizeEpss(inputs.epssScore),
    kev: normalizeKev(inputs.knownExploited),
    feedCorrelation: normalizeFeedCorrelation(inputs.matchedFeeds, inputs.feedsChecked),
    multiRepoCorroboration: normalizeCorroboration(inputs.corroboratingRepoCount),
  };

  const available = Object.entries(WEIGHTS).filter(([key]) => normalized[key] != null);
  const totalWeight = available.reduce((sum, [, w]) => sum + w, 0);

  if (totalWeight === 0) return { score: 0, breakdown: [] };

  const breakdown = available.map(([key, w]) => {
    const weight = w / totalWeight;
    const value = normalized[key];
    return { signal: key, normalized: value, weight, contribution: weight * value * 100 };
  });

  const score = Math.round(breakdown.reduce((sum, b) => sum + b.contribution, 0));
  return { score, breakdown };
}

export { WEIGHTS, computeThreatScore };
