// Best-effort algorithmic heuristics for typosquatting/homograph/DGA/parked/
// disposable domain signals -- explicitly NOT presented as a live feed or ML
// classifier, just a documented, deterministic heuristic. Every field this
// produces is labeled "heuristic" in the API response so the frontend can be
// equally honest about it, same precedent as this app's other curated,
// clearly-labeled static reference data (e.g. the ATT&CK malware->technique
// map).
const COMMON_TARGET_BRANDS = [
  "google", "microsoft", "apple", "amazon", "paypal", "facebook", "instagram",
  "netflix", "bankofamerica", "wellsfargo", "chase", "citibank", "coinbase",
  "binance", "outlook", "office365", "gmail", "linkedin", "twitter", "x",
  "github", "dropbox", "adobe", "docusign", "americanexpress", "usps",
  "fedex", "dhl", "ups",
];

// Visually-confusable character substitutions commonly used in homograph
// attacks (Latin lookalikes for common ASCII letters).
const CONFUSABLES = { "0": "o", "1": "l", "3": "e", "5": "s", "rn": "m", vv: "w" };

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[m][n];
}

function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] ?? 0) + 1;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / str.length;
    return sum + p * Math.log2(p);
  }, 0);
}

function normalizeConfusables(label) {
  let out = label;
  for (const [from, to] of Object.entries(CONFUSABLES)) out = out.split(from).join(to);
  return out;
}

/** Registrable-label typosquat/homograph check against a small curated brand list -- distance <= 2 on a label of similar length is flagged, never a definitive claim. */
export function checkTyposquatting(domain) {
  const label = domain.split(".")[0]?.toLowerCase() ?? "";
  const normalized = normalizeConfusables(label);
  let closest = null;
  let closestDistance = Infinity;
  for (const brand of COMMON_TARGET_BRANDS) {
    const distance = Math.min(levenshtein(label, brand), levenshtein(normalized, brand));
    if (distance < closestDistance) {
      closestDistance = distance;
      closest = brand;
    }
  }
  const flagged = closest !== null && closestDistance > 0 && closestDistance <= 2 && Math.abs(label.length - closest.length) <= 3;
  const homographFlagged = closest !== null && normalized !== label && levenshtein(normalized, closest) === 0;
  return {
    heuristic: true,
    flagged: flagged || homographFlagged,
    closestBrandMatch: closestDistance <= 2 ? closest : null,
    editDistance: closestDistance <= 2 ? closestDistance : null,
    homographSuspected: homographFlagged,
  };
}

/** Domain Generation Algorithm likelihood -- high-entropy, consonant-heavy, non-dictionary-looking labels score higher. Purely statistical, not a trained classifier. */
export function checkDgaLikelihood(domain) {
  const label = domain.split(".")[0]?.toLowerCase() ?? "";
  if (label.length < 6) return { heuristic: true, score: 0, likely: false, reason: "Label too short to assess" };
  const entropy = shannonEntropy(label);
  const vowelRatio = (label.match(/[aeiou]/g)?.length ?? 0) / label.length;
  const digitRatio = (label.match(/[0-9]/g)?.length ?? 0) / label.length;
  // Normal English-derived words: entropy ~2.5-3.5, vowel ratio ~0.35-0.5.
  // High entropy + low vowel ratio + digits mixed in is the classic
  // algorithmically-generated-string signature.
  let score = 0;
  if (entropy > 3.6) score += 0.4;
  if (vowelRatio < 0.25) score += 0.3;
  if (digitRatio > 0.15) score += 0.2;
  if (label.length > 20) score += 0.1;
  score = Math.min(1, score);
  return { heuristic: true, score: Math.round(score * 100) / 100, likely: score >= 0.6, entropy: Math.round(entropy * 100) / 100 };
}

// A small curated sample of well-known disposable-email/free-dynamic-DNS
// domains -- not exhaustive, deliberately labeled as such.
const DISPOSABLE_SAMPLE = new Set([
  "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
  "yopmail.com", "trashmail.com", "throwawaymail.com", "fakeinbox.com",
  "getnada.com", "sharklasers.com",
]);
const DYNAMIC_DNS_SUFFIXES = ["duckdns.org", "no-ip.com", "ddns.net", "dyndns.org", "freedynamicdns.org"];

export function checkParkedOrDisposable(domain) {
  const lower = domain.toLowerCase();
  const disposable = DISPOSABLE_SAMPLE.has(lower);
  const dynamicDns = DYNAMIC_DNS_SUFFIXES.some((suffix) => lower.endsWith(suffix));
  return {
    heuristic: true,
    disposable,
    dynamicDns,
    note: "Checked against a small curated sample list, not a live feed -- a 'false' result means 'not in our sample', not 'confirmed legitimate'.",
  };
}
