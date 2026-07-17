// Best-effort full-article-text fetch, built specifically for AI
// Summarization (server/aiThreatSummary.js). Every other extraction job in
// this app (server/combinedExtraction.js) deliberately works from just the
// RSS title+summary -- fine for pulling out a malware/actor/victim *name*,
// which usually does appear in a headline or teaser. AI Summarization's
// brief is different: it's required to preserve specific detection rules,
// hunting queries, exact configs, and step-by-step exploitation mechanics,
// none of which a ~200-400 character RSS blurb ever contains. Confirmed
// live: a Datadog Security Labs report on CVE-2026-31431 came back with
// detection engineering, hunting queries, IR guidance, patch info, and all
// four role takeaways as empty/"Not Reported" -- not because the model
// hallucinated or failed, but because it was only ever given a 271-
// character teaser while the real article (19,774 characters) had a full
// 4-stage SECL detection rule chain, working hunting queries, and a 5-point
// remediation list sitting right there in the page. This fetches that page
// so the model actually has something to extract from.
//
// No HTML parser/DOMParser exists in Node (same constraint noted in
// server/lib/rss.js) -- this uses the same pragmatic regex-strip approach,
// not a full readability algorithm. Blog/article pages are far less
// structured than RSS XML, so this cannot be as precise as rss.js's tag
// extraction; it accepts some leading/trailing chrome (nav links, cookie
// banners) in exchange for never needing a new dependency.
import { fetchText } from "./http.js";
import { withRetry } from "./retry.js";

// ~4 chars/token for English prose -- 14,000 chars is roughly 3,500 tokens.
// Sized to comfortably fit most vendor/CISA technical write-ups in full
// (confirmed live: the Datadog CVE-2026-31431 post's entire substantive
// body -- exploit mechanics, detection rules, hunting queries, conclusion --
// fits within this budget; only trailing boilerplate like "Related
// Content"/job listings gets cut) while leaving headroom in the model's
// context window (see num_ctx in aiThreatSummary.js) for the system prompt,
// verified CVE/technique data, and a large structured JSON response.
const MAX_ARTICLE_CHARS = 20_000;
const MIN_USEFUL_CHARS = 200; // below this, the fetch likely hit a paywall/consent wall, not real content

// Marks where the real article body reliably ends across most blog
// platforms -- confirmed live on the Datadog page: everything past
// "Related Content" is a recommended-posts widget and an unrelated job
// board, not article text. Cutting here (when found) keeps the character
// budget spent entirely on substance instead of splitting it with
// boilerplate that would otherwise eat into MAX_ARTICLE_CHARS.
const TRAILING_BOILERPLATE_MARKERS = [
  /related (content|posts|articles)/i,
  /you (might|may) also like/i,
  /recommended for you/i,
  /subscribe to (the|our)/i,
];

function trimTrailingBoilerplate(text) {
  let cutAt = text.length;
  for (const marker of TRAILING_BOILERPLATE_MARKERS) {
    const match = text.match(marker);
    if (match && match.index < cutAt) cutAt = match.index;
  }
  return text.slice(0, cutAt).trim();
}

const HTML_ENTITIES = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  "#39": "'",
  apos: "'",
  nbsp: " ",
};

function decodeEntities(text) {
  return text
    .replace(/&(amp|lt|gt|quot|#39|apos|nbsp);/g, (_, name) => HTML_ENTITIES[name])
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/** Strips the tag families that are almost never the actual article body (nav chrome, scripts, embedded styles/class soup) before falling back to a blanket tag strip for what's left. */
function htmlToText(html) {
  const stripped = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<nav[\s\S]*?<\/nav>/gi, " ")
    .replace(/<header[\s\S]*?<\/header>/gi, " ")
    .replace(/<footer[\s\S]*?<\/footer>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]+>/g, "\n");

  return decodeEntities(stripped)
    .split("\n")
    .map((line) => line.trim())
    // Drops the Tailwind-style arbitrary-variant class soup that leaks through
    // when a class/style attribute value ends up outside an actual tag match
    // (confirmed live on the Datadog page: `[&_input]:proportional-nums...`)
    // -- a real sentence has spaces; a class list is one unbroken token run.
    .filter((line) => line && !(line.length > 60 && !line.includes(" ")))
    .join("\n");
}

/**
 * Fetches `url` and returns its plain-text article body, capped to
 * MAX_ARTICLE_CHARS. Returns null (never throws) on any failure -- timeout,
 * non-2xx, paywall/consent-wall stub, or a page too short to be real
 * content -- so a single blocked/slow source falls back to the caller's
 * existing title+summary behavior instead of failing an entire batch cycle.
 */
export async function fetchArticleText(url, source) {
  try {
    const html = await withRetry(() => fetchText(url, { source: `article-text:${source}`, timeoutMs: 20_000 }), {
      retries: 1,
      baseDelayMs: 1000,
    });
    const text = trimTrailingBoilerplate(htmlToText(html));
    if (text.length < MIN_USEFUL_CHARS) return null;
    return text.slice(0, MAX_ARTICLE_CHARS);
  } catch {
    return null;
  }
}
