import { fetchText } from "../lib/http.js";
import { parseRss } from "../lib/rss.js";

// All free, keyless, standard RSS 2.0 (<item>-based) feeds -- Atom-only feeds
// (e.g. Schneier on Security, The Register) are deliberately excluded since
// server/lib/rss.js is a small regex parser that only understands <item>,
// not Atom's <entry>. Widened from 4 to 15 sources so no single publisher's
// posting cadence dominates the merged, recency-sorted list. SC Media was
// tried and dropped -- confirmed live that scmagazine.com/feed now 301s to
// scworld.com/feed (rebranded), which returns a Cloudflare-protected 403
// HTML page instead of XML, not a usable feed. The DFIR Report, Red Canary
// and Cisco Talos (all confirmed live as standard WordPress RSS) were added
// specifically to improve incident-response/threat-research coverage for
// the Threat Actor Profile feature's news matching. CISA ICS Advisories and
// UK NCSC (both confirmed live, standard RSS 2.0 with real pubDate values)
// add government-CERT coverage beyond CISA's general advisories feed.
// CrowdStrike, Unit 42, Recorded Future, Google Threat Intelligence and
// Microsoft Security (all confirmed live, standard RSS 2.0) add major vendor
// threat-research coverage for actor-profile enrichment. Mandiant's own blog
// now redirects into Google Cloud's site -- its threat research is published
// under the same "Google Threat Intelligence" feed below, so it isn't listed
// separately. Microsoft's feed is its general Security blog (no separate
// public feed exists scoped to just Microsoft Threat Intelligence/MSTIC), so
// it also carries non-threat-intel posts (e.g. product/compliance content).
// SentinelLabs, Rapid7, Check Point Research, ESET (WeLiveSecurity), Kaspersky
// Securelist, Elastic Security Labs and FortiGuard Labs (all confirmed live,
// standard RSS 2.0) round out major-vendor threat-research coverage.
// FortiGuard's feed lives on FeedBurner's legacy feeds.fortinet.com domain,
// found via Fortinet's own RSS directory page -- the more obvious
// fortinet.com/blog/threat-research/rss guess 404s. CISA Malware Analysis
// Reports and CISA Cybersecurity Advisories (confirmed live, distinct content
// from the general "CISA"/all.xml feed above -- MARs are per-sample technical
// writeups, CSAs are joint/agency threat advisories) add two more CISA
// categories beyond the general and ICS-specific ones already present.
// CISA's alerts.xml (a feed of "N vulnerabilities added to KEV" announcement
// posts) was deliberately skipped -- redundant with the KEV catalog already
// tracked directly and fully via the cisa-kev connector. JPCERT/CC's English
// alerts feed (confirmed live, RSS 1.0/RDF using <dc:date> instead of
// <pubDate> -- see server/lib/rss.js's fallback for that) adds Japan's
// national CERT to the government-advisory coverage already here from
// CISA/UK NCSC. Two other national-CERT candidates were evaluated and
// dropped: ACSC (Australia)'s RSS endpoints connection-refused outright from
// this environment, the same signature as Sophos below (likely a WAF/IP
// range block, not a missing feed); and FBI/IC3's cyber-alerts RSS returned
// a Cloudflare bot-check challenge page (HTTP 403) instead of XML. Deliberately NOT added:
// Secureworks (acquired by Sophos in 2025, its domain now just redirects to
// sophos.com), Sophos X-Ops (every sophos.com/news.sophos.com URL refused the
// connection outright from this environment -- likely a WAF blocking the
// whole IP range, not a missing feed), Trend Micro Research (no discoverable
// RSS -- old FeedBurner URL is dead and no auto-discovery link tag exists on
// its current research pages), and Proofpoint Threat Insight (no dedicated
// feed exists; the only public RSS is /us/rss.xml, which is a general
// newsroom/press-release feed -- confirmed live it's roughly half PR
// announcements like new product launches, not threat research, so adding it
// would dilute signal rather than add it).
const FEEDS = [
  { source: "CISA", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { source: "CISA ICS Advisories", url: "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml" },
  { source: "CISA Malware Analysis Reports", url: "https://www.cisa.gov/cybersecurity-advisories/analysis-reports.xml" },
  { source: "CISA Cybersecurity Advisories", url: "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml" },
  { source: "UK NCSC", url: "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml" },
  { source: "JPCERT/CC", url: "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf" },
  { source: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { source: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { source: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" },
  { source: "Dark Reading", url: "https://www.darkreading.com/rss.xml" },
  { source: "SecurityWeek", url: "https://www.securityweek.com/feed/" },
  { source: "Infosecurity Magazine", url: "https://www.infosecurity-magazine.com/rss/news/" },
  { source: "The Record", url: "https://therecord.media/feed" },
  { source: "CyberScoop", url: "https://cyberscoop.com/feed/" },
  { source: "Malwarebytes Labs", url: "https://www.malwarebytes.com/blog/feed/index.xml" },
  { source: "SANS ISC", url: "https://isc.sans.edu/rssfeed_full.xml" },
  { source: "Graham Cluley", url: "https://grahamcluley.com/feed/" },
  { source: "The DFIR Report", url: "https://thedfirreport.com/feed/" },
  { source: "Red Canary", url: "https://redcanary.com/blog/feed/" },
  { source: "Cisco Talos", url: "https://blog.talosintelligence.com/rss/" },
  { source: "CrowdStrike", url: "https://www.crowdstrike.com/blog/feed/" },
  { source: "Unit 42", url: "https://unit42.paloaltonetworks.com/feed/" },
  { source: "Recorded Future", url: "https://www.recordedfuture.com/feed" },
  { source: "Google Threat Intelligence", url: "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/" },
  { source: "Microsoft Security", url: "https://www.microsoft.com/en-us/security/blog/feed/" },
  { source: "SentinelLabs", url: "https://www.sentinelone.com/labs/feed/" },
  { source: "Rapid7", url: "https://www.rapid7.com/rss.xml" },
  { source: "Check Point Research", url: "https://research.checkpoint.com/feed/" },
  { source: "ESET Research", url: "https://www.welivesecurity.com/en/rss/feed/" },
  { source: "Kaspersky Securelist", url: "https://securelist.com/feed/" },
  { source: "Elastic Security Labs", url: "https://www.elastic.co/security-labs/rss/feed.xml" },
  { source: "FortiGuard Labs", url: "https://feeds.fortinet.com/fortinet/blog/threat-research" },
];

/**
 * The commercial security-vendor threat-research feeds above (per the
 * "major vendor threat-research coverage" grouping in the comment block at
 * the top of this file), as opposed to journalism/aggregator outlets
 * (BleepingComputer, The Hacker News, Krebs, SANS ISC's daily podcast, etc.)
 * or government/CERT advisories (CISA, UK NCSC). Exported so
 * server/dailySummary.js can prefer a real vendor report over a
 * higher-frequency but lower-signal source when picking "today's" news
 * highlight, and mirrored (kept in sync manually -- this app has no shared
 * client/server code layer) by `MAJOR_VENDOR_SOURCES` in
 * src/components/dashboard/SecurityNews.tsx for the "Major Vendors
 * (grouped)" filter option there.
 */
export const MAJOR_VENDOR_SOURCES = new Set([
  "Cisco Talos",
  "CrowdStrike",
  "Unit 42",
  "Recorded Future",
  "Google Threat Intelligence",
  "Microsoft Security",
  "SentinelLabs",
  "Rapid7",
  "Check Point Research",
  "ESET Research",
  "Kaspersky Securelist",
  "Elastic Security Labs",
  "FortiGuard Labs",
]);

// Widened from 15 -- the Threat Actor Profile feature matches this pool
// against actor names/aliases (server/actorProfile.js), and a small window
// meant most actors never had a chance of a match even when real coverage
// existed somewhere in that publisher's recent history.
const ITEMS_PER_SOURCE = 40;

function toNewsItems(xml, source) {
  return parseRss(xml).map((item) => ({
    id: item.link,
    title: item.title,
    link: item.link,
    source,
    publishedDate: item.pubDate ? new Date(item.pubDate).toISOString() : new Date().toISOString(),
  }));
}

/**
 * All four security-news RSS feeds share one connector (one sync cycle)
 * since they're the same shape and none need frequent refresh -- but each
 * feed's success/failure is tracked individually in `sources` so a single
 * dead feed doesn't hide the others' health status.
 */
export default {
  id: "news",
  label: "Security News",
  intervalMs: 15 * 60 * 1000,
  async fetch() {
    const results = await Promise.allSettled(
      FEEDS.map(async ({ source, url }) => {
        const xml = await fetchText(url, { source });
        return toNewsItems(xml, source);
      }),
    );

    const items = [];
    const sources = {};
    results.forEach((result, i) => {
      const { source } = FEEDS[i];
      if (result.status === "fulfilled") {
        items.push(...result.value.slice(0, ITEMS_PER_SOURCE));
        sources[source] = { ok: true };
      } else {
        sources[source] = { ok: false, error: result.reason?.message ?? String(result.reason) };
      }
    });

    items.sort((a, b) => new Date(b.publishedDate).getTime() - new Date(a.publishedDate).getTime());
    return { items, sources };
  },
};
