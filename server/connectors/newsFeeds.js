import { fetchText } from "../lib/http.js";
import { parseFeed } from "../lib/rss.js";

// A generic Node fetch (no User-Agent at all) gets a flat 403 from Sucuri's
// WAF, confirmed live -- but confirmed live the opposite way too: sending
// this same browser UA to every feed broke BleepingComputer, which had been
// working fine with no UA at all and instead 403s when it sees a browser-
// looking one (its WAF apparently flags stale/generic Chrome UA strings
// specifically, rather than the absence of one). So this is opt-in per feed
// (see the `headers` field on individual FEEDS entries below), not applied
// blanket -- there's no single UA setting that satisfies both, and each
// publisher's WAF is a black box from the outside.
const BROWSER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

// All free, keyless feeds -- a mix of RSS 2.0/1.0 (<item>-based) and Atom 1.0
// (<entry>-based); server/lib/rss.js#parseFeed auto-detects which and parses
// accordingly (Atom support added specifically to stop excluding real feeds
// like Schneier on Security and The Register purely on format). Widened from 4 to 15 sources so no single publisher's
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
// would dilute signal rather than add it). AWS Security Bulletins (confirmed
// live at the /rss/feed/ path -- the more obvious /rss/ path serves an HTML
// app shell, not XML, despite returning 200) and Palo Alto Networks Security
// Advisories (confirmed live, distinct from the Unit 42 threat-research feed
// already above -- these are CVE-style product advisories, e.g. "CVE-2026-...
// PAN-OS: ... (Severity: HIGH)" right in the title) add cloud/vendor product
// advisory coverage, a gap next to the threat-research and government-CERT
// feeds already here. Neither is added to MAJOR_VENDOR_SOURCES below --
// that set is specifically threat-research blogs, and these are vendor
// patch/product advisories, closer in kind to CISA's advisories than to
// Talos/Unit 42 research. Google Threat Analysis Group's blog was also
// evaluated and dropped: every RSS URL variant 404s and the blog's own page
// has no discoverable feed `<link>` tag -- its dedicated feed appears to no
// longer exist (its threat-intel content is likely folded into the "Google
// Threat Intelligence" feed already tracked above).
//
// Widened again from 34 to 74 sources (driven by a "get to 100 total
// dashboard sources" goal) after adding Atom support to server/lib/rss.js.
// Every URL below was fetched and confirmed live with real parsed items
// before being added -- same discipline as everything above. Also
// confirmed live but deliberately NOT added, for quality/relevance reasons
// rather than technical failure: ZDNet's "security" tag feed (sampled
// items were general consumer-tech content -- a Fitbit review, a Best Buy
// TV deal -- not security news, the tag appears mistagged on ZDNet's end);
// IT Security Guru (roughly half sponsored/PR-adjacent posts, same
// rejection reason as Proofpoint above); vpnMentor and Comparitech (both
// consumer VPN/privacy content, off-topic, and Comparitech's feed was
// serving French-language items); BankInfoSecurity/DataBreachToday (ISMG's
// two sites syndicate the same top stories and neither feed exposes a
// parseable date field). Confirmed dead/unreachable and skipped: Zscaler,
// Trellix, Bitdefender Labs, Group-IB, Akamai's dedicated security tag,
// Dragos, Claroty, Nozomi Networks, NCSC-NL, ENISA, CERT NZ, Anomali,
// Censys, HackerOne, Cyware (all 404 on every URL pattern tried); Volexity,
// NCC Group Research, PortSwigger Daily Swig, WithSecure Labs, Avast
// Decoded, Bugcrowd (all serve an HTML shell at their /feed path instead of
// XML, likely behind the same kind of WAF/JS-rendered-page issue as Sophos
// above); Intezer (the /feed/ path is WordPress's *comments* feed, not
// posts, and is empty); Cybernews (403); SC World and Naked Security
// (still returning empty/blocked, same as previously confirmed). CERT-FR's
// "alerte" category feed was tried alongside its "avis" feed below and
// dropped -- confirmed live its most recent entry is from 2023, i.e. no
// longer actively published, while "avis" is current. BSI (Germany)'s
// CERT-Bund feed is confirmed live and current (250 entries) but was left
// out since every title is German-language, which would read as broken/
// mistranslated noise in an otherwise all-English feed list.
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
  { source: "AWS Security Bulletins", url: "https://aws.amazon.com/security/security-bulletins/rss/feed/" },
  { source: "Palo Alto Security Advisories", url: "https://security.paloaltonetworks.com/rss.xml" },

  // -- Government/CERT advisories --
  { source: "CERT-EU", url: "https://cert.europa.eu/publications/security-advisories-rss" },
  { source: "CERT-FR (ANSSI)", url: "https://www.cert.ssi.gouv.fr/avis/feed/" },
  { source: "Canadian Centre for Cyber Security", url: "https://www.cyber.gc.ca/webservice/en/rss/alerts" },

  // -- Major vendor / security-firm threat research (see MAJOR_VENDOR_SOURCES below) --
  { source: "Huntress", url: "https://www.huntress.com/blog/rss.xml" },
  { source: "Cybereason", url: "https://www.cybereason.com/blog/rss.xml" },
  { source: "Wiz Research", url: "https://www.wiz.io/blog/rss.xml" },
  { source: "GreyNoise Labs", url: "https://www.greynoise.io/blog/rss.xml" },
  { source: "Bishop Fox", url: "https://bishopfox.com/blog/rss.xml" },
  { source: "Trail of Bits", url: "https://blog.trailofbits.com/feed/" },
  { source: "Tenable", url: "https://www.tenable.com/blog/feed" },
  { source: "Qualys", url: "https://blog.qualys.com/feed" },
  { source: "Orca Security", url: "https://orca.security/resources/blog/feed/" },
  { source: "Praetorian", url: "https://www.praetorian.com/blog/feed/" },
  { source: "Datadog Security Labs", url: "https://securitylabs.datadoghq.com/rss/feed.xml" },

  // -- Broader vendor blogs (real signal, mixed with non-security posts -- same tradeoff already accepted for Microsoft Security above) --
  { source: "Akamai", url: "https://www.akamai.com/blog/rss.xml" },
  { source: "Snyk", url: "https://snyk.io/blog/feed/" },
  { source: "Cloudflare", url: "https://blog.cloudflare.com/tag/security/rss/" },

  // -- Consumer-security / detection vendors --
  { source: "Emsisoft", url: "https://blog.emsisoft.com/en/feed/" },
  { source: "Sucuri", url: "https://blog.sucuri.net/feed", headers: { "User-Agent": BROWSER_USER_AGENT } },
  { source: "Wordfence", url: "https://www.wordfence.com/blog/feed/" },
  { source: "ThreatFabric", url: "https://www.threatfabric.com/blogs/rss.xml" },
  { source: "Cofense", url: "https://cofense.com/feed/" },
  { source: "Shodan Blog", url: "https://blog.shodan.io/feed/" },

  // -- Independent researchers / small specialist blogs --
  { source: "Objective-See", url: "https://objective-see.org/rss.xml" },
  { source: "Malware Traffic Analysis", url: "https://www.malware-traffic-analysis.net/blog-entries.rss" },
  { source: "GitHub Security Lab", url: "https://github.blog/tag/github-security-lab/feed/" },

  // -- Journalism / aggregators (Atom feeds, unlocked by server/lib/rss.js's new parseFeed) --
  { source: "Schneier on Security", url: "https://www.schneier.com/feed/atom/" },
  { source: "The Register", url: "https://www.theregister.com/security/headlines.atom" },
  { source: "Reddit r/netsec", url: "https://www.reddit.com/r/netsec/.rss" },

  // -- Journalism / aggregators (RSS) --
  { source: "Security Affairs", url: "https://securityaffairs.com/feed" },
  { source: "Troy Hunt", url: "https://www.troyhunt.com/rss/" },
  { source: "Hackread", url: "https://www.hackread.com/feed/" },
  { source: "GBHackers", url: "https://gbhackers.com/feed/" },
  { source: "The Cyber Express", url: "https://thecyberexpress.com/feed/" },
  { source: "DataBreaches.net", url: "https://databreaches.net/feed/" },
  { source: "TechCrunch Security", url: "https://techcrunch.com/category/security/feed/" },
  { source: "Ars Technica Security", url: "https://arstechnica.com/tag/security/feed/" },
  { source: "CSO Online", url: "https://www.csoonline.com/feed" },
  { source: "The CyberWire", url: "https://thecyberwire.com/feeds/rss.xml" },
  { source: "Help Net Security", url: "https://www.helpnetsecurity.com/feed/" },
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
  "Huntress",
  "Cybereason",
  "Wiz Research",
  "GreyNoise Labs",
  "Bishop Fox",
  "Trail of Bits",
  "Tenable",
  "Qualys",
  "Orca Security",
  "Praetorian",
  "Datadog Security Labs",
]);

// Widened from 15 -- the Threat Actor Profile feature matches this pool
// against actor names/aliases (server/actorProfile.js), and a small window
// meant most actors never had a chance of a match even when real coverage
// existed somewhere in that publisher's recent history.
const ITEMS_PER_SOURCE = 40;

// Not every publisher's timestamp format is one `new Date()` can parse --
// confirmed live that CERT-EU's "13:55:39 CEST"-style timezone abbreviation
// (as opposed to a numeric offset or GMT/UTC) produces an Invalid Date,
// which then threw inside .toISOString() and took CERT-EU's entire fetch
// down as "failed" every cycle. Falling back to "now" for an unparseable
// date loses that one item's real recency, but that's strictly better than
// losing the whole source.
function parseDate(pubDate) {
  if (!pubDate) return new Date();
  const parsed = new Date(pubDate);
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
}

function toNewsItems(xml, source) {
  return parseFeed(xml).map((item) => ({
    id: item.link,
    title: item.title,
    link: item.link,
    source,
    publishedDate: parseDate(item.pubDate).toISOString(),
  }));
}


/**
 * All security-news RSS/Atom feeds share one connector (one sync cycle)
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
      FEEDS.map(async ({ source, url, headers }) => {
        const xml = await fetchText(url, { source, headers });
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
