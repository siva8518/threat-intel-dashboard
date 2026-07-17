import { fetchText } from "../lib/http.js";
import { parseFeed } from "../lib/rss.js";
import { withRetry } from "../lib/retry.js";

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
// Widened again from 74 to 136 sources (driven by a "get toward 200 total
// dashboard sources" goal). Every URL below was fetched live and confirmed
// to return real, current RSS/Atom/RDF with parseable items -- same
// discipline as everything above. A large batch of plausible-looking
// candidates was tried and confirmed dead/unreachable/off-topic in this
// pass and deliberately NOT added: Sysdig, Invicti, Doyensec, SpecterOps,
// Positive Technologies, CyberArk, Trustwave SpiderLabs, SecurityScorecard,
// Patchstack, Shadowserver, Fortra, WatchGuard, Malwation, Group-IB, Sansec,
// NetSPI, Binary Defense, eSentire, Arctic Wolf, Kroll, Kudelski Security,
// SEC Consult, SANS Institute's main blog (distinct from SANS ISC already
// tracked), Offensive Security, HackTheBox, Intigriti, Team Cymru's blog
// (its IP/ASN lookup is already used directly as an IOC-search lookup),
// Duo Security, LevelBlue, Socket, Cycode, Apiiro, StackHawk, Semgrep,
// Truffle Security, SpyCloud, Silent Push, Hunt.io, ZeroFox, Deepfence,
// Bitdefender's business-insights blog, Red Hat's security-scoped feed
// (its general /blog feed worked and is used instead), JumpCloud, Cyjax,
// Malcore (serves Vietnamese-language AMP HTML, not the expected feed),
// Nucleus Security, and IBM Security Intelligence (its feed and FeedBurner
// mirror both now redirect to a plain HTML page, no XML) -- all confirmed
// dead/off-topic outright. Digital Shadows and InfoSec Institute both
// connection-timed-out from this environment, the same signature as
// Sophos/ACSC's own outright-refused connections noted above -- likely
// blocked, not missing. Tripwire's State of Security blog returns real RSS
// to a plain curl check but consistently 403s this app's own server-side
// fetch even with the same browser User-Agent header added (the same
// WAF-fingerprinting gap already documented for Sophos/ACSC) -- dropped
// rather than left in as permanently "offline" in the health panel.
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
  // SonicWall PSIRT (confirmed live -- the /rss-feeds landing page is a JS
  // SPA shell with no static feed link; the actual XML is served from a
  // separate API host, only discoverable by inspecting the rendered page's
  // anchor hrefs). Same "vendor product/patch advisory" category as the two
  // feeds above, not threat-research -- so also not added to
  // MAJOR_VENDOR_SOURCES below, for the same reason those two aren't.
  { source: "SonicWall PSIRT", url: "https://psirtapi.global.sonicwall.com/api/v1/feed/rss.xml" },

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

  // -- Additional major vendor / security-firm threat research --
  { source: "Palo Alto Networks Blog", url: "https://blog.paloaltonetworks.com/feed/" },
  { source: "Netskope", url: "https://www.netskope.com/blog/feed" },
  { source: "Darktrace", url: "https://darktrace.com/blog/rss.xml" },
  { source: "Vectra AI", url: "https://www.vectra.ai/blog/rss.xml" },
  { source: "Corelight", url: "https://corelight.com/blog/rss.xml" },
  { source: "Barracuda", url: "https://blog.barracuda.com/feed/" },
  { source: "Cisco Security Blog", url: "https://blogs.cisco.com/security/feed" },

  // -- AppSec / cloud / identity / attack-surface vendors --
  { source: "Veracode", url: "https://www.veracode.com/blog/feed" },
  { source: "Detectify", url: "https://blog.detectify.com/feed" },
  { source: "Varonis", url: "https://www.varonis.com/blog/rss.xml" },
  { source: "Imperva", url: "https://www.imperva.com/blog/feed/" },
  { source: "F5 Labs", url: "https://www.f5.com/labs/rss-feeds/all.xml" },
  { source: "Aqua Security", url: "https://blog.aquasec.com/rss.xml" },
  { source: "Cequence Security", url: "https://www.cequence.ai/blog/feed/" },
  { source: "Salt Security", url: "https://salt.security/blog/rss.xml" },
  { source: "Wallarm", url: "https://lab.wallarm.com/feed/" },
  { source: "WPScan", url: "https://wpscan.com/blog/feed/" },
  { source: "Contrast Security", url: "https://www.contrastsecurity.com/security-influencers/rss.xml" },
  { source: "Okta Security", url: "https://sec.okta.com/rss.xml" },
  { source: "Bitsight", url: "https://www.bitsight.com/blog/rss.xml" },
  { source: "UpGuard", url: "https://www.upguard.com/blog/rss.xml" },
  { source: "NopSec", url: "https://nopsec.com/feed/" },
  { source: "GuidePoint Security", url: "https://www.guidepointsecurity.com/blog/feed/" },
  { source: "Immersive Labs", url: "https://www.immersivelabs.com/resources/blog/rss.xml" },
  { source: "Menlo Security", url: "https://www.menlosecurity.com/blog/rss.xml" },
  { source: "KnowBe4", url: "https://blog.knowbe4.com/rss.xml" },
  { source: "CrowdSec", url: "https://crowdsec.net/blog/rss.xml" },
  { source: "Netenrich", url: "https://netenrich.com/blog/rss.xml" },

  // -- Offensive security / penetration-testing research --
  { source: "PortSwigger Research", url: "https://portswigger.net/research/rss" },
  { source: "Zero Day Initiative", url: "https://www.thezdi.com/blog?format=rss" },
  { source: "MDSec", url: "https://www.mdsec.co.uk/feed/" },
  { source: "Rhino Security Labs", url: "https://rhinosecuritylabs.com/feed/" },
  { source: "Include Security", url: "https://blog.includesecurity.com/feed/" },
  { source: "Horizon3.ai", url: "https://horizon3.ai/feed/" },
  { source: "watchTowr Labs", url: "https://labs.watchtowr.com/rss/" },
  { source: "Assetnote", url: "https://blog.assetnote.io/feed.xml" },
  { source: "NVISO Labs", url: "https://blog.nviso.eu/feed/" },
  { source: "Pentest Partners", url: "https://www.pentestpartners.com/security-blog/feed/" },
  { source: "Nettitude", url: "https://labs.nettitude.com/feed/" },
  { source: "Synack", url: "https://www.synack.com/blog/feed/" },
  { source: "Didier Stevens", url: "https://blog.didierstevens.com/feed/" },
  { source: "0patch Blog", url: "https://blog.0patch.com/feeds/posts/default" },
  { source: "VirusBulletin", url: "https://www.virusbulletin.com/rss" },

  // -- Threat intelligence platforms / malware sandboxes --
  { source: "Any.run", url: "https://any.run/cybersecurity-blog/feed/" },
  { source: "VMRay", url: "https://www.vmray.com/blog/feed/", headers: { "User-Agent": BROWSER_USER_AGENT } },
  { source: "KELA", url: "https://www.kelacyber.com/blog/feed/" },
  { source: "Intel 471", url: "https://intel471.com/blog/feed" },
  { source: "Sublime Security", url: "https://sublime.security/blog/rss.xml" },

  // -- Software supply chain / DevSecOps security --
  { source: "Sonatype", url: "https://blog.sonatype.com/rss.xml" },
  { source: "JFrog", url: "https://jfrog.com/blog/feed/" },
  { source: "Chainguard", url: "https://www.chainguard.dev/unchained/rss.xml" },
  { source: "Legit Security", url: "https://www.legitsecurity.com/blog/rss.xml" },
  { source: "GitGuardian", url: "https://blog.gitguardian.com/rss/" },
  { source: "Uptycs", url: "https://www.uptycs.com/blog/rss.xml" },

  // -- Platform / OS vendor security blogs (mixed with non-security posts, same tradeoff already accepted for Microsoft Security above) --
  { source: "Red Hat Blog", url: "https://www.redhat.com/en/rss/blog" },
  { source: "Ubuntu Security Notices", url: "https://ubuntu.com/security/notices/rss.xml" },
  { source: "Google Online Security Blog", url: "https://security.googleblog.com/feeds/posts/default" },
  { source: "Google Project Zero", url: "https://googleprojectzero.blogspot.com/feeds/posts/default" },
  { source: "Mozilla Security Blog", url: "https://blog.mozilla.org/security/feed/" },
  { source: "GitHub Blog Security", url: "https://github.blog/tag/security/feed/" },

  // -- Additional journalism / aggregators --
  { source: "Wired Security", url: "https://www.wired.com/feed/category/security/latest/rss" },
  { source: "TechRadar Pro Security", url: "https://www.techradar.com/feeds/tag/security" },

  // -- Widened a third time from 136 to 164 sources (same "toward 200 total
  // dashboard sources" goal), same live-fetch-and-confirm discipline as both
  // prior passes. Deliberately NOT added this round, all confirmed dead/
  // blocked/off-topic: Truesec, Sekoia, Cyfirma, HYAS, Resecurity,
  // Cybersixgill, ThreatConnect, ThreatQuotient, Forescout, Morphisec,
  // Cynet, Tanium, SailPoint, Axonius, Cado Security, Push Security,
  // Automox, Jamf, Kolide, ISC2, CIS, ExtraHop, Netography, Webroot, McAfee,
  // Comodo, Bitdefender's consumer blog, NSA (Akamai-fronted, 403s every
  // UA), Trustwave (tried three different URL patterns across two passes),
  // NCC Group Research (HTML shell at every path tried), Analyst1, Nisos,
  // BinaryEdge, ImmuniWeb, Cymulate, SafeBreach, AttackIQ, Picus Security,
  // Censys, BeyondTrust, Delinea, Forcepoint, Egress, Mimecast, Gigamon,
  // iboss, CyberArk (three attempts, three different paths, all 404),
  // Vade Secure, NETSCOUT, Corero, Fastly's security tag, Recorded Future's
  // separate Insikt-branded feed (redundant with the main Recorded Future
  // feed already tracked above anyway), and Socket (a duplicate of the
  // already-rejected "Socket" from the prior pass under a different path).
  // N-able also confirmed live via a plain curl check but, like Tripwire in
  // the prior pass, consistently 403s this app's own server-side fetch even
  // with the browser User-Agent header added -- a structural WAF block, not
  // a missing feed -- so it's dropped rather than kept as permanently
  // "offline" in the health panel.
  // -- Threat intel platforms / CTI vendors --
  { source: "SOCRadar", url: "https://socradar.io/feed/" },
  { source: "Cyble", url: "https://cyble.com/blog/feed/" },
  { source: "EclecticIQ", url: "https://blog.eclecticiq.com/rss.xml" },
  { source: "Constella Intelligence", url: "https://constella.ai/blog/feed/" },
  { source: "Silobreaker", url: "https://www.silobreaker.com/blog/feed/" },
  { source: "Cyborg Security", url: "https://www.cyborgsecurity.com/blog/feed/" },
  { source: "Reversing Labs", url: "https://www.reversinglabs.com/blog/rss.xml" },

  // -- Attack-surface management / offensive security --
  { source: "Outpost24", url: "https://outpost24.com/blog/feed/" },
  { source: "Intruder", url: "https://www.intruder.io/blog/rss.xml" },
  { source: "Pentera", url: "https://pentera.io/blog/feed/" },
  { source: "Doyensec", url: "https://blog.doyensec.com/atom.xml" },
  { source: "Permiso", url: "https://permiso.io/blog/rss.xml" },
  { source: "Snort Blog", url: "https://blog.snort.org/feeds/posts/default" },

  // -- Identity / endpoint / MSP security vendors --
  { source: "Ping Identity", url: "https://www.pingidentity.com/en/company/blog.rss.xml" },
  { source: "Ivanti", url: "https://www.ivanti.com/blog/feed" },
  { source: "Field Effect", url: "https://fieldeffect.com/blog/rss.xml" },
  { source: "Blumira", url: "https://www.blumira.com/blog/rss.xml" },

  // -- Network / DDoS security --
  { source: "Cato Networks", url: "https://www.catonetworks.com/blog/feed/" },
  { source: "A10 Networks", url: "https://www.a10networks.com/blog/feed/" },

  // -- Consumer-security / detection vendors --
  { source: "Avira", url: "https://www.avira.com/en/blog/feed" },
  { source: "Panda Security", url: "https://www.pandasecurity.com/en/mediacenter/feed/" },
  { source: "Heimdal Security", url: "https://heimdalsecurity.com/blog/feed/", headers: { "User-Agent": BROWSER_USER_AGENT } },
  { source: "OpenText Security", url: "https://blogs.opentext.com/tag/security/feed/" },

  // -- Government / standards --
  { source: "NIST Cybersecurity Insights", url: "https://www.nist.gov/blogs/cybersecurity-insights/rss.xml" },

  // -- Additional journalism / aggregators --
  { source: "The Last Watchdog", url: "https://www.lastwatchdog.com/feed/" },
  { source: "eSecurity Planet", url: "https://www.esecurityplanet.com/feed/" },
  { source: "Cybersecurity Dive", url: "https://www.cybersecuritydive.com/feeds/news/" },
  { source: "Cyber Security News", url: "https://cybersecuritynews.com/feed/" },
];

/**
 * The commercial security-vendor threat-research feeds above (per the
 * "major vendor threat-research coverage" grouping in the comment block at
 * the top of this file), as opposed to journalism/aggregator outlets
 * (BleepingComputer, The Hacker News, Krebs, SANS ISC's daily podcast, etc.)
 * or government/CERT advisories (CISA, UK NCSC). Mirrored (kept in sync
 * manually -- this app has no shared client/server code layer) by
 * `MAJOR_VENDOR_SOURCES` in
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
  "Palo Alto Networks Blog",
  "Netskope",
  "Darktrace",
  "Vectra AI",
  "Corelight",
  "Barracuda",
  "Cisco Security Blog",
  "Varonis",
  "Imperva",
  "F5 Labs",
  "Aqua Security",
  "Okta Security",
  "Any.run",
  "VMRay",
  "KELA",
  "Intel 471",
  "Synack",
  "SOCRadar",
  "Cyble",
  "Reversing Labs",
  "Pentera",
  "Ivanti",
  "Cato Networks",
]);

// Widened from 15 -- the Threat Actor Profile feature matches this pool
// against actor names/aliases (server/actorProfile.js), and a small window
// meant most actors never had a chance of a match even when real coverage
// existed somewhere in that publisher's recent history.
const ITEMS_PER_SOURCE = 40;

// Not every publisher's timestamp format is one `new Date()` can parse --
// confirmed live that CERT-EU's "13:55:39 CEST"-style timezone abbreviation
// (as opposed to a numeric offset or GMT/UTC, which Date does understand) is
// unrecognized and produces an Invalid Date. An earlier version of this
// function fell back to "now" for any unparseable date -- which stopped the
// crash, but silently stamped CERT-EU's entire archive (advisories spanning
// January through June 2026) as published this exact second, making months-
// old items masquerade as breaking news in the "Breaking · Last 6 hours"
// panel (caught live: a user noticed 2026-001 through 2026-008 all showing
// as "just now"). Normalizing the known European abbreviations to a numeric
// offset first means these parse correctly instead of needing the fallback
// at all; "now" is now only reached for a genuinely unrecognized format.
const TIMEZONE_OFFSETS = { CEST: "+0200", CET: "+0100", EEST: "+0300", EET: "+0200", BST: "+0100" };

// Bitsight's <pubDate> isn't RFC 822 at all -- its CMS stamps each post in
// whatever locale that post was authored/translated in, so the *same feed*
// mixes formats: "Thu, 07/16/2026 - 07:25" (US slash-date) for most posts,
// but "Mo., 29.06.2026 - 08:57" (German dot-date, DD.MM.YYYY) for at least
// one. `new Date()` can't parse either, so every affected article was
// silently falling back to "now" below -- confirmed live this is exactly why
// a real June 24 article ("bitsight-aids-disruption-efforts-on-amadey-
// malware...") kept showing up under a "today" date filter: it got re-
// stamped as the current sync time on every 15-min cycle instead of ever
// showing its real, months-old date. A live audit of all ~165 feeds found
// Bitsight was the only one silently collapsing to "now" this way. Both
// known variants are converted to a parseable ISO-ish string before the
// generic fallback below ever runs; a still-unrecognized format keeps
// falling back to "now" same as before, rather than throwing.
const SLASH_DASH_DATE = /(\d{2})\/(\d{2})\/(\d{4})\s*-\s*(\d{2}):(\d{2})/; // MM/DD/YYYY - HH:MM
const DOT_DASH_DATE = /(\d{2})\.(\d{2})\.(\d{4})\s*-\s*(\d{2}):(\d{2})/; // DD.MM.YYYY - HH:MM

function parseDate(pubDate) {
  if (!pubDate) return new Date();
  const slashMatch = pubDate.match(SLASH_DASH_DATE);
  if (slashMatch) {
    const [, mm, dd, yyyy, hh, min] = slashMatch;
    const parsed = new Date(`${yyyy}-${mm}-${dd}T${hh}:${min}:00Z`);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  const dotMatch = pubDate.match(DOT_DASH_DATE);
  if (dotMatch) {
    const [, dd, mm, yyyy, hh, min] = dotMatch;
    const parsed = new Date(`${yyyy}-${mm}-${dd}T${hh}:${min}:00Z`);
    if (!Number.isNaN(parsed.getTime())) return parsed;
  }
  const abbrMatch = pubDate.match(/ ([A-Z]{2,4})$/);
  const normalized = abbrMatch && TIMEZONE_OFFSETS[abbrMatch[1]] ? pubDate.slice(0, -abbrMatch[1].length) + TIMEZONE_OFFSETS[abbrMatch[1]] : pubDate;
  const parsed = new Date(normalized);
  return Number.isNaN(parsed.getTime()) ? new Date() : parsed;
}

// Feed descriptions are frequently raw HTML (vendor blogs render their dek
// through the same template as the post body) -- strip tags/entities down to
// plain text before this ever reaches the malware-name extractor's prompt
// (server/malwareExtraction.js) or gets cached for the frontend. Capped at
// 600 chars: enough for a full dek/abstract, short enough to keep each
// extraction prompt small.
function cleanSummary(raw) {
  if (!raw) return null;
  const text = raw
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return text ? text.slice(0, 600) : null;
}

function toNewsItems(xml, source) {
  return parseFeed(xml).map((item) => ({
    id: item.link,
    title: item.title,
    link: item.link,
    source,
    publishedDate: parseDate(item.pubDate).toISOString(),
    summary: cleanSummary(item.summary),
  }));
}


// ~200 independently-run RSS servers have some baseline transient failure
// rate (timeout, momentary 5xx, DNS blip) every cycle just by chance -- with
// no per-feed retry and no memory across cycles, that noise alone flips a
// meaningful chunk of the source count "offline" on every 15-min sync, which
// self-heals by the next cycle but reads as a constantly-recurring problem.
// Fixed two ways: each feed gets a couple of quick retries within the same
// cycle (below), and `feedFailureStreak` remembers consecutive failures
// across cycles so a feed only reports offline once it's *actually* been
// down for a while, not after one blip.
const feedFailureStreak = new Map();
const OFFLINE_AFTER_CONSECUTIVE_FAILURES = 2;

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
        const xml = await withRetry(() => fetchText(url, { source, headers }), { retries: 1, baseDelayMs: 500 });
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
        feedFailureStreak.set(source, 0);
      } else {
        const streak = (feedFailureStreak.get(source) ?? 0) + 1;
        feedFailureStreak.set(source, streak);
        sources[source] = {
          ok: streak < OFFLINE_AFTER_CONSECUTIVE_FAILURES,
          error: result.reason?.message ?? String(result.reason),
        };
      }
    });

    // A systemic failure (network down, DNS not yet resolved, the machine
    // just woke from sleep before connectivity came back -- confirmed live:
    // every one of ~165 feeds failed in the same instant right after a
    // sleep/wake gap) looks identical, per-feed, to an ordinary isolated
    // feed blip. The per-feed grace period above (OFFLINE_AFTER_CONSECUTIVE_
    // FAILURES) is deliberately lenient about a single blip so one flaky
    // feed doesn't page anyone -- but that leniency backfires when literally
    // every feed among ~165 independent, geographically-diverse publishers
    // fails in the same cycle: each one's *first* failure this session still
    // reads as "ok" individually, so health showed "163/165 online" while
    // this synced and cached zero items -- exactly what made "Security News
    // is not loading" silently persist for a full cycle with no visible
    // error. Throwing here instead of returning `{ items: [], sources }`
    // routes this through the scheduler's normal retry + graceful-
    // degradation path (server/scheduler.js -> cache.setError, same as
    // every other connector): it retries almost immediately, and if the
    // outage is still ongoing, keeps serving the last-known-good cached
    // items/sources rather than overwriting good data with an empty result.
    // ~165 diverse feeds legitimately producing zero combined items is not a
    // real scenario, so this has no meaningful false-positive risk.
    if (items.length === 0 && FEEDS.length > 0) {
      throw new Error(`news sync produced zero items across all ${FEEDS.length} feeds -- treating as a systemic failure, not genuine "no news"`);
    }

    items.sort((a, b) => new Date(b.publishedDate).getTime() - new Date(a.publishedDate).getTime());
    return { items, sources };
  },
};
