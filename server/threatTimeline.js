// Interactive Threat Timeline: a unified, chronologically-sorted feed of
// individually-dated events across sources already ingested elsewhere in
// this app -- CISA/VulnCheck KEV additions, ransomware.live victim posts,
// MalwareBazaar sample sightings, newly-discovered GitHub repos, and
// notable (critical/high severity) tagged news headlines. Distinct from
// server/todaySecurityEvents.js, which reduces the same kinds of activity
// to same-day *counts* for the Overview tile -- this keeps each event as
// its own dated, clickable row and covers a selectable window (not just
// "today"), which is what an actual timeline needs.
const MAX_EVENTS = 150;
const MAX_PER_TYPE = { kev: 40, ransomware: 40, malware: 30, github: 20, news: 30 };

function withinDays(dateStr, days) {
  if (!dateStr) return false;
  const time = new Date(dateStr).getTime();
  if (Number.isNaN(time)) return false;
  return time >= Date.now() - days * 24 * 60 * 60 * 1000;
}

function pushCapped(byType, event) {
  const list = byType.get(event.type) ?? [];
  list.push(event);
  byType.set(event.type, list);
}

export function buildThreatTimeline(sources, { days = 7 } = {}) {
  const { kevEntries, vulncheckKevEntries, ransomwareCampaigns, threatFeedIocs, githubRepos, newsItems } = sources;
  const byType = new Map();

  for (const e of kevEntries ?? []) {
    if (!withinDays(e.dateAdded, days)) continue;
    pushCapped(byType, {
      id: `kev:${e.cveId}`,
      type: "kev",
      date: e.dateAdded,
      title: `${e.cveId} added to CISA's Known Exploited Vulnerabilities catalog`,
      detail: e.vulnerabilityName ?? null,
      url: `https://nvd.nist.gov/vuln/detail/${e.cveId}`,
      severity: e.ransomwareUse ? "critical" : "high",
      cveId: e.cveId,
      malwareFamily: null,
    });
  }

  // VulnCheck KEV is a separate, larger catalog (see server/connectors/vulncheckKev.js)
  // -- skip any CVE already surfaced above from CISA's own catalog so the
  // same addition doesn't appear twice just because both track it.
  const cisaKevIds = new Set((kevEntries ?? []).map((e) => e.cveId));
  const seenVulncheckCves = new Set();
  for (const e of vulncheckKevEntries ?? []) {
    if (!withinDays(e.dateAdded, days)) continue;
    for (const cveId of e.cveIds ?? []) {
      if (cisaKevIds.has(cveId) || seenVulncheckCves.has(cveId)) continue;
      seenVulncheckCves.add(cveId);
      pushCapped(byType, {
        id: `vulncheck-kev:${cveId}`,
        type: "kev",
        date: e.dateAdded,
        title: `${cveId} added to VulnCheck's Known Exploited Vulnerabilities catalog`,
        detail: e.vulnerabilityName ?? null,
        url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
        severity: e.ransomwareUse ? "critical" : "high",
        cveId,
        malwareFamily: null,
      });
    }
  }

  for (const c of ransomwareCampaigns ?? []) {
    if (!withinDays(c.discoveredDate, days)) continue;
    pushCapped(byType, {
      id: `ransomware:${c.id}`,
      type: "ransomware",
      date: c.discoveredDate,
      title: `${c.group} posted a new victim: ${c.victim}`,
      detail: c.sector ? `${c.sector} · ${c.country}` : c.country,
      url: c.sourceUrl,
      severity: "high",
      cveId: null,
      malwareFamily: null,
    });
  }

  // MalwareBazaar sightings are the noisiest source by far -- aggregated to
  // one event per family per day (with a count) rather than one row per raw
  // sample, or the timeline would be almost entirely malware-hash noise.
  const malwareByDay = new Map(); // `${day}:${family}` -> count
  for (const ioc of threatFeedIocs ?? []) {
    if (ioc.source !== "MalwareBazaar" || !ioc.malwareFamily || ioc.malwareFamily === "Unknown") continue;
    if (!withinDays(ioc.firstSeen, days)) continue;
    const day = ioc.firstSeen.slice(0, 10);
    for (const family of ioc.malwareFamily.split(",").map((f) => f.trim()).filter(Boolean)) {
      const key = `${day}:${family}`;
      malwareByDay.set(key, (malwareByDay.get(key) ?? 0) + 1);
    }
  }
  for (const [key, count] of malwareByDay) {
    const [day, family] = key.split(":");
    pushCapped(byType, {
      id: `malware:${key}`,
      type: "malware",
      date: new Date(`${day}T00:00:00Z`).toISOString(),
      title: `${count} new ${family} sample${count === 1 ? "" : "s"} seen`,
      detail: null,
      url: null,
      severity: "medium",
      cveId: null,
      malwareFamily: family,
    });
  }

  for (const r of githubRepos ?? []) {
    if (!withinDays(r.discoveredAt, days)) continue;
    pushCapped(byType, {
      id: `github:${r.fullName}`,
      type: "github",
      date: r.discoveredAt,
      title: `New GitHub repo discovered: ${r.fullName}`,
      detail: r.description ?? null,
      url: r.url,
      severity: (r.threatScore?.score ?? 0) >= 70 ? "high" : "medium",
      cveId: null,
      malwareFamily: null,
    });
  }

  // News: only critical/high-severity tagged headlines (server/newsCorrelation.js
  // already computes this) -- otherwise all ~30 feeds' daily volume would
  // dwarf every other source on the timeline.
  for (const item of newsItems ?? []) {
    if (!withinDays(item.publishedDate, days)) continue;
    if (item.severity !== "critical" && item.severity !== "high") continue;
    pushCapped(byType, {
      id: `news:${item.id}`,
      type: "news",
      date: item.publishedDate,
      title: item.title,
      detail: item.source,
      url: item.link,
      severity: item.severity,
      cveId: item.tags?.cveIds?.[0] ?? null,
      malwareFamily: item.tags?.malware?.[0] ?? null,
    });
  }

  const events = [];
  for (const [type, list] of byType) {
    list.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
    events.push(...list.slice(0, MAX_PER_TYPE[type] ?? 30));
  }

  events.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
  return events.slice(0, MAX_EVENTS);
}
