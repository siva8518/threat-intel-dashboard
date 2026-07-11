// Executive Threat Summary: one hero-level rollup combining every source
// this app already collects into a single glanceable picture for a security
// analyst. A transparent weighted heuristic (same philosophy as
// server/githubIntel/threatScoring.js's per-repo score) -- not a claimed
// industry-standard metric. Every input is the same data shown elsewhere in
// this dashboard (Latest CVEs, Threat Feed, Threat Actors, GitHub Intel), so
// the score is always traceable, not a black box.

// Weights sum to 1.0. KEV activity (confirmed real-world exploitation) and
// critical CVE volume dominate since they're the strongest ground-truth risk
// signals; live IOC volume, ransomware campaign volume and malware
// concentration are corroborating "how active is the ambient threat feed
// right now" signals.
const WEIGHTS = {
  criticalCves: 0.25,
  kevActivity: 0.3,
  iocVolume: 0.2,
  ransomware: 0.15,
  malwareConcentration: 0.1,
};

// Caps below are the point at which a signal contributes its full weight --
// deliberately generous/conservative, tuned against what this app's sources
// realistically produce day-to-day, not a formal benchmark.
const CAPS = {
  criticalCves30d: 50, // NVD critical CVEs published in the last 30 days
  kevAdded7d: 5, // new CISA KEV entries in the last 7 days
  threatFeedIocs: 150, // live malicious IOCs currently in the deduped feed
  ransomwareCampaigns: 40, // ransomware victim posts currently tracked
};

const LEVELS = [
  { max: 25, level: "Low" },
  { max: 50, level: "Elevated" },
  { max: 75, level: "High" },
  { max: Infinity, level: "Critical" },
];

function clamp01(n) {
  return Math.min(Math.max(n, 0), 1);
}

function levelForScore(score) {
  return LEVELS.find((t) => score <= t.max).level;
}

function countKevAddedSince(kevEntries, days) {
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  return (kevEntries ?? []).filter((e) => new Date(e.dateAdded).getTime() >= cutoff).length;
}

/**
 * Most exploited CVE: prefers a CVE that's both confirmed actively exploited
 * (CISA KEV) *and* has real attacker/researcher tooling built for it (referenced
 * across multiple tracked GitHub PoC repos) -- the strongest combined signal
 * this app can derive for free. Falls back to the single strongest signal
 * available if both together don't turn one up.
 */
function computeMostExploitedCve(kevEntries, githubTopCves) {
  const kevIds = new Set((kevEntries ?? []).map((e) => e.cveId));
  const bothSignals = (githubTopCves ?? []).find((c) => kevIds.has(c.cveId));

  if (bothSignals) {
    return {
      cveId: bothSignals.cveId,
      knownExploited: true,
      repoCount: bothSignals.repoCount,
      reason: `Confirmed actively exploited (CISA KEV) and referenced in ${bothSignals.repoCount} tracked GitHub PoC repo${bothSignals.repoCount === 1 ? "" : "s"}`,
    };
  }
  if (githubTopCves?.[0]) {
    const top = githubTopCves[0];
    return {
      cveId: top.cveId,
      knownExploited: kevIds.has(top.cveId),
      repoCount: top.repoCount,
      reason: `Most-referenced CVE across tracked GitHub PoC repos (${top.repoCount} repo${top.repoCount === 1 ? "" : "s"})`,
    };
  }
  if (kevEntries?.[0]) {
    return {
      cveId: kevEntries[0].cveId,
      knownExploited: true,
      repoCount: 0,
      reason: "Most recently added to CISA's Known Exploited Vulnerabilities catalog",
    };
  }
  return null;
}

export function buildExecutiveSummary(sources) {
  const {
    criticalCves30d,
    kevEntries,
    threatFeedIocs,
    ransomwareCampaigns,
    trendingMalware,
    githubTopCves,
    industryHeatmap,
    geoTargeting,
    mergedActors,
    attackCampaignsCount = 0,
    otxActorSignalsCount = 0,
  } = sources;

  const kevAdded7d = countKevAddedSince(kevEntries, 7);
  const totalMalwareSightings = trendingMalware.reduce((sum, m) => sum + m.count, 0) || 1;
  const topMalwareShare = trendingMalware[0] ? trendingMalware[0].count / totalMalwareSightings : 0;

  const signals = {
    criticalCves: clamp01((criticalCves30d ?? 0) / CAPS.criticalCves30d),
    kevActivity: clamp01(kevAdded7d / CAPS.kevAdded7d),
    iocVolume: clamp01(threatFeedIocs.length / CAPS.threatFeedIocs),
    ransomware: clamp01(ransomwareCampaigns.length / CAPS.ransomwareCampaigns),
    // A single family owning half or more of current sightings reads as a
    // coordinated/active campaign, not background noise -- so it alone
    // saturates this signal.
    malwareConcentration: clamp01(topMalwareShare * 2),
  };

  const breakdown = Object.entries(WEIGHTS).map(([signal, weight]) => ({
    signal,
    normalized: signals[signal],
    weight,
    contribution: weight * signals[signal] * 100,
  }));

  const score = Math.round(breakdown.reduce((sum, b) => sum + b.contribution, 0));

  return {
    score,
    level: levelForScore(score),
    breakdown,
    generatedAt: new Date().toISOString(),
    mostActiveActor: mergedActors[0] ?? null,
    mostActiveMalware: trendingMalware[0] ?? null,
    mostExploitedCve: computeMostExploitedCve(kevEntries, githubTopCves),
    industriesTargeted: industryHeatmap.industryTotals.filter((i) => i.count > 0).sort((a, b) => b.count - a.count).slice(0, 5),
    countriesUnderAttack: geoTargeting.countries.slice(0, 5),
    // Broadened beyond ransomware.live/RansomWatch/RansomLook victim posts
    // to also count real named threat-actor campaigns: MITRE ATT&CK's own
    // Campaigns objects (e.g. "APT28 Nearest Neighbor Campaign") and OTX
    // pulses with adversary attribution -- so this isn't just "how many
    // ransomware gangs posted a victim today."
    totalActiveCampaigns: ransomwareCampaigns.length + attackCampaignsCount + otxActorSignalsCount,
    campaignsBreakdown: {
      ransomware: ransomwareCampaigns.length,
      attackCampaigns: attackCampaignsCount,
      otxPulses: otxActorSignalsCount,
    },
  };
}
