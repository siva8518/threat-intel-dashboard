// Top Security Events Today: a same-calendar-day rollup. Reuses the exact
// same cached sources already read for executive-summary and the AI Daily
// Brief -- KEV, OTX campaign signals, ransomware campaigns, the deduped
// threat-feed IOCs, and GitHub repos -- just filtered down to "did this
// happen on today's date" and reduced to one count per category, for a quick
// "what changed today" glance in the merged Overview tile.

// Exported: server/aiDailyBrief.js reuses this exact same-day check rather
// than re-deriving it, so "today" means the same calendar date everywhere.
export function isToday(dateStr) {
  if (!dateStr) return false;
  const today = new Date().toISOString().slice(0, 10);
  return String(dateStr).slice(0, 10) === today;
}

function countTodayKev(kevEntries) {
  return (kevEntries ?? []).filter((e) => isToday(e.dateAdded)).length;
}

function countTodayCampaigns(otxActorSignals) {
  const names = new Set((otxActorSignals ?? []).filter((s) => isToday(s.date)).map((s) => s.pulseName));
  return names.size;
}

function countTodayRansomware(ransomwareCampaigns) {
  return (ransomwareCampaigns ?? []).filter((c) => isToday(c.discoveredDate)).length;
}

// `i.source` (singular) only reflects whichever connector's record for this
// indicator was merged first during dedup (see correlate.js#dedupeIocs) --
// checking it directly silently drops any hash MalwareBazaar also reported
// but that URLhaus/ThreatFox happened to report first. `i.sources` (plural)
// is the full deduped list of every source that actually reported it.
function countTodayMalwareSamples(threatFeedIocs) {
  return (threatFeedIocs ?? []).filter((i) => i.sources.includes("MalwareBazaar") && isToday(i.firstSeen)).length;
}

function countTodayGithubExploits(githubRepos) {
  return (githubRepos ?? []).filter((r) => isToday(r.discoveredAt)).length;
}

function countTodayIocs(threatFeedIocs) {
  return (threatFeedIocs ?? []).filter((i) => isToday(i.firstSeen)).length;
}

export function buildTodaySecurityEvents(sources) {
  const { kevEntries, otxActorSignals, ransomwareCampaigns, threatFeedIocs, githubRepos } = sources;

  return {
    criticalKev: countTodayKev(kevEntries),
    activeExploitCampaigns: countTodayCampaigns(otxActorSignals),
    newRansomwareVictims: countTodayRansomware(ransomwareCampaigns),
    newMalwareSamples: countTodayMalwareSamples(threatFeedIocs),
    githubExploits: countTodayGithubExploits(githubRepos),
    newIocs: countTodayIocs(threatFeedIocs),
    generatedAt: new Date().toISOString(),
  };
}
