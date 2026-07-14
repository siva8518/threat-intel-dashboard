// Threat Correlation Engine: automatically links *live* records this app
// currently ingests -- the deduped threat feed, ransomware.live campaigns,
// and enriched GitHub Intel repos -- whenever they share a CVE, malware
// family, threat actor, IP, domain, URL, or hash. Each connected cluster
// becomes one "Unified Intelligence Card" instead of leaving the same
// underlying activity scattered across separate, isolated feed rows.
// MITRE ATT&CK (groups/software/techniques) is layered on top as
// *enrichment* of an already-formed cluster (which techniques/CVEs a
// cluster's actor/malware are known for) -- never used to merge clusters.
//
// Why ATT&CK itself can't drive the merge (confirmed live, not a guess):
// the first version of this engine unioned two ATT&CK groups together
// whenever they shared a tool, and separately capped out any single tool
// used by "too many" groups as a hub. Both attempts still collapsed into one
// supercluster covering most of the dataset -- because MITRE's own
// group<->software graph is a genuinely dense small-world network (most APT
// groups share *some* tooling with *some* other group), so any threshold
// still leaves enough short chains to transitively connect nearly
// everything. That's real underlying data, but it makes ATT&CK's own graph
// unusable as a *live correlation* signal -- it answers "how does the threat
// landscape interconnect historically," not "what's happening right now."
// So here it's read-only enrichment of a cluster some *live* signal already
// anchored, never a source of new unions.
//
// Implementation: a union-find over normalized key tokens (`cve:...`,
// `malware:...`, `actor:...`, `ioc:<type>:...`) across only the three live
// sources above. Deliberately NOT using GitHub repos' raw extracted
// ip/domain/url/hash lists -- confirmed live these are dominated by README
// boilerplate (shields.io badges, github.com self-links, nvd.nist.gov
// reference links). Repos instead contribute IOC keys only through
// `correlation.matches` (server/githubIntel/enrich.js's own cross-check
// against the live threat feed), already filtered to genuine overlaps.
// Also excluded: generic URLHaus filetype/architecture tags ("elf",
// "32-bit", "exe"...) masquerading as malware family names -- the same
// quirk already noted in server/correlate.js's trending-malware computation.

class UnionFind {
  constructor() {
    this.parent = new Map();
  }
  find(x) {
    if (!this.parent.has(x)) this.parent.set(x, x);
    let root = x;
    while (this.parent.get(root) !== root) root = this.parent.get(root);
    let cur = x;
    while (this.parent.get(cur) !== root) {
      const next = this.parent.get(cur);
      this.parent.set(cur, root);
      cur = next;
    }
    return root;
  }
  union(a, b) {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent.set(ra, rb);
  }
}

function norm(s) {
  return (s ?? "").trim().toLowerCase();
}

const GENERIC_LABELS = new Set([
  "32-bit",
  "64-bit",
  "elf",
  "mips",
  "arm",
  "arm5",
  "windows",
  "macos",
  "linux",
  "opendir",
  "exe",
  "dll",
  "sh",
  "apk",
  "ps1",
  "html",
  "config",
  "json",
  "unknown",
  "n/a",
  // Common dual-use offensive/red-team tools -- the same hub problem as
  // ATT&CK's group<->software graph (Mimikatz/PsExec/Cobalt Strike used by
  // dozens of groups there), just showing up again via GitHub repos and live
  // IOC tags: these are the generic payload/C2 framework nearly every
  // unrelated exploit or PoC repo happens to mention, so treating a shared
  // mention of one as "these are the same campaign" produces the same kind
  // of meaningless supercluster confirmed live during this feature's build.
  "cobalt strike",
  "cobaltstrike",
  "mimikatz",
  "metasploit",
  "empire",
  "powershell empire",
  "meterpreter",
  "psexec",
  // URLHaus's `tags` field is freeform and community-submitted (server/
  // connectors/urlhaus.js joins it straight into `malwareFamily`) -- these
  // are honeypot/protocol/infrastructure labels confirmed live showing up
  // as fake "malware families" (a URLHaus submitter tagging a host as
  // "cowrie"/"telnet" describes how the sighting was captured, not what
  // malware it is) rather than an actual family name.
  "cowrie",
  "honeypot",
  "ssh",
  "telnet",
  "ftp",
  "rdp",
  "smb",
  "scanner",
  "bruteforce",
  "c2",
  "proxy",
  "botnet",
]);

// Same URLHaus freeform-tag problem, but for values that can't be caught by
// a fixed denylist -- a submitter tagging a host with its own hostname/IP-like
// identifier (e.g. "137-184-6-122") or a detection-signature id (e.g.
// "win-0x4679", confirmed live sitting in the same comma-joined tag list
// right next to a real family name like "ClearFake") rather than any real
// family name. A genuine malware family name is never purely digits and
// separators, and never a short word glued to a hex code by a dash.
const NUMERIC_LABEL_PATTERN = /^\d+([.-]\d+){2,}$/;
const SIGNATURE_ID_PATTERN = /^\w{1,6}-0x[0-9a-f]+$/i;

export function splitFamilies(malwareFamily) {
  if (!malwareFamily || malwareFamily === "Unknown" || malwareFamily === "N/A") return [];
  return malwareFamily
    .split(",")
    .map((f) => f.trim())
    .filter((f) => f && !GENERIC_LABELS.has(f.toLowerCase()) && !NUMERIC_LABEL_PATTERN.test(f) && !SIGNATURE_ID_PATTERN.test(f));
}

/**
 * Names of ATT&CK "software" entries used by more than `threshold` different
 * groups -- dual-use/living-off-the-land tools (Mimikatz, PsExec, Cobalt
 * Strike, and built-in admin binaries like ping/net/tasklist/certutil) that
 * are real attribution but too generic to anchor a correlation on (see the
 * module-level note above). Reused by server/newsCorrelation.js for the same
 * reason: as plain English words/common tool names, they light up in
 * headlines that have nothing to do with the actual malware family.
 */
export function getCommonAttackToolNames(attackData, threshold = 5) {
  const groupCountBySoftwareId = new Map();
  for (const g of attackData?.groups ?? []) {
    for (const sid of g.softwareIds ?? []) groupCountBySoftwareId.set(sid, (groupCountBySoftwareId.get(sid) ?? 0) + 1);
  }
  const softwareById = new Map((attackData?.software ?? []).map((s) => [s.id, s]));
  const names = new Set();
  for (const [id, count] of groupCountBySoftwareId.entries()) {
    if (count <= threshold) continue;
    const software = softwareById.get(id);
    if (!software) continue;
    for (const n of [software.name, ...(software.aliases ?? [])]) names.add(n.toLowerCase());
  }
  return names;
}

const MIN_ENTITY_TYPES = 2; // a cluster must connect at least this many distinct kinds of live intel to be worth surfacing
const MAX_CARDS = 40;
const MAX_IOCS_PER_CARD = 12;
const MAX_REPOS_PER_CARD = 5;
const MAX_CAMPAIGNS_PER_CARD = 5;
const MAX_TECHNIQUES_PER_CARD = 12;
const MAX_ENRICHED_CVES_PER_CARD = 10;

export function buildCorrelationClusters(sources) {
  const { threatFeedIocs, ransomwareCampaigns, kevEntries, githubRepos, attackData } = sources;

  const uf = new UnionFind();
  const contributions = []; // { keys: string[], record }
  const displayNames = new Map(); // "malware:zebrocy" | "actor:apt28" -> nicely-cased display string

  function remember(key, display) {
    if (display && !displayNames.has(key)) displayNames.set(key, display);
  }

  function addRecord(rawKeys, record) {
    const keys = Array.from(new Set(rawKeys.filter(Boolean)));
    if (keys.length === 0) return;
    uf.find(keys[0]);
    for (let i = 1; i < keys.length; i++) uf.union(keys[0], keys[i]);
    contributions.push({ keys, record });
  }

  // --- 1. Live threat feed IOCs -> IOC + malware keys ---
  for (const ioc of threatFeedIocs) {
    const keys = [`ioc:${ioc.indicatorType}:${norm(ioc.indicator)}`];
    for (const fam of splitFamilies(ioc.malwareFamily)) {
      const key = `malware:${norm(fam)}`;
      keys.push(key);
      remember(key, fam);
    }
    addRecord(keys, { kind: "ioc", ioc });
  }

  // --- 2. Ransomware campaigns -> actor key ---
  for (const rc of ransomwareCampaigns) {
    const actorKey = `actor:${norm(rc.group)}`;
    remember(actorKey, rc.group);
    addRecord([actorKey], { kind: "ransomware-campaign", campaign: rc });
  }

  // --- 3. Enriched GitHub Intel repos -> CVE + malware + actor keys, plus IOC keys
  //     from already-verified live-feed matches ---
  // "Aggregator" repos (PoC/signature *indexes* like trickest/cve or
  // Neo23x0/signature-base, which mention dozens of unrelated CVEs/families
  // in one README because they catalog many campaigns, not because those
  // campaigns relate to each other) turned out to be a third hub-node
  // source, confirmed live: unioning everything one such repo mentions
  // re-created the supercluster even after the ATT&CK-graph fix above. A
  // repo only gets to use its own extracted CVE/malware/actor mentions as
  // *union* keys if it mentions few enough of them to plausibly be about one
  // specific thing -- past that, it's treated as an index, and only
  // contributes through its already-verified IOC matches instead (still
  // real correlation, just not "everything this catalog page ever links to").
  const FOCUSED_REPO_ENTITY_LIMIT = 5;

  // A second, independent hub source, confirmed live: even repos that stay
  // under the focused-entity limit above can still collectively bridge
  // almost everything if *one* name they mention (e.g. "Conti" -- a defunct
  // ransomware brand, shut down in 2022, that nonetheless still gets listed
  // in dozens of unrelated repos' generic "detects: Conti, LockBit, Play,
  // ..." family-support blurbs) is repeated across enough otherwise-
  // unconnected repos. Same fix as the ATT&CK common-tool case: count how
  // many distinct repos mention each family/actor via extraction (not via a
  // verified live IOC match, which doesn't have this problem), and stop
  // letting a name repeated across too many repos act as a union key.
  const REPEATED_NAME_REPO_THRESHOLD = 3;
  const repoCountByMalwareName = new Map();
  const repoCountByActorName = new Map();
  for (const repo of githubRepos) {
    if (!repo.lastEnrichedAt) continue;
    const ex = repo.extracted ?? {};
    for (const fam of new Set((ex.malwareFamilies ?? []).map(norm))) {
      repoCountByMalwareName.set(fam, (repoCountByMalwareName.get(fam) ?? 0) + 1);
    }
    for (const name of new Set((ex.threatActorNames ?? []).map(norm))) {
      repoCountByActorName.set(name, (repoCountByActorName.get(name) ?? 0) + 1);
    }
  }

  for (const repo of githubRepos) {
    if (!repo.lastEnrichedAt) continue;
    const ex = repo.extracted ?? {};
    const cveIds = ex.cveIds ?? [];
    const malwareFamilies = (ex.malwareFamilies ?? []).filter(
      (f) => !GENERIC_LABELS.has(f.toLowerCase()) && (repoCountByMalwareName.get(norm(f)) ?? 0) <= REPEATED_NAME_REPO_THRESHOLD,
    );
    const actorNames = (ex.threatActorNames ?? []).filter((a) => (repoCountByActorName.get(norm(a)) ?? 0) <= REPEATED_NAME_REPO_THRESHOLD);
    const isFocused = cveIds.length + malwareFamilies.length + actorNames.length <= FOCUSED_REPO_ENTITY_LIMIT;

    // A focused repo's own mentions plausibly all describe the one thing
    // it's about, so they're unioned together as a single record.
    if (isFocused) {
      const keys = [...cveIds.map((id) => `cve:${id}`)];
      for (const fam of malwareFamilies) {
        const key = `malware:${norm(fam)}`;
        keys.push(key);
        remember(key, fam);
      }
      for (const name of actorNames) {
        const key = `actor:${norm(name)}`;
        keys.push(key);
        remember(key, name);
      }
      if (keys.length) addRecord(keys, { kind: "github-repo", repo });
    }

    // Each verified IOC match is its OWN record, unioned only with its own
    // malware-family tag -- NOT combined with the repo's other matches.
    // A broad IOC aggregator (e.g. a repo that collects indicators tweeted
    // by many different researchers about many different, unrelated
    // campaigns) would otherwise merge every one of its unrelated matches
    // into a single cluster just because they came from the same repo.
    for (const match of repo.correlation?.matches ?? []) {
      const keys = [`ioc:${match.indicatorType}:${norm(match.indicator)}`];
      for (const fam of splitFamilies(match.malwareFamily)) {
        const key = `malware:${norm(fam)}`;
        keys.push(key);
        remember(key, fam);
      }
      addRecord(keys, { kind: "github-repo", repo });
    }
  }

  // --- Reconstitute clusters from cluster-root -> contributions ---
  const kevIds = new Set((kevEntries ?? []).map((e) => e.cveId));

  const clusters = new Map();
  function clusterFor(root) {
    if (!clusters.has(root)) {
      clusters.set(root, {
        cves: new Set(),
        malware: new Set(),
        actors: new Set(),
        iocs: new Map(),
        repos: new Map(),
        campaigns: new Map(),
        recordCount: 0,
      });
    }
    return clusters.get(root);
  }

  for (const { keys, record } of contributions) {
    const cluster = clusterFor(uf.find(keys[0]));
    cluster.recordCount += 1;
    for (const key of keys) {
      const [type, ...rest] = key.split(":");
      if (type === "cve") cluster.cves.add(rest.join(":"));
      else if (type === "malware") cluster.malware.add(rest.join(":"));
      else if (type === "actor") cluster.actors.add(rest.join(":"));
      else if (type === "ioc") cluster.iocs.set(key, { indicatorType: rest[0], indicator: rest.slice(1).join(":") });
    }
    if (record.kind === "github-repo") cluster.repos.set(record.repo.fullName, record.repo);
    if (record.kind === "ransomware-campaign") cluster.campaigns.set(record.campaign.id, record.campaign);
  }

  // --- ATT&CK enrichment lookups (read-only -- never merges clusters) ---
  const softwareByNormName = new Map();
  for (const s of attackData?.software ?? []) {
    for (const n of [s.name, ...(s.aliases ?? [])].map(norm)) softwareByNormName.set(n, s);
  }
  const groupByNormName = new Map();
  for (const g of attackData?.groups ?? []) {
    for (const n of [g.name, ...(g.aliases ?? [])].map(norm)) groupByNormName.set(n, g);
  }
  const techniqueById = new Map((attackData?.techniques ?? []).map((t) => [t.id, t]));

  // --- Build final cards, ranked by how many distinct kinds of live intel they connect ---
  const cards = [];
  for (const cluster of clusters.values()) {
    const entityTypesPresent =
      ["cves", "malware", "actors"].filter((k) => cluster[k].size > 0).length + (cluster.iocs.size > 0 ? 1 : 0);
    if (entityTypesPresent < MIN_ENTITY_TYPES) continue;

    const techniqueIds = new Set();
    const enrichedCveIds = new Set(cluster.cves);
    for (const m of cluster.malware) {
      const software = softwareByNormName.get(m);
      for (const id of software?.techniqueIds ?? []) techniqueIds.add(id);
      for (const id of software?.cveIds ?? []) enrichedCveIds.add(id);
    }
    for (const a of cluster.actors) {
      const group = groupByNormName.get(a);
      for (const id of group?.techniqueIds ?? []) techniqueIds.add(id);
      for (const id of group?.cveIds ?? []) enrichedCveIds.add(id);
    }

    cards.push({
      malware: Array.from(cluster.malware).map((key) => displayNames.get(`malware:${key}`) ?? key),
      actors: Array.from(cluster.actors).map((key) => displayNames.get(`actor:${key}`) ?? key),
      cves: Array.from(enrichedCveIds)
        .slice(0, MAX_ENRICHED_CVES_PER_CARD)
        .map((id) => ({ id, knownExploited: kevIds.has(id) }))
        .sort((a, b) => Number(b.knownExploited) - Number(a.knownExploited)),
      techniques: Array.from(techniqueIds)
        .slice(0, MAX_TECHNIQUES_PER_CARD)
        .map((id) => techniqueById.get(id) ?? { id, name: id, tactic: "unknown", url: `https://attack.mitre.org/techniques/${id}` })
        .sort((a, b) => a.id.localeCompare(b.id)),
      iocs: Array.from(cluster.iocs.values()).slice(0, MAX_IOCS_PER_CARD),
      githubRepos: Array.from(cluster.repos.values())
        .sort((a, b) => (b.stars ?? 0) - (a.stars ?? 0))
        .slice(0, MAX_REPOS_PER_CARD)
        .map((r) => ({ fullName: r.fullName, url: r.url, stars: r.stars })),
      ransomwareCampaigns: Array.from(cluster.campaigns.values())
        .sort((a, b) => new Date(b.discoveredDate) - new Date(a.discoveredDate))
        .slice(0, MAX_CAMPAIGNS_PER_CARD),
      entityTypeCount: entityTypesPresent,
      recordCount: cluster.recordCount,
      totalIocCount: cluster.iocs.size,
    });
  }

  return cards
    .sort((a, b) => b.entityTypeCount - a.entityTypeCount || b.recordCount - a.recordCount)
    .slice(0, MAX_CARDS);
}
