// "Compute everything, then decide" empty-state model -- one honest summary
// of every intelligence layer a search actually consulted, built entirely
// from data server/investigation/index.js#assemble already has in hand (no
// new external calls introduced here). Replaces the old pattern of each
// frontend section (EntitySections.tsx, ArtifactSections.tsx, the CVE
// EmptyState in InvestigationWorkspace.tsx) independently deciding -- and
// rendering -- its own "no results" message with no visibility into what
// the OTHER systems found. `nothingFound` is only ever true when every
// layer below found zero hits; this is meant to be rare given how much of
// this platform's own correlation (entity stores, ransomware/dark-web
// victim data via the graph, detection content) is already checked here.
//
// Dark Web Intelligence deliberately has no standalone layer here -- its
// entities carry no per-indicator IOC field to cross-reference an IP/
// domain/hash against (only actor/malware/CVE associations), so its real
// contribution already flows through the "Ransomware / dark-web victim
// disclosures" layer below, which reads the graph's own victim edges
// (investigationGraph.js's gatherActor/gatherMalware/gatherCampaign already
// query getDarkWebEntities() directly when building those edges).
function layer(name, checked, hitCount, summary) {
  return { name, checked, hitCount, summary };
}

/**
 * @param {string} type
 * @param {Record<string, unknown>} moduleData
 * @param {ReturnType<import("./crossReference.js").crossReferenceIndicator> | null} crossRef
 * @param {import("./investigationGraph.js").GraphNodeResult | null} graph
 */
export function buildSearchCoverage(type, moduleData, crossRef, graph) {
  const layers = [];

  const lookupResults = Array.isArray(moduleData?.lookupResults) ? moduleData.lookupResults : null;
  if (lookupResults) {
    const hits = lookupResults.filter((r) => r && r.verdict && r.verdict !== "unknown").length;
    layers.push(
      layer(
        "Live external reputation lookups",
        true,
        hits,
        hits > 0 ? `${hits} of ${lookupResults.length} configured source(s) returned a verdict.` : `${lookupResults.length} configured source(s) checked -- none flagged this indicator.`,
      ),
    );
  }

  if (type === "cve") {
    const found = Boolean(moduleData?.found);
    layers.push(layer("CVE database (NVD / CIRCL)", true, found ? 1 : 0, found ? "Found in NVD or CIRCL." : "Not found in NVD or CIRCL."));
  }

  const crossRefSource =
    crossRef ??
    (type === "name"
      ? {
          matchedMalwareFamilies: (moduleData?.malware ?? []).map((m) => m.entity.name),
          associatedThreatActors: (moduleData?.actors ?? []).map((a) => a.name),
          activeCampaigns: (moduleData?.campaigns ?? []).map((c) => c.name),
          matchingAiReports: [],
        }
      : null);
  if (crossRefSource) {
    const hits = crossRefSource.matchedMalwareFamilies.length + crossRefSource.associatedThreatActors.length + crossRefSource.activeCampaigns.length + (crossRefSource.matchingAiReports?.length ?? 0);
    layers.push(
      layer(
        "This platform's own tracked intelligence (malware, threat actors, campaigns, AI Summarization reports)",
        true,
        hits,
        hits > 0 ? `${hits} match(es) across this platform's own entity stores and reports.` : "No match in this platform's own tracked intelligence.",
      ),
    );
  }

  if (graph) {
    const edges = graph.edges ?? [];
    layers.push(
      layer(
        "Relationship graph (correlated entities this platform has already linked)",
        true,
        edges.length,
        edges.length > 0 ? `${edges.length} real relationship(s) discovered.` : "No relationship discovered for this entity yet.",
      ),
    );

    const victimEdges = edges.filter((e) => e.targetType === "victim");
    layers.push(
      layer(
        "Ransomware / dark-web victim disclosures",
        true,
        victimEdges.length,
        victimEdges.length > 0 ? `${victimEdges.length} victim disclosure(s) linked.` : "No victim disclosure linked.",
      ),
    );

    const detectionRules = graph.node?.metadata?.detectionRules ?? [];
    const huntingQueries = graph.node?.metadata?.huntingQueries ?? [];
    const detectionHits = detectionRules.length + huntingQueries.length;
    layers.push(
      layer(
        "Detection rules & hunting queries",
        true,
        detectionHits,
        detectionHits > 0 ? `${detectionRules.length} detection rule(s), ${huntingQueries.length} hunting quer(ies).` : "No detection/hunting content matched.",
      ),
    );
  }

  const nothingFound = layers.length > 0 && layers.every((l) => l.hitCount === 0);
  return { layers, nothingFound };
}
