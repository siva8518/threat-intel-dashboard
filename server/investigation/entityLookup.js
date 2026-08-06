// Shared entity name/alias matching -- hoisted out of investigationGraph.js
// (where this was previously defined inline and duplicated in spirit by
// crossReference.js#searchEntitiesByName's own substring version) so both it
// and knownAliasGroups.js's canonical-alias resolver share one
// implementation instead of three slightly different ones.
export function norm(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

/** Exact match (not substring) against an entity's own name or any of its stored aliases -- used wherever a specific, single entity needs to be resolved from a name (graph node lookups, alias resolution), as opposed to crossReference.js#searchEntitiesByName's broader substring search used for free-text "does anything match" queries. */
export function findByNameOrAlias(entities, key) {
  const target = norm(key);
  return entities.find((e) => norm(e.name) === target || (e.aliases ?? []).some((a) => norm(a) === target)) ?? null;
}
