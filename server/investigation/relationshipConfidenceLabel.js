// DIRECT/STRONG/MODERATE/WEAK/CONTEXTUAL -- a user-facing 5-value confidence
// scale for entity-search relationships, always DERIVED from a GraphEdge's
// existing `semantics.claimStrength` + `confidence` (see
// investigationGraph.js's RELATIONSHIP_SEMANTICS / scoreConfidence), never a
// new, independently-computed judgment. `infrastructure-colocation` (e.g.
// "shares ASN with") is pinned to CONTEXTUAL unconditionally, regardless of
// confidence score -- the concrete code enforcement of "shared ASN/hosting
// infrastructure must never be presented as attribution."
//
// | claimStrength                          | confidence  | label      |
// |-----------------------------------------|-------------|------------|
// | explicit-record / attribution           | High        | DIRECT     |
// | explicit-record / attribution           | Medium/Low  | STRONG     |
// | reverse-lookup                          | High/Medium | STRONG     |
// | reverse-lookup                          | Low         | MODERATE   |
// | cross-reference                         | any         | MODERATE   |
// | algorithmic-guess / unresolved-mention  | any         | WEAK       |
// | infrastructure-colocation               | any (always)| CONTEXTUAL |

/**
 * @param {import("../../src/types/threat-intel.js").GraphEdge} edge
 * @returns {import("../../src/types/threat-intel.js").RelationshipConfidenceLabel}
 */
export function labelFor(edge) {
  const claimStrength = edge?.semantics?.claimStrength;
  const confidence = edge?.confidence;

  if (claimStrength === "infrastructure-colocation") return "CONTEXTUAL";

  if (claimStrength === "explicit-record" || claimStrength === "attribution") {
    return confidence === "High" ? "DIRECT" : "STRONG";
  }
  if (claimStrength === "reverse-lookup") {
    return confidence === "Low" ? "MODERATE" : "STRONG";
  }
  if (claimStrength === "cross-reference") return "MODERATE";
  // algorithmic-guess, unresolved-mention, or any unmapped relationship
  return "WEAK";
}
