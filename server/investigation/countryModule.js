// Country investigation module -- a search that resolves to a real country
// name (see detect.js's country check against server/data/country-names.json).
// No live lookup, no per-country entity store -- the real correlation (which
// actors originate from / target this country, which campaigns/victims are
// tied to it) is computed by investigationGraph.js#gatherCountry, fetched in
// the same pass by this search's caller. This module just supplies the
// Universal Overview's verdict, mirroring artifactModule.js's shape.
import { crossReferenceIndicator } from "./crossReference.js";

export const type = "country";

export async function gather(value) {
  const crossReference = crossReferenceIndicator(value);
  const verdict = { verdict: "unknown", label: "Country Profile", confidence: "Medium", severity: "UNKNOWN", riskLevel: "Low", priority: "Low" };
  const note = "Which actors originate from or target this country, and which campaigns/victims are tied to it, is shown in the Investigation Graph above -- no separate reputation source exists for a country as a standalone indicator.";
  return { country: value, crossReference, note, verdict };
}
