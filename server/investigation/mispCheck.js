// Shared MISP Warning Lists check -- identical logic to the inline
// checkMispWarninglists() in server/routes/dashboard.js's legacy /ioc-search
// route, factored out so every Investigation module can reuse it instead of
// each one redefining it.
import * as cache from "../cache.js";
import { matchWarninglists } from "../connectors/mispWarninglists.js";

export async function checkMispWarninglists(type, value) {
  const data = cache.getEntry("misp-warninglists").data;
  const matches = matchWarninglists(type, value, data);
  return { source: "MISP Warning Lists", verdict: matches.size > 0 ? "clean" : "unknown", matchedLists: Array.from(matches) };
}
