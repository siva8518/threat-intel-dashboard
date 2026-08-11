// Sandbox provider registry -- the ONE place the rest of the app imports
// from. Adding a second provider (CAPE, Any.Run, ...) means writing a new
// server/sandbox/providers/*.js file that implements the same contract
// (checkExistingHash/submitUrl/pollStatus, all returning the shared
// SandboxReport shape from src/types/threat-intel.ts) and adding one line
// below -- no other file in the app (evidence.js, investigationGraph.js,
// actionability.js, the routes, sandboxIntelligence.js) needs to change.
import hybridAnalysisProvider from "./providers/hybridAnalysisProvider.js";

const PROVIDERS = {
  [hybridAnalysisProvider.id]: hybridAnalysisProvider,
};

// First-configured provider wins -- today there's only ever one, but this
// keeps sandboxIntelligence.js/the routes from having to know a provider id
// up front.
export const DEFAULT_PROVIDER_ID = hybridAnalysisProvider.id;

export function getProvider(id = DEFAULT_PROVIDER_ID) {
  const provider = PROVIDERS[id];
  if (!provider) throw new Error(`Unknown sandbox provider "${id}"`);
  return provider;
}

export function listProviders() {
  return Object.values(PROVIDERS);
}
