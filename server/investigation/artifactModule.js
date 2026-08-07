// Email Address / File Name / Process Name / Registry Key / User Agent
// investigation module -- no external reputation source treats any of these
// as a globally-queryable indicator (there's no "look up this filename"
// API), so this is cross-reference-only: does this value already appear in
// this app's own ingested IOC data? If yes, show what it's linked to; if
// no, say plainly that no external lookup exists for this type rather than
// rendering an empty "results" panel with no explanation.
import { crossReferenceIndicator } from "./crossReference.js";

export const type = "artifact";

const NO_SOURCE_NOTE = {
  email: "No external reputation service treats an email address alone as a queryable indicator. This platform can only report whether it already appears in its own ingested threat intelligence.",
  fileName: "No external service provides a general-purpose file name reputation lookup (file names aren't unique -- only hashes are). This platform can only report whether it already appears in its own ingested threat intelligence.",
  processName: "No external service provides a general-purpose process name reputation lookup. This platform can only report whether it already appears in its own ingested threat intelligence.",
  registryKey: "No external service provides a general-purpose registry key reputation lookup. This platform can only report whether it already appears in its own ingested threat intelligence.",
  userAgent: "No external service provides a general-purpose user agent reputation lookup. This platform can only report whether it already appears in its own ingested threat intelligence.",
};

export async function gather(value, artifactType) {
  const crossRef = crossReferenceIndicator(value);
  return {
    noExternalSource: true,
    note: NO_SOURCE_NOTE[artifactType] ?? NO_SOURCE_NOTE.fileName,
    crossReference: crossRef,
  };
}
