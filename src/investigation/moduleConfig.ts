// Declarative grouping of the 16 IndicatorType values into the section
// family that renders them -- adding a 17th type later means adding one
// entry here (plus, if it's genuinely a new shape, one new section
// component), not touching InvestigationWorkspace.tsx's layout.
import type { IndicatorType } from "@/types/threat-intel";

export type SectionFamily = "network" | "hash" | "cve" | "entity" | "artifact" | "unknown";

const FAMILY_BY_TYPE: Record<IndicatorType, SectionFamily> = {
  ip: "network",
  domain: "network",
  url: "network",
  sha256: "hash",
  sha1: "hash",
  md5: "hash",
  cve: "cve",
  name: "entity",
  email: "artifact",
  fileName: "artifact",
  processName: "artifact",
  registryKey: "artifact",
  userAgent: "artifact",
  // Ransomware group / country / ASN have no Indicator-Specific Intelligence
  // section of their own -- their real correlation is entirely the
  // Investigation Graph (already rendered above this section for every
  // type), so these render as "artifact" (a plain cross-reference note,
  // same shape as email/fileName/etc.) rather than adding a fourth
  // never-populated section family.
  ransomwareGroup: "artifact",
  country: "artifact",
  asn: "artifact",
  unknown: "unknown",
};

export function sectionFamilyFor(type: IndicatorType): SectionFamily {
  return FAMILY_BY_TYPE[type] ?? "unknown";
}

export const INDICATOR_TYPE_LABEL: Record<IndicatorType, string> = {
  ip: "IP Address",
  domain: "Domain",
  url: "URL",
  sha256: "SHA256 Hash",
  sha1: "SHA1 Hash",
  md5: "MD5 Hash",
  cve: "CVE",
  name: "Malware / Threat Actor / Campaign / Organization",
  email: "Email Address",
  fileName: "File Name",
  processName: "Process Name",
  registryKey: "Registry Key",
  userAgent: "User Agent",
  ransomwareGroup: "Ransomware Group",
  country: "Country",
  asn: "ASN",
  unknown: "Unrecognized",
};
