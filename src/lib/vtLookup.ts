import type { IocType } from "@/types/threat-intel";

/**
 * A safe, no-account-needed lookup for one indicator -- deliberately never
 * links to the indicator's own value directly (an "ip"/"domain"/"url" entry
 * here is live attacker infrastructure, not a citation), just to a public
 * verification page for it. Shared by every indicator table in the
 * dashboard (Malware Intelligence's family drawer, the All IOCs table) so
 * there's one place that knows how to build these URLs.
 */
export function virusTotalLookupUrl({ indicator, indicatorType }: { indicator: string; indicatorType: IocType }): string {
  // Defensive port-stripping for an "ip" indicator -- ThreatFox's "ip:port"
  // ioc_type is normalized to plain "ip" server-side but, for records
  // cached before that fix, the port can still be baked into the value
  // ("1.2.3.4:8080"), which produced an invalid VirusTotal URL. Guarded to
  // exactly one colon so a real IPv6 address is never touched.
  const value = indicatorType === "ip" && indicator.split(":").length === 2 ? indicator.split(":")[0] : indicator;
  switch (indicatorType) {
    case "ip":
      return `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(value)}`;
    case "domain":
      return `https://www.virustotal.com/gui/domain/${encodeURIComponent(value)}`;
    case "hash":
      return `https://www.virustotal.com/gui/file/${encodeURIComponent(value)}`;
    default:
      return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
  }
}
