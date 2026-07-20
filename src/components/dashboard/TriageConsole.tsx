import { useMemo, useState } from "react";
import { AlertTriangle, ExternalLink, Search, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "./ErrorState";
import { useSelection } from "@/context/SelectionContext";
import { useIocSearch } from "@/hooks/useIocSearch";
import { useMalwareIntelligence } from "@/hooks/useMalwareIntelligence";
import { useThreatActorIntelligence } from "@/hooks/useThreatActorIntelligence";
import { useCampaignIntelligence } from "@/hooks/useCampaignIntelligence";
import { useThreatActors } from "@/hooks/useRansomware";
import { fetchCveById } from "@/api/dashboardApi";
import { virusTotalLookupUrl } from "@/lib/vtLookup";
import type {
  CveRecord,
  IocSearchIndicatorType,
  IocSearchResult,
  IocLookupResult,
  MalwareIntelligenceEntity,
  ThreatActorIntelligenceEntity,
  CampaignIntelligenceEntity,
  ThreatActor,
} from "@/types/threat-intel";
import { cn } from "@/lib/utils";

type TriageType = "cve" | "ip" | "domain" | "url" | "hash" | "name";

// Deliberately the same shapes this app's other indicator handling already
// trusts (IocSearch.tsx's type dropdown, server/routes/dashboard.js's
// IOC_LOOKUPS) -- this just picks the type instead of making an analyst pick
// it from a dropdown, since the whole point of a triage console is pasting
// straight from an alert with no extra clicks first.
const CVE_PATTERN = /^CVE-\d{4}-\d{4,7}$/i;
const IPV4_PATTERN = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_PATTERN = /^[0-9a-f]{0,4}(:[0-9a-f]{0,4}){2,7}$/i;
const HASH_PATTERN = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const DOMAIN_PATTERN = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;

function detectTriageType(raw: string): TriageType {
  const value = raw.trim();
  if (CVE_PATTERN.test(value)) return "cve";
  if (IPV4_PATTERN.test(value) || IPV6_PATTERN.test(value)) return "ip";
  if (HASH_PATTERN.test(value)) return "hash";
  if (/^https?:\/\//i.test(value)) return "url";
  if (DOMAIN_PATTERN.test(value)) return "domain";
  return "name";
}

interface Verdict {
  level: "critical" | "high" | "medium" | "low" | "unknown";
  label: string;
  action: string;
}

const VERDICT_BADGE: Record<Verdict["level"], "critical" | "high" | "medium" | "low" | "muted"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  unknown: "muted",
};

/** Same priority signal the rest of this app treats as authoritative for a CVE -- KEV (confirmed active exploitation) outranks everything, EPSS is the next-best predictive signal, CVSS severity alone is the weakest since it says nothing about real-world exploitation. */
function cveVerdict(cve: CveRecord): Verdict {
  if (cve.knownExploited) {
    return { level: "critical", label: "Actively exploited (KEV)", action: "Escalate immediately — CISA confirms active exploitation in the wild. Patch or mitigate now." };
  }
  if ((cve.epssScore ?? 0) >= 0.5) {
    return {
      level: "critical",
      label: "High exploitation probability",
      action: `Escalate — ${Math.round((cve.epssScore ?? 0) * 100)}% predicted exploitation probability (EPSS) in the next 30 days.`,
    };
  }
  if (cve.severity === "CRITICAL") return { level: "high", label: "Critical severity", action: "Prioritize patching — critical CVSS severity, no confirmed active exploitation yet." };
  if (cve.severity === "HIGH") return { level: "medium", label: "High severity", action: "Schedule patching per your standard SLA." };
  if (cve.severity === "MEDIUM") return { level: "low", label: "Medium severity", action: "Lower priority — patch during routine maintenance." };
  return { level: "low", label: "Low severity", action: "Low priority — monitor for any change in exploitation status." };
}

const IOC_VERDICT: Record<IocSearchResult["correlatedVerdict"], Verdict> = {
  malicious: { level: "critical", label: "Malicious", action: "Escalate immediately — confirmed malicious by multiple sources below." },
  suspicious: { level: "high", label: "Suspicious", action: "Escalate for review — flagged by at least one source, not yet fully corroborated." },
  clean: { level: "low", label: "Clean", action: "No malicious signal found across configured sources — likely benign, but confirm against the original alert context." },
  unknown: { level: "unknown", label: "No data", action: "No configured source has data on this indicator — treat per your SOC's baseline for unknowns, or add more IOC Search API keys." },
};

/**
 * Label for the source/type of a merged (ransomware.live/OTX) actor entry --
 * same helper as TopThreatActors.tsx#typeLabel, duplicated locally rather
 * than shared since it's a tiny, self-contained formatter.
 */
function typeLabel(type: ThreatActor["type"]): string {
  if (type === "ransomware") return "Ransomware group";
  if (type === "otx-tagged") return "OTX-tagged actor";
  return `${type} (news-tracked)`;
}

function matchesQuery(name: string, aliases: string[], query: string) {
  const q = query.toLowerCase();
  return name.toLowerCase().includes(q) || aliases.some((a) => a.toLowerCase().includes(q));
}

function VerdictBanner({ verdict }: { verdict: Verdict }) {
  const Icon = verdict.level === "critical" || verdict.level === "high" ? AlertTriangle : ShieldCheck;
  return (
    <div
      className={cn(
        "flex items-start gap-3 rounded-xl border p-4",
        verdict.level === "critical" && "border-critical/30 bg-critical/10",
        verdict.level === "high" && "border-high/30 bg-high/10",
        verdict.level === "medium" && "border-medium/30 bg-medium/10",
        verdict.level === "low" && "border-low/30 bg-low/10",
        verdict.level === "unknown" && "border-white/10 bg-white/[0.03]",
      )}
    >
      <Icon
        className={cn(
          "mt-0.5 h-5 w-5 shrink-0",
          verdict.level === "critical" && "text-critical",
          verdict.level === "high" && "text-high",
          verdict.level === "medium" && "text-medium",
          verdict.level === "low" && "text-low",
          verdict.level === "unknown" && "text-muted",
        )}
      />
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={VERDICT_BADGE[verdict.level]}>{verdict.level.toUpperCase()}</Badge>
          <span className="text-sm font-semibold text-foreground">{verdict.label}</span>
        </div>
        <p className="mt-1 text-sm text-muted">{verdict.action}</p>
      </div>
    </div>
  );
}

function CveResultView({ cve, cveError, cveLoading, onViewProfile }: { cve: CveRecord | null; cveError: string | null; cveLoading: boolean; onViewProfile: () => void }) {
  if (cveLoading) return <Skeleton className="h-24 w-full" />;
  if (cveError) return <EmptyState message={cveError} />;
  if (!cve) return null;
  return (
    <div className="space-y-3">
      <VerdictBanner verdict={cveVerdict(cve)} />
      <div className="grid grid-cols-2 gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 text-sm sm:grid-cols-4">
        <div>
          <p className="text-[11px] uppercase tracking-wide text-muted">CVSS</p>
          <p className="font-mono font-semibold text-foreground">{cve.cvssScore ?? "—"}</p>
        </div>
        <div>
          <p className="text-[11px] uppercase tracking-wide text-muted">EPSS</p>
          <p className="font-mono font-semibold text-foreground">{cve.epssScore != null ? `${Math.round(cve.epssScore * 100)}%` : "—"}</p>
        </div>
        <div>
          <p className="text-[11px] uppercase tracking-wide text-muted">Vendor / Product</p>
          <p className="truncate font-semibold text-foreground">
            {cve.vendor} / {cve.product}
          </p>
        </div>
        <div>
          <p className="text-[11px] uppercase tracking-wide text-muted">Published</p>
          <p className="font-semibold text-foreground">{new Date(cve.publishedDate).toLocaleDateString()}</p>
        </div>
      </div>
      <p className="text-sm text-muted">{cve.description}</p>
      <div className="flex flex-wrap gap-2">
        <Button type="button" onClick={onViewProfile}>
          View full correlated profile (actors, malware, campaigns, IOCs, PoCs)
        </Button>
        <a
          href={cve.sourceUrl}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-muted hover:text-foreground"
        >
          NVD record
          <ExternalLink className="h-3 w-3" />
        </a>
      </div>
    </div>
  );
}

interface KeyFact {
  label: string;
  value: string;
}

/**
 * Cross-source "so what" summary an L1/L2 analyst actually wants at a
 * glance -- IP geolocation/ASN/open ports/known CVEs, domain cert/exposure
 * data, hash malware-family/detection ratio -- pulled from whichever
 * sources happened to answer, not a fixed list every one has to fill in.
 * Confirmed live this was the actual gap: every source already returns
 * this data, it just wasn't surfaced anywhere except as a raw JSON dump.
 */
/** Some sources genuinely have nothing to report for a given field (e.g. SANS ISC's reportCount/firstSeen when an IP has no sighting history there) -- renders as "—", not the literal word "null"/"undefined". */
function safe(v: unknown): string {
  return v == null || v === "" ? "—" : String(v);
}

function buildKeyFacts(type: IocSearchIndicatorType, results: IocLookupResult[]): KeyFact[] {
  const facts: KeyFact[] = [];
  const find = (source: string) => results.find((r) => r.source === source);

  if (type === "ip") {
    const abuseIpdb = find("AbuseIPDB");
    const shodan = find("Shodan");
    const ripestat = find("RIPEstat");
    const teamCymru = find("Team Cymru");
    const isc = find("SANS ISC");
    const greynoise = find("GreyNoise");
    const otx = find("OTX");

    const country = abuseIpdb?.countryCode ?? isc?.country ?? teamCymru?.country;
    if (country) facts.push({ label: "Country", value: String(country) });

    const org = shodan?.org ?? isc?.asName ?? ripestat?.holder;
    const asn = ripestat?.asn ?? teamCymru?.asn ?? isc?.asn;
    if (org || asn) facts.push({ label: "ASN / Organization", value: [asn ? `AS${asn}` : null, org].filter(Boolean).join(" · ") });

    if (Array.isArray(shodan?.openPorts) && shodan.openPorts.length > 0) {
      facts.push({ label: "Open Ports", value: shodan.openPorts.slice(0, 12).join(", ") });
    }
    if (typeof shodan?.vulnCount === "number" && shodan.vulnCount > 0) {
      facts.push({ label: "Known Vulnerabilities (Shodan)", value: String(shodan.vulnCount) });
    }
    if (abuseIpdb) facts.push({ label: "Abuse Reports", value: `${abuseIpdb.abuseConfidenceScore}% confidence · ${abuseIpdb.totalReports} reports` });
    if (greynoise) {
      facts.push({
        label: "GreyNoise",
        value: greynoise.riot ? "Known-benign business service" : `${greynoise.classification}${greynoise.name ? ` (${greynoise.name})` : ""}`,
      });
    }
    if (isc && (typeof isc.reportCount === "number" || typeof isc.attackTargets === "number")) {
      facts.push({ label: "SANS ISC Sightings", value: `${safe(isc.reportCount)} reports · ${safe(isc.attackTargets)} targets` });
    }
    if (typeof otx?.pulseCount === "number" && otx.pulseCount > 0) facts.push({ label: "OTX Pulses", value: String(otx.pulseCount) });
  }

  if (type === "domain" || type === "url") {
    const crtsh = find("crt.sh");
    const hudsonRock = find("Hudson Rock");
    const leakix = find("LeakIX");
    const pulsedive = find("Pulsedive");
    const otx = find("OTX");
    const vt = find("VirusTotal");

    if (crtsh) {
      facts.push({ label: "Subdomains Found", value: String(crtsh.subdomainCount) });
      if (crtsh.latestIssuer) facts.push({ label: "Latest Cert Issuer", value: String(crtsh.latestIssuer) });
    }
    if (hudsonRock && typeof hudsonRock.infostealerInfections === "number" && hudsonRock.infostealerInfections > 0) {
      facts.push({
        label: "Infostealer Exposure",
        value: `${hudsonRock.infostealerInfections} infections (${hudsonRock.employeesExposed} employees, ${hudsonRock.usersExposed} users)`,
      });
    }
    if (leakix && typeof leakix.serviceCount === "number" && leakix.serviceCount > 0) {
      facts.push({ label: "Exposed Services", value: `${leakix.serviceCount} services · ${leakix.leakCount} leaks` });
    }
    if (pulsedive) facts.push({ label: "Pulsedive Risk", value: String(pulsedive.risk) });
    if (vt) facts.push({ label: "VirusTotal Detections", value: `${vt.malicious} malicious / ${vt.harmless} harmless` });
    if (typeof otx?.pulseCount === "number" && otx.pulseCount > 0) facts.push({ label: "OTX Pulses", value: String(otx.pulseCount) });
  }

  if (type === "hash") {
    const vt = find("VirusTotal");
    const ha = find("Hybrid Analysis");
    const cymru = find("Team Cymru MHR");
    if (vt) {
      const total = (vt.malicious as number) + (vt.suspicious as number) + (vt.harmless as number);
      facts.push({ label: "VirusTotal Detections", value: `${vt.malicious} / ${total} engines flagged malicious` });
    }
    if (ha) {
      facts.push({ label: "Malware Family", value: (ha.malwareFamily as string) || "Not identified" });
      facts.push({ label: "Hybrid Analysis Threat Score", value: `${ha.threatScore}/100` });
    }
    if (cymru) {
      facts.push({
        label: "Malware Hash Registry",
        value: `${cymru.detectionPercent}% detection · last seen ${new Date(cymru.lastSeen as string).toLocaleDateString()}`,
      });
    }
  }

  return facts;
}

function KeyFactsPanel({ facts }: { facts: KeyFact[] }) {
  if (facts.length === 0) return null;
  return (
    <div>
      <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Key Facts</p>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
        {facts.map((f) => (
          <div key={f.label} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5">
            <p className="text-[10px] uppercase tracking-wide text-muted">{f.label}</p>
            <p className="mt-0.5 text-xs font-semibold text-foreground" title={f.value}>
              {f.value}
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Per-source facts, labeled and formatted for what each field actually
 * means -- replaces a raw JSON dump of the same data. Falls back to a
 * generic key/value listing for any source not explicitly mapped here, so
 * a newly added lookup still renders something rather than nothing.
 */
function renderSourceFacts(r: IocLookupResult): KeyFact[] {
  switch (r.source) {
    case "OTX":
      return [
        { label: "Pulses", value: safe(r.pulseCount) },
        ...(Array.isArray(r.tags) && r.tags.length > 0 ? [{ label: "Tags", value: r.tags.slice(0, 8).join(", ") }] : []),
      ];
    case "AbuseIPDB":
      return [
        { label: "Abuse Confidence", value: `${r.abuseConfidenceScore}%` },
        { label: "Total Reports", value: safe(r.totalReports) },
        { label: "Country", value: safe(r.countryCode) },
      ];
    case "Pulsedive":
      return [
        { label: "Risk", value: safe(r.risk) },
        ...(Array.isArray(r.threats) && r.threats.length > 0 ? [{ label: "Threats", value: r.threats.join(", ") }] : []),
      ];
    case "VirusTotal":
      return [{ label: "Detections", value: `${r.malicious} malicious · ${r.suspicious} suspicious · ${r.harmless} harmless` }];
    case "GreyNoise":
      return [
        { label: "Classification", value: safe(r.classification) },
        ...(r.name ? [{ label: "Known Actor/Scanner", value: String(r.name) }] : []),
        { label: "Known-Benign Service (RIOT)", value: r.riot ? "Yes" : "No" },
      ];
    case "Shodan":
      return [
        ...(r.org ? [{ label: "Organization", value: String(r.org) }] : []),
        ...(Array.isArray(r.openPorts) && r.openPorts.length > 0 ? [{ label: "Open Ports", value: r.openPorts.join(", ") }] : []),
        { label: "Known Vulnerabilities", value: safe(r.vulnCount) },
        ...(Array.isArray(r.tags) && r.tags.length > 0 ? [{ label: "Tags", value: r.tags.join(", ") }] : []),
      ];
    case "LeakIX":
      return [
        { label: "Exposed Services", value: safe(r.serviceCount) },
        { label: "Leaks Found", value: safe(r.leakCount) },
        ...(Array.isArray(r.sampleServices) && r.sampleServices.length > 0
          ? [{ label: "Sample Services", value: r.sampleServices.slice(0, 3).map((sv: { host: string; port: string; protocol: string }) => `${sv.host}:${sv.port}/${sv.protocol}`).join(", ") }]
          : []),
      ];
    case "RIPEstat":
      return [
        { label: "ASN", value: safe(r.asn) },
        { label: "Prefix", value: safe(r.prefix) },
        { label: "Holder", value: safe(r.holder) },
      ];
    case "Team Cymru":
      return [
        { label: "ASN", value: safe(r.asn) },
        { label: "Prefix", value: safe(r.prefix) },
        { label: "Country", value: safe(r.country) },
        { label: "Registry", value: safe(r.registry) },
        { label: "Allocated", value: safe(r.allocated) },
      ];
    case "Team Cymru MHR":
      return [
        { label: "Last Seen", value: r.lastSeen ? new Date(r.lastSeen as string).toLocaleDateString() : "—" },
        { label: "Detection", value: `${r.detectionPercent}%` },
        ...(r.note ? [{ label: "Note", value: String(r.note) }] : []),
      ];
    case "SANS ISC":
      return [
        { label: "Reports", value: safe(r.reportCount) },
        { label: "Attack Targets", value: safe(r.attackTargets) },
        { label: "First Seen", value: safe(r.firstSeen) },
        { label: "Last Seen", value: safe(r.lastSeen) },
        { label: "ASN", value: `${safe(r.asn)}${r.asName ? ` (${r.asName})` : ""}` },
        { label: "Country", value: safe(r.country) },
        ...(Array.isArray(r.threatFeeds) && r.threatFeeds.length > 0 ? [{ label: "Listed On", value: r.threatFeeds.join(", ") }] : []),
        ...(r.comment ? [{ label: "Comment", value: String(r.comment) }] : []),
      ];
    case "MISP Warning Lists":
      return Array.isArray(r.matchedLists) && r.matchedLists.length > 0
        ? [{ label: "Matched Lists", value: r.matchedLists.join(", ") }]
        : [{ label: "Matched Lists", value: "None" }];
    case "crt.sh":
      return [
        { label: "Certificates", value: safe(r.certificateCount) },
        { label: "Subdomains Found", value: safe(r.subdomainCount) },
        ...(r.latestIssuer ? [{ label: "Latest Issuer", value: String(r.latestIssuer) }] : []),
        ...(r.latestNotBefore ? [{ label: "Latest Cert Date", value: new Date(r.latestNotBefore as string).toLocaleDateString() }] : []),
      ];
    case "Hudson Rock":
      return [
        { label: "Infostealer Infections", value: safe(r.infostealerInfections) },
        { label: "Employees Exposed", value: safe(r.employeesExposed) },
        { label: "Users Exposed", value: safe(r.usersExposed) },
        { label: "Third Parties Exposed", value: safe(r.thirdPartiesExposed) },
      ];
    case "Hybrid Analysis":
      return [
        { label: "Threat Score", value: `${r.threatScore}/100` },
        { label: "Malware Family", value: r.malwareFamily ? String(r.malwareFamily) : "Not identified" },
        { label: "Verdict", value: safe(r.verdictLabel) },
      ];
    default:
      return Object.entries(r)
        .filter(([k]) => k !== "source" && k !== "verdict")
        .map(([k, v]) => ({ label: k, value: typeof v === "object" ? JSON.stringify(v) : String(v) }));
  }
}

function IocResultView({
  result,
  error,
  linkedFamily,
  onOpenMalware,
}: {
  result: IocSearchResult | undefined;
  error: string | null;
  linkedFamily: MalwareIntelligenceEntity | null;
  onOpenMalware: (entity: MalwareIntelligenceEntity) => void;
}) {
  if (error) return <EmptyState message={error} />;
  if (!result) return null;
  const keyFacts = buildKeyFacts(result.type, result.results);
  return (
    <div className="space-y-3">
      <VerdictBanner verdict={IOC_VERDICT[result.correlatedVerdict]} />
      <KeyFactsPanel facts={keyFacts} />
      {linkedFamily && (
        <button
          type="button"
          onClick={() => onOpenMalware(linkedFamily)}
          className="flex w-full items-center justify-between gap-2 rounded-lg border border-primary/30 bg-primary/10 px-3 py-2 text-left text-xs text-foreground hover:border-primary/50"
        >
          <span>
            Already tracked in this platform's own feed — linked to malware family <strong>{linkedFamily.name}</strong>
          </span>
          <span className="shrink-0 text-primary">View family →</span>
        </button>
      )}
      {result.results.length > 0 && (
        <div>
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Source Breakdown</p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {result.results.map((r) => (
              <div key={r.source} className="rounded-md border border-border p-3 text-xs">
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="font-semibold">{r.source}</span>
                  <Badge variant={VERDICT_BADGE[r.verdict === "malicious" ? "critical" : r.verdict === "suspicious" ? "high" : r.verdict === "clean" ? "low" : "unknown"]}>
                    {r.verdict}
                  </Badge>
                </div>
                <dl className="space-y-1">
                  {renderSourceFacts(r).map((f) => (
                    <div key={f.label} className="flex gap-1.5">
                      <dt className="shrink-0 text-muted">{f.label}:</dt>
                      <dd className="min-w-0 break-words text-foreground">{f.value}</dd>
                    </div>
                  ))}
                </dl>
              </div>
            ))}
          </div>
        </div>
      )}
      {result.notConfigured.length > 0 && <p className="text-xs text-muted">Not configured (missing API key): {result.notConfigured.join(", ")}</p>}
      {result.rateLimited.length > 0 && <p className="text-xs text-medium">Rate limited, try again shortly: {result.rateLimited.join(", ")}</p>}
      <a
        href={virusTotalLookupUrl({ indicator: result.indicator, indicatorType: result.type === "url" ? "url" : result.type })}
        target="_blank"
        rel="noreferrer"
        className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
      >
        Look up on VirusTotal
        <ExternalLink className="h-3 w-3" />
      </a>
    </div>
  );
}

function NameMatchView({
  query,
  malware,
  actors,
  ransomwareOnly,
  campaigns,
  onOpenMalware,
  onOpenActor,
  onOpenCampaign,
}: {
  query: string;
  malware: MalwareIntelligenceEntity[];
  actors: ThreatActorIntelligenceEntity[];
  ransomwareOnly: ThreatActor[];
  campaigns: CampaignIntelligenceEntity[];
  onOpenMalware: (entity: MalwareIntelligenceEntity) => void;
  onOpenActor: (name: string) => void;
  onOpenCampaign: () => void;
}) {
  const total = malware.length + actors.length + ransomwareOnly.length + campaigns.length;
  if (total === 0) {
    return <EmptyState message={`No malware family, threat actor, or campaign matches "${query}". Try the exact name, or paste an IP/domain/hash/CVE instead.`} />;
  }
  return (
    <div className="space-y-4">
      <VerdictBanner
        verdict={{
          level: actors.some((a) => a.type === "Ransomware" || a.type === "APT") ? "high" : "medium",
          label: `${total} match${total === 1 ? "" : "es"} found`,
          action: "Review the matches below — click one to open its full correlated profile.",
        }}
      />
      {malware.length > 0 && (
        <div>
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Malware Families</p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {malware.map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => onOpenMalware(m)}
                className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-left text-xs hover:border-primary/40"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-foreground">{m.name}</span>
                  {m.verified && <Badge variant="low">Confirmed</Badge>}
                </div>
                <p className="mt-1 text-muted">
                  {m.iocSightings} live indicator(s) · {m.mentionCount} article{m.mentionCount === 1 ? "" : "s"}
                </p>
              </button>
            ))}
          </div>
        </div>
      )}
      {actors.length > 0 && (
        <div>
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Threat Actors</p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {actors.map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => onOpenActor(a.name)}
                className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-left text-xs hover:border-primary/40"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-foreground">{a.name}</span>
                  <Badge variant="danger">{a.type}</Badge>
                </div>
                <p className="mt-1 text-muted">
                  {a.targetedIndustries.slice(0, 3).join(", ") || "Targeted industries not reported"} · {a.mentionCount} article{a.mentionCount === 1 ? "" : "s"}
                </p>
              </button>
            ))}
          </div>
        </div>
      )}
      {ransomwareOnly.length > 0 && (
        <div>
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Ransomware / OTX-Tagged Groups (no news profile yet)</p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {ransomwareOnly.map((a) => (
              <div key={a.name} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-left text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-semibold text-foreground">{a.name}</span>
                  <Badge variant="danger">{typeLabel(a.type)}</Badge>
                </div>
                <p className="mt-1 text-muted">
                  {a.campaignCount} campaign{a.campaignCount === 1 ? "" : "s"} · last active {new Date(a.lastActivity).toLocaleDateString()}
                </p>
                <p className="mt-1 text-muted/70">Tracked via {a.type === "ransomware" ? "ransomware.live" : "OTX"} only — no news-derived profile to open yet.</p>
              </div>
            ))}
          </div>
        </div>
      )}
      {campaigns.length > 0 && (
        <div>
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Campaigns</p>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {campaigns.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={onOpenCampaign}
                className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-left text-xs hover:border-primary/40"
              >
                <span className="font-mono font-semibold text-foreground">{c.name}</span>
                <p className="mt-1 text-muted">
                  {c.associatedActors.slice(0, 2).join(", ") || "No actor attribution yet"} · {c.mentionCount} article{c.mentionCount === 1 ? "" : "s"}
                </p>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

interface TriageConsoleProps {
  onOpenActor: (name: string) => void;
  onOpenCampaign: () => void;
}

/**
 * The entry point this app was missing for SOC L1/L2 triage: every other tab
 * is organized by data source/type (CVEs here, IOCs there, malware families
 * over there), which means an analyst working an actual alert -- "what is
 * this IP/hash/CVE and how bad is it" -- had to check several tabs by hand.
 * This takes one pasted value, detects what it is, and answers that question
 * with a single verdict banner, reusing every lookup this app already has
 * (IOC Search's live fan-out, the CVE/malware detail drawers, the entity
 * stores) rather than duplicating any of it.
 */
export function TriageConsole({ onOpenActor, onOpenCampaign }: TriageConsoleProps) {
  const [input, setInput] = useState("");
  const [submitted, setSubmitted] = useState<{ query: string; type: TriageType } | null>(null);

  const [cve, setCve] = useState<CveRecord | null>(null);
  const [cveLoading, setCveLoading] = useState(false);
  const [cveError, setCveError] = useState<string | null>(null);

  const iocSearch = useIocSearch();
  const { selectCve, selectMalware } = useSelection();

  const malwareIntel = useMalwareIntelligence();
  const actorIntel = useThreatActorIntelligence();
  const campaignIntel = useCampaignIntelligence();
  const threatActors = useThreatActors();

  const nameMatches = useMemo(() => {
    if (!submitted || submitted.type !== "name") return null;
    const q = submitted.query;
    const actors = (actorIntel.data?.entities ?? []).filter((e) => matchesQuery(e.name, e.aliases, q)).slice(0, 6);
    // Ransomware groups and OTX-only "adversary" tags never get a
    // threatActorIntelligence record unless news extraction also picked
    // them up by name -- confirmed live that active, well-known ransomware
    // groups can otherwise be completely invisible to this search even
    // though this app already tracks their campaigns elsewhere (Ransomware
    // Data tab, Top Threat Actors). Only added here if not already covered
    // by an `actors` match above, so an actor with both a ransomware.live
    // record AND a real news profile isn't shown twice under two shapes.
    const alreadyCovered = new Set(actors.map((a) => a.name.toLowerCase()));
    const ransomwareOnly = (threatActors.data ?? [])
      .filter((a) => a.name.toLowerCase().includes(q.toLowerCase()) && !alreadyCovered.has(a.name.toLowerCase()))
      .slice(0, 6);
    return {
      malware: (malwareIntel.data?.entities ?? []).filter((e) => matchesQuery(e.name, e.aliases, q)).slice(0, 6),
      actors,
      ransomwareOnly,
      campaigns: (campaignIntel.data?.entities ?? []).filter((e) => matchesQuery(e.name, e.aliases, q)).slice(0, 6),
    };
  }, [submitted, malwareIntel.data, actorIntel.data, campaignIntel.data, threatActors.data]);

  // One hop into this platform's own already-ingested feed -- an IOC search
  // result only tells you what external sources think; this tells you
  // whether it's already been seen inside data this app has been tracking.
  const linkedFamily = useMemo(() => {
    if (!submitted || !iocSearch.data) return null;
    const target = submitted.query.toLowerCase();
    for (const entity of malwareIntel.data?.entities ?? []) {
      if (entity.iocs.some((ioc) => ioc.indicator.toLowerCase() === target)) return entity;
    }
    return null;
  }, [submitted, iocSearch.data, malwareIntel.data]);

  function openMalware(entity: MalwareIntelligenceEntity) {
    selectMalware({ family: entity.name, count: entity.iocSightings, sources: entity.articles.map((a) => a.source), techniques: [], detectionRules: [] });
  }

  async function runTriage(raw: string) {
    const query = raw.trim();
    if (!query) return;
    const type = detectTriageType(query);
    setSubmitted({ query, type });
    setCve(null);
    setCveError(null);

    if (type === "cve") {
      setCveLoading(true);
      try {
        setCve(await fetchCveById(query.toUpperCase()));
      } catch (error) {
        setCveError(error instanceof Error ? error.message : `${query.toUpperCase()} not found`);
      } finally {
        setCveLoading(false);
      }
      return;
    }
    if (type === "ip" || type === "domain" || type === "url" || type === "hash") {
      iocSearch.mutate({ type: type as IocSearchIndicatorType, value: query });
    }
  }

  const isLoading = cveLoading || iocSearch.isPending;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">Triage Console</CardTitle>
        <p className="mt-1 text-xs text-muted">
          Paste anything from an alert — an IP, domain, URL, file hash, CVE ID, or a malware/actor/campaign name — and get one correlated verdict instead of
          checking every tab by hand.
        </p>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            runTriage(input);
          }}
          className="flex flex-wrap gap-2"
        >
          <Input
            autoFocus
            placeholder="e.g. CVE-2026-31431, 185.220.101.5, evil-domain.com, a1b2c3…, LockBit"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="w-full font-mono text-sm sm:w-[26rem]"
          />
          <Button type="submit" disabled={isLoading || !input.trim()}>
            <Search className="h-3.5 w-3.5" />
            Triage
          </Button>
        </form>

        {isLoading && (
          <div className="space-y-2">
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-10 w-full" />
          </div>
        )}

        {!isLoading && submitted && (
          <div className="space-y-1">
            <p className="text-xs text-muted">
              Detected as <span className="font-mono text-foreground">{submitted.type.toUpperCase()}</span>: <span className="font-mono text-foreground">{submitted.query}</span>
            </p>
            {submitted.type === "cve" && <CveResultView cve={cve} cveError={cveError} cveLoading={cveLoading} onViewProfile={() => cve && selectCve(cve)} />}
            {(submitted.type === "ip" || submitted.type === "domain" || submitted.type === "url" || submitted.type === "hash") && (
              <IocResultView
                result={iocSearch.data}
                error={iocSearch.isError ? (iocSearch.error as Error).message : null}
                linkedFamily={linkedFamily}
                onOpenMalware={openMalware}
              />
            )}
            {submitted.type === "name" && nameMatches && (
              <NameMatchView
                query={submitted.query}
                malware={nameMatches.malware}
                actors={nameMatches.actors}
                ransomwareOnly={nameMatches.ransomwareOnly}
                campaigns={nameMatches.campaigns}
                onOpenMalware={openMalware}
                onOpenActor={onOpenActor}
                onOpenCampaign={onOpenCampaign}
              />
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
