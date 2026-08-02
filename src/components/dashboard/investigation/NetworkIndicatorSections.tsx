// IP / Domain / URL Indicator-Specific Intelligence -- extends the
// buildKeyFacts/renderSourceFacts pattern TriageConsole.tsx already used for
// these three types, plus the new sub-panels (Network Intelligence,
// Registration/DNS/Email Security, URL scan) the redesign adds.
import { ExternalLink } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Section, KeyValueBlock } from "../reportPrimitives";
import type { IocLookupResult } from "@/types/threat-intel";

function safe(v: unknown): string {
  return v == null || v === "" ? "—" : String(v);
}

const VERDICT_BADGE = { malicious: "critical", suspicious: "high", clean: "low", unknown: "muted" } as const;

function renderSourceFacts(r: IocLookupResult): Array<{ label: string; value: string }> {
  switch (r.source) {
    case "OTX":
      return [
        { label: "Pulses", value: safe(r.pulseCount) },
        ...(Array.isArray(r.tags) && r.tags.length > 0 ? [{ label: "Tags", value: (r.tags as string[]).slice(0, 8).join(", ") }] : []),
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
        ...(Array.isArray(r.threats) && r.threats.length > 0 ? [{ label: "Threats", value: (r.threats as string[]).join(", ") }] : []),
      ];
    case "VirusTotal":
      return [
        { label: "Detections", value: `${r.malicious} malicious · ${r.suspicious} suspicious · ${r.harmless} harmless` },
        ...(r.threatLabel ? [{ label: "Threat Classification", value: String(r.threatLabel) }] : []),
      ];
    case "GreyNoise":
      return [
        { label: "Classification", value: safe(r.classification) },
        ...(r.name ? [{ label: "Known Actor/Scanner", value: String(r.name) }] : []),
        { label: "Known-Benign Service (RIOT)", value: r.riot ? "Yes" : "No" },
      ];
    case "Shodan":
      return [
        ...(r.org ? [{ label: "Organization", value: String(r.org) }] : []),
        ...(Array.isArray(r.openPorts) && r.openPorts.length > 0 ? [{ label: "Open Ports", value: (r.openPorts as number[]).join(", ") }] : []),
        { label: "Known Vulnerabilities", value: safe(r.vulnCount) },
      ];
    case "LeakIX":
      return [
        { label: "Exposed Services", value: safe(r.serviceCount) },
        { label: "Leaks Found", value: safe(r.leakCount) },
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
      ];
    case "SANS ISC":
      return [
        { label: "Reports", value: safe(r.reportCount) },
        { label: "Attack Targets", value: safe(r.attackTargets) },
        { label: "Listed On", value: Array.isArray(r.threatFeeds) ? (r.threatFeeds as string[]).join(", ") : "—" },
      ];
    case "MISP Warning Lists":
      return Array.isArray(r.matchedLists) && r.matchedLists.length > 0
        ? [{ label: "Matched Lists", value: (r.matchedLists as string[]).join(", ") }]
        : [{ label: "Matched Lists", value: "None" }];
    case "crt.sh":
      return [
        { label: "Certificates", value: safe(r.certificateCount) },
        { label: "Subdomains Found", value: safe(r.subdomainCount) },
        ...(r.latestIssuer ? [{ label: "Latest Issuer", value: String(r.latestIssuer) }] : []),
      ];
    case "Hudson Rock":
      return [
        { label: "Infostealer Infections", value: safe(r.infostealerInfections) },
        { label: "Employees Exposed", value: safe(r.employeesExposed) },
      ];
    default:
      return Object.entries(r)
        .filter(([k]) => k !== "source" && k !== "verdict")
        .slice(0, 6)
        .map(([k, v]) => ({ label: k, value: typeof v === "object" ? JSON.stringify(v) : String(v) }));
  }
}

export function SourceBreakdown({ results }: { results: IocLookupResult[] }) {
  if (results.length === 0) return null;
  return (
    <Section title="Reputation Source Breakdown">
      <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {results.map((r) => (
          <div key={r.source} className="rounded-md border border-border p-3 text-xs">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="font-semibold">{r.source}</span>
              <Badge variant={VERDICT_BADGE[r.verdict]}>{r.verdict}</Badge>
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
    </Section>
  );
}

export function NotConfiguredNotice({ notConfigured, rateLimited, skipped }: { notConfigured: string[]; rateLimited: string[]; skipped: { source: string; reason: string }[] }) {
  return (
    <>
      {notConfigured.length > 0 && <p className="text-xs text-muted">Not configured (missing API key): {notConfigured.join(", ")}</p>}
      {rateLimited.length > 0 && <p className="text-xs text-medium">Rate limited, try again shortly: {rateLimited.join(", ")}</p>}
      {skipped.length > 0 && <p className="text-xs text-muted">Not applicable to this indicator: {skipped.map((s) => `${s.source} (${s.reason})`).join(" · ")}</p>}
    </>
  );
}

interface IpModuleData {
  lookupResults: IocLookupResult[];
  network: {
    reverseDns: string | null;
    passiveDns: { available: boolean; records?: Array<{ hostname: string; address: string; recordType: string; firstSeen: string; lastSeen: string }>; reason?: string };
    cidr: string | null;
    asn: string | number | null;
    organization: string | null;
    openPorts: number[];
    country: string | null;
  };
  internalInvestigation: { connected: boolean; message: string };
}

export function IpIntelligenceSection({ data }: { data: IpModuleData }) {
  return (
    <div className="space-y-4">
      <Section title="Network Intelligence">
        <div className="grid grid-cols-2 gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-4 text-sm sm:grid-cols-4">
          <div>
            <p className="text-[11px] uppercase tracking-wide text-muted">Reverse DNS</p>
            <p className="font-mono text-xs font-semibold text-foreground">{safe(data.network.reverseDns)}</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-muted">CIDR / ASN</p>
            <p className="font-mono text-xs font-semibold text-foreground">
              {safe(data.network.cidr)} {data.network.asn ? `· AS${data.network.asn}` : ""}
            </p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-muted">Organization</p>
            <p className="text-xs font-semibold text-foreground">{safe(data.network.organization)}</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wide text-muted">Country</p>
            <p className="text-xs font-semibold text-foreground">{safe(data.network.country)}</p>
          </div>
        </div>
        {data.network.openPorts.length > 0 && (
          <p className="mt-2 text-xs text-muted">Open Ports: <span className="font-mono text-foreground">{data.network.openPorts.join(", ")}</span></p>
        )}
      </Section>

      <Section title="Passive DNS">
        {data.network.passiveDns.available ? (
          data.network.passiveDns.records && data.network.passiveDns.records.length > 0 ? (
            <ul className="space-y-1 text-xs">
              {data.network.passiveDns.records.slice(0, 10).map((r, i) => (
                <li key={i} className="font-mono text-foreground">
                  {r.hostname} <span className="text-muted">({r.recordType}, last seen {new Date(r.lastSeen).toLocaleDateString()})</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted">No passive DNS records found for this IP.</p>
          )
        ) : (
          <p className="text-xs text-muted">Not available — {data.network.passiveDns.reason}</p>
        )}
      </Section>

      <Section title="Internal Investigation">
        <div className="rounded-lg border border-dashed border-white/15 bg-white/[0.02] p-3 text-xs text-muted">{data.internalInvestigation.message}</div>
      </Section>

      <SourceBreakdown results={data.lookupResults} />
    </div>
  );
}

interface DomainModuleData {
  lookupResults: IocLookupResult[];
  registration: Record<string, unknown> | null;
  dnsRecords: { a: string[]; aaaa: string[]; mx: string[]; ns: string[]; cname: string[]; txt: string[] } | null;
  emailSecurity: { spf: string | null; dmarc: { raw: string; policy: string | null } | null; dkim: Array<{ selector: string; record: string }> | null; dkimNote: string | null } | null;
  certificate: IocLookupResult | undefined;
  passiveDns: { available: boolean; records?: Array<{ hostname: string; recordType: string; lastSeen: string }>; reason?: string };
  security: {
    typosquatting: { flagged: boolean; closestBrandMatch: string | null; editDistance: number | null; homographSuspected: boolean };
    dga: { score: number; likely: boolean; entropy?: number; reason?: string };
    parkedOrDisposable: { disposable: boolean; dynamicDns: boolean; note: string };
  };
}

export function DomainIntelligenceSection({ data }: { data: DomainModuleData }) {
  const reg = data.registration as { registered?: boolean; registrar?: string | null; createdDate?: string | null; expiresDate?: string | null; nameservers?: string[] } | null;
  return (
    <div className="space-y-4">
      <KeyValueBlock
        title="Registration (WHOIS via RDAP)"
        pairs={[
          ["Registered", reg?.registered === false ? "Not Registered" : reg?.registered ? "Yes" : null],
          ["Registrar", reg?.registrar ?? null],
          ["Created", reg?.createdDate ? new Date(reg.createdDate).toLocaleDateString() : null],
          ["Expires", reg?.expiresDate ? new Date(reg.expiresDate).toLocaleDateString() : null],
          ["Nameservers", reg?.nameservers?.length ? reg.nameservers.join(", ") : null],
        ]}
      />

      {data.dnsRecords && (
        <Section title="DNS Records">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 text-xs">
            {(["a", "aaaa", "mx", "ns", "cname", "txt"] as const).map((key) =>
              data.dnsRecords![key].length > 0 ? (
                <div key={key}>
                  <p className="mb-1 font-semibold uppercase text-muted">{key}</p>
                  <p className="font-mono text-foreground break-words">{data.dnsRecords![key].join(", ")}</p>
                </div>
              ) : null,
            )}
          </div>
        </Section>
      )}

      {data.emailSecurity && (
        <KeyValueBlock
          title="Email Security (SPF / DKIM / DMARC)"
          pairs={[
            ["SPF", data.emailSecurity.spf],
            ["DMARC Policy", data.emailSecurity.dmarc?.policy ?? null],
            ["DKIM", data.emailSecurity.dkim ? data.emailSecurity.dkim.map((d) => d.selector).join(", ") : data.emailSecurity.dkimNote],
          ]}
        />
      )}

      <Section title="Security Heuristics (best-effort, not a live feed)">
        <div className="space-y-2 text-xs">
          <p>
            <span className="font-semibold text-foreground">Typosquatting/Homograph: </span>
            {data.security.typosquatting.flagged ? (
              <span className="text-high">
                Flagged — resembles “{data.security.typosquatting.closestBrandMatch}”
                {data.security.typosquatting.homographSuspected ? " (homograph substitution suspected)" : ` (edit distance ${data.security.typosquatting.editDistance})`}
              </span>
            ) : (
              <span className="text-muted">No match against known-brand sample list</span>
            )}
          </p>
          <p>
            <span className="font-semibold text-foreground">DGA Likelihood: </span>
            <span className={data.security.dga.likely ? "text-high" : "text-muted"}>
              {Math.round(data.security.dga.score * 100)}% {data.security.dga.likely ? "(likely algorithmically generated)" : "(low)"}
            </span>
          </p>
          <p>
            <span className="font-semibold text-foreground">Parked / Disposable: </span>
            <span className="text-muted">
              {data.security.parkedOrDisposable.disposable ? "Matches disposable-domain sample" : data.security.parkedOrDisposable.dynamicDns ? "Dynamic DNS provider" : "No match"}
            </span>
          </p>
        </div>
      </Section>

      <Section title="Passive DNS">
        {data.passiveDns.available ? (
          data.passiveDns.records && data.passiveDns.records.length > 0 ? (
            <ul className="space-y-1 text-xs">
              {data.passiveDns.records.slice(0, 10).map((r, i) => (
                <li key={i} className="font-mono text-foreground">
                  {r.hostname} <span className="text-muted">({r.recordType})</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted">No passive DNS records found for this domain.</p>
          )
        ) : (
          <p className="text-xs text-muted">Not available — {data.passiveDns.reason}</p>
        )}
      </Section>

      {data.certificate && (
        <KeyValueBlock
          title="Certificate Info"
          pairs={[
            ["Certificates Found", safe(data.certificate.certificateCount)],
            ["Subdomains Found", safe(data.certificate.subdomainCount)],
            ["Latest Issuer", data.certificate.latestIssuer ? String(data.certificate.latestIssuer) : null],
          ]}
        />
      )}

      <SourceBreakdown results={data.lookupResults} />
    </div>
  );
}

interface UrlModuleData {
  lookupResults: IocLookupResult[];
  components: { valid: boolean; protocol?: string; host?: string; port?: string | null; path?: string; fragment?: string | null };
  scan: {
    scanUrl: string | null;
    screenshotUrl: string | null;
    finalUrl: string | null;
    pageTitle: string | null;
    malicious: boolean;
    categories: string[];
    tags: string[];
    notScanned?: boolean;
    reason?: string;
  } | null;
}

export function UrlIntelligenceSection({ data }: { data: UrlModuleData }) {
  return (
    <div className="space-y-4">
      <KeyValueBlock
        title="URL Components"
        pairs={[
          ["Protocol", data.components.protocol ?? null],
          ["Host", data.components.host ?? null],
          ["Port", data.components.port ?? null],
          ["Path", data.components.path ?? null],
        ]}
      />

      <Section title="Scan Results (urlscan.io)">
        {data.scan && !data.scan.notScanned ? (
          <div className="space-y-2 text-xs">
            {data.scan.screenshotUrl && (
              <img src={data.scan.screenshotUrl} alt="Page screenshot" className="max-w-sm rounded-lg border border-white/10" loading="lazy" />
            )}
            <KeyValueBlock
              title=""
              pairs={[
                ["Page Title", data.scan.pageTitle],
                ["Final URL (after redirects)", data.scan.finalUrl],
                ["Classification", data.scan.malicious ? "Malicious" : "No malicious classification"],
                ["Categories", data.scan.categories.length ? data.scan.categories.join(", ") : null],
              ]}
            />
            {data.scan.scanUrl && (
              <a href={data.scan.scanUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                Full scan report on urlscan.io <ExternalLink className="h-3 w-3" />
              </a>
            )}
          </div>
        ) : (
          <p className="text-xs text-muted">Not available — {data.scan?.reason ?? "No scan data returned."}</p>
        )}
      </Section>

      <SourceBreakdown results={data.lookupResults} />
    </div>
  );
}
