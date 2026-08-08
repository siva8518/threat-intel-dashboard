// IP / Domain / URL Indicator-Specific Intelligence -- extends the
// buildKeyFacts/renderSourceFacts pattern TriageConsole.tsx already used for
// these three types, plus the new sub-panels (Network Intelligence,
// Registration/DNS/Email Security, URL scan) the redesign adds.
import { ExternalLink } from "lucide-react";
import { Section, KeyValueBlock } from "../reportPrimitives";
import type { IocLookupResult } from "@/types/threat-intel";

function safe(v: unknown): string {
  return v == null || v === "" ? "—" : String(v);
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

interface RelatedIndicatorEntry {
  indicator: string;
  indicatorType: string;
  malwareFamily: string;
  associatedThreatActors: string[];
  activeCampaigns: string[];
}

interface SameAsnEntry {
  indicator: string;
  asn: string | number;
  holder: string | null;
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
  relatedIndicators?: { sameCampaignOrActor: RelatedIndicatorEntry[]; sameAsn: SameAsnEntry[] };
}

function RelatedIndicatorsSection({ data, onPivotToIndicator }: { data: IpModuleData; onPivotToIndicator: (value: string) => void }) {
  const related = data.relatedIndicators;
  if (!related) return null;
  const actorsAndCampaigns = new Set<string>();
  for (const r of related.sameCampaignOrActor) {
    for (const a of r.associatedThreatActors) actorsAndCampaigns.add(a);
    for (const c of r.activeCampaigns) actorsAndCampaigns.add(c);
  }

  return (
    <Section title="Related Indicators">
      <div className="space-y-3">
        <div>
          <p className="mb-1.5 text-xs font-semibold text-foreground">Same Malware Family / Campaign / Actor</p>
          {related.sameCampaignOrActor.length === 0 ? (
            <p className="text-xs text-muted">No other indicators in this platform's own tracked data share a malware family with this IP.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {related.sameCampaignOrActor.map((r) => (
                <button
                  key={r.indicator}
                  type="button"
                  title={`Via malware family: ${r.malwareFamily}`}
                  onClick={() => onPivotToIndicator(r.indicator)}
                  className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-xs text-primary hover:border-primary/50"
                >
                  {r.indicator} →
                </button>
              ))}
            </div>
          )}
        </div>
        <div>
          <p className="mb-1.5 text-xs font-semibold text-foreground">Same ASN</p>
          {related.sameAsn.length === 0 ? (
            <p className="text-xs text-muted">
              {related.sameCampaignOrActor.length === 0
                ? "No sibling indicators to check for a shared ASN."
                : "None of the checked sibling indicators share this IP's ASN."}
            </p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {related.sameAsn.map((r) => (
                <button
                  key={r.indicator}
                  type="button"
                  title={`AS${r.asn}${r.holder ? ` — ${r.holder}` : ""}`}
                  onClick={() => onPivotToIndicator(r.indicator)}
                  className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-xs text-primary hover:border-primary/50"
                >
                  {r.indicator} →
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </Section>
  );
}

export function IpIntelligenceSection({ data, onPivotToIndicator }: { data: IpModuleData; onPivotToIndicator: (value: string) => void }) {
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

      <RelatedIndicatorsSection data={data} onPivotToIndicator={onPivotToIndicator} />

      <Section title="Internal Investigation">
        <div className="rounded-lg border border-dashed border-white/15 bg-white/[0.02] p-3 text-xs text-muted">{data.internalInvestigation.message}</div>
      </Section>
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
    </div>
  );
}
