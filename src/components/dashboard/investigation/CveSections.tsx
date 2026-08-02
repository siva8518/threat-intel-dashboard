// CVE Indicator-Specific Intelligence -- a thin wrapper around the existing
// CVE correlation engine (server/cveProfile.js, already reused wholesale by
// server/investigation/cveModule.js) and the existing CveDetailDrawer.tsx
// full-profile view, rather than building a second CVE display from
// scratch. Compact facts here; "View full correlated profile" opens the
// same drawer every other CVE entry point in this app already uses.
import { ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { KeyValueBlock } from "../reportPrimitives";
import type { CveRecord, CveProfile } from "@/types/threat-intel";

export function CveIntelligenceSection({ cve, profile, onViewProfile }: { cve: CveRecord; profile: CveProfile | null; onViewProfile: () => void }) {
  return (
    <div className="space-y-4">
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

      {profile && (
        <KeyValueBlock
          title="Correlation Summary"
          pairs={[
            ["Related Threat Actors", profile.relatedActors.length ? profile.relatedActors.map((a) => a.name).join(", ") : null],
            ["Related Malware", profile.relatedMalware.length ? profile.relatedMalware.join(", ") : null],
            ["GitHub PoCs Found", profile.githubPocs.length ? String(profile.githubPocs.length) : null],
            ["Known Exploits", profile.exploits.length ? String(profile.exploits.length) : null],
          ]}
        />
      )}

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
