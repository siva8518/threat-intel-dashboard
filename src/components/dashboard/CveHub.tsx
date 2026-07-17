import { useEffect, useState } from "react";
import { ShieldAlert, Wrench } from "lucide-react";
import { CveStatsHeader } from "./CveStatsHeader";
import { CveTable } from "./CveTable";
import { CveProgramActivity } from "./CveProgramActivity";
import { ExploitIntelligence } from "./ExploitIntelligence";
import { RemediationTracker } from "./RemediationTracker";
import type { Severity } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

const SECTIONS = [
  { id: "overview", label: "Latest CVEs", icon: ShieldAlert },
  { id: "remediation", label: "Vulnerabilities Remediation Tracker", icon: Wrench },
] as const;
type SectionId = (typeof SECTIONS)[number]["id"];

interface CveHubProps {
  /** Pre-selects the severity filter -- set from the CVE Severity Distribution widget (see CveSeverityDistribution.tsx) when the user clicks a segment. Always lands on the Latest CVEs section, since that's the only one the filter applies to. */
  initialSeverity?: Severity | null;
}

/**
 * Latest CVEs and the Remediation Tracker are the same underlying CVE data
 * viewed two ways -- the full feed vs. a prioritized, status-tracked patch
 * queue -- so they live together as sections of one tab rather than two
 * separate top-level ones, same pattern as Malware Intelligence and
 * Hunting & Detection.
 */
export function CveHub({ initialSeverity }: CveHubProps = {}) {
  const [section, setSection] = useState<SectionId>("overview");

  useEffect(() => {
    if (initialSeverity) setSection("overview");
  }, [initialSeverity]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5">
        {SECTIONS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setSection(id)}
            className={cn(
              "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
              section === id ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
            )}
          >
            <Icon className="h-3.5 w-3.5" />
            {label}
          </button>
        ))}
      </div>
      {section === "overview" && (
        <>
          <CveStatsHeader />
          <CveTable initialSeverity={initialSeverity} />
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <CveProgramActivity />
            <ExploitIntelligence />
          </div>
        </>
      )}
      {section === "remediation" && <RemediationTracker />}
    </div>
  );
}
