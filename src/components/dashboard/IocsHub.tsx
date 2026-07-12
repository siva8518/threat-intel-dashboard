import { useState } from "react";
import { Radar, Clock, Search } from "lucide-react";
import { cn } from "@/lib/utils";
import { ThreatFeedTable } from "./ThreatFeedTable";
import { ThreatTimeline } from "./ThreatTimeline";
import { IocSearch } from "./IocSearch";

const SECTIONS = [
  { id: "threat-feed", label: "Threat Feed", icon: Radar },
  { id: "timeline", label: "Timeline", icon: Clock },
  { id: "ioc-search", label: "IOC Search", icon: Search },
] as const;

type SectionId = (typeof SECTIONS)[number]["id"];

/**
 * Consolidated "IOCs" tab -- Threat Feed, Timeline, and IOC Search were three
 * separate destinations covering the same underlying indicator data from
 * different angles (a live table, a chronological view, a lookup tool).
 * Clicking between them is cheap client-side state, not a route change, so
 * each section keeps its own existing component/query untouched.
 */
export function IocsHub() {
  const [section, setSection] = useState<SectionId>("threat-feed");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold text-foreground">IOCs</h2>
        <div className="flex flex-wrap gap-1.5">
          {SECTIONS.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              type="button"
              onClick={() => setSection(id)}
              className={cn(
                "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
                section === id
                  ? "bg-gradient-primary text-white shadow-glow-primary"
                  : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
              )}
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </button>
          ))}
        </div>
      </div>
      {section === "threat-feed" && <ThreatFeedTable />}
      {section === "timeline" && <ThreatTimeline />}
      {section === "ioc-search" && <IocSearch />}
    </div>
  );
}
