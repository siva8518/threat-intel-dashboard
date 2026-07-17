import { useState } from "react";
import { Bot, BrainCircuit, Bug, Crosshair, Eye, Ghost, Github, LayoutDashboard, Network, Newspaper, ShieldAlert, Siren, Skull, UserSearch, Wifi, Wrench } from "lucide-react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { TriageConsole } from "@/components/dashboard/TriageConsole";
import { RemediationTracker } from "@/components/dashboard/RemediationTracker";
import { ExecutiveThreatSummary } from "@/components/dashboard/ExecutiveThreatSummary";
import { WorldThreatMap } from "@/components/dashboard/WorldThreatMap";
import { TopMitreTechniques } from "@/components/dashboard/TopMitreTechniques";
import { DailySummary } from "@/components/dashboard/DailySummary";
import { CveSeverityDistribution } from "@/components/dashboard/CveSeverityDistribution";
import { TopMalware } from "@/components/dashboard/TopMalware";
import { ThreatScoreTrend } from "@/components/dashboard/ThreatScoreTrend";
import { CampaignVolumeTrend } from "@/components/dashboard/CampaignVolumeTrend";
import { TopThreatActors } from "@/components/dashboard/TopThreatActors";
import { TopCves } from "@/components/dashboard/TopCves";
import { CveStatsHeader } from "@/components/dashboard/CveStatsHeader";
import { CveTable } from "@/components/dashboard/CveTable";
import { CveProgramActivity } from "@/components/dashboard/CveProgramActivity";
import { ExploitIntelligence } from "@/components/dashboard/ExploitIntelligence";
import { CorrelationEngine } from "@/components/dashboard/CorrelationEngine";
import { AttackTechniques } from "@/components/dashboard/AttackTechniques";
import { AttackTacticHeatmap } from "@/components/dashboard/AttackTacticHeatmap";
import { ThreatActorsHub } from "@/components/dashboard/ThreatActorsHub";
import { SecurityNews } from "@/components/dashboard/SecurityNews";
import { SourcesHealthPanel } from "@/components/dashboard/SourcesHealthPanel";
import { McpServerPanel } from "@/components/dashboard/McpServerPanel";
import { GithubIntel } from "@/components/dashboard/GithubIntel";
import { Chatbot } from "@/components/dashboard/Chatbot";
import { MalwareIntelligence } from "@/components/dashboard/MalwareIntelligence";
import { ThreatActorIntelligence } from "@/components/dashboard/ThreatActorIntelligence";
import { CampaignIntelligence } from "@/components/dashboard/CampaignIntelligence";
import { DarkWebIntelligence } from "@/components/dashboard/DarkWebIntelligence";
import { AiSummarization } from "@/components/dashboard/AiSummarization";
import { Watchlist } from "@/components/dashboard/Watchlist";
import { CveDetailDrawer } from "@/components/dashboard/CveDetailDrawer";
import { MalwareDetailDrawer } from "@/components/dashboard/MalwareDetailDrawer";
import type { TodayEventKey } from "@/components/dashboard/TopSecurityEventsToday";
import { EMPTY_DATE_RANGE, type DateRange } from "@/components/dashboard/DateRangeFilter";
import { SelectionProvider } from "@/context/SelectionContext";
import type { Severity } from "@/types/threat-intel";

const TABS = [
  { id: "triage", label: "Triage Console", icon: Siren },
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "cves", label: "Latest CVEs", icon: ShieldAlert },
  { id: "remediation-tracker", label: "Remediation Tracker", icon: Wrench },
  { id: "correlation-engine", label: "Correlation Engine", icon: Network },
  { id: "attack-techniques", label: "ATT&CK Techniques", icon: ShieldAlert },
  { id: "threat-actors", label: "Ransomware Data", icon: Skull },
  { id: "github-intel", label: "GitHub Intel", icon: Github },
  { id: "malware-intelligence", label: "Malware Intelligence", icon: Bug },
  { id: "actor-intelligence", label: "Threat Actor Intelligence", icon: UserSearch },
  { id: "campaign-intelligence", label: "Campaign Intelligence", icon: Crosshair },
  { id: "darkweb-intelligence", label: "Dark Web Intelligence", icon: Ghost },
  { id: "ai-summarization", label: "AI Summarization", icon: BrainCircuit },
  { id: "news", label: "Security News", icon: Newspaper },
  { id: "watchlist", label: "Watchlist", icon: Eye },
  { id: "ai-assistant", label: "Chat Bot", icon: Bot },
  { id: "sources", label: "Sources", icon: Wifi },
] as const;

type TabId = (typeof TABS)[number]["id"];

/** Today's calendar date, from-only range (open-ended going forward) -- matches exactly what server/todaySecurityEvents.js itself counts as "today," so a stat tile's click target shows precisely what the tile counted, not a wider or narrower set. */
function todayOnwardRange(): DateRange {
  return { from: new Date().toISOString().slice(0, 10), to: "" };
}

export function DashboardPage() {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [countryFilter, setCountryFilter] = useState<string | null>(null);
  const [industryFilter, setIndustryFilter] = useState<string | null>(null);
  const [actorSearchQuery, setActorSearchQuery] = useState<string | null>(null);
  const [cveSeverityFilter, setCveSeverityFilter] = useState<Severity | null>(null);
  const [malwareSection, setMalwareSection] = useState<"families" | "iocs">("families");
  const [malwareDateRange, setMalwareDateRange] = useState<DateRange>(EMPTY_DATE_RANGE);
  const [ransomwareDateRange, setRansomwareDateRange] = useState<DateRange>(EMPTY_DATE_RANGE);

  function goToActorSearch(name: string) {
    setActorSearchQuery(name);
    setActiveTab("actor-intelligence");
  }

  function goToCveSeverity(severity: Severity) {
    setCveSeverityFilter(severity);
    setActiveTab("cves");
  }

  function goToCountry(countryCode: string) {
    setCountryFilter(countryCode);
    setActiveTab("threat-actors");
  }

  function goToIndustry(industry: string) {
    setIndustryFilter(industry);
    setActiveTab("threat-actors");
  }

  /**
   * Every "New X" stat on the Overview tab used to land on its destination
   * tab showing everything ever tracked, not just what the tile counted --
   * confirmed live, that read as broken ("it says 40 new samples but the
   * list has hundreds"). Malware/ransomware stats now seed that tab's own
   * calendar filter to today (matching server/todaySecurityEvents.js's own
   * same-day count exactly); clearing the calendar there still reaches
   * everything.
   */
  function goToTodayEvent(key: TodayEventKey) {
    switch (key) {
      case "activeExploitCampaigns":
        setActiveTab("correlation-engine");
        break;
      case "githubExploits":
        setActiveTab("github-intel");
        break;
      case "newRansomwareVictims":
        setRansomwareDateRange(todayOnwardRange());
        setActiveTab("threat-actors");
        break;
      case "newMalwareSamples":
      case "newIocs":
        setMalwareSection("iocs");
        setMalwareDateRange(todayOnwardRange());
        setActiveTab("malware-intelligence");
        break;
    }
  }

  return (
    <SelectionProvider>
    <DashboardLayout tabs={TABS} activeTab={activeTab} onTabChange={(id) => setActiveTab(id as TabId)} onSelectActor={goToActorSearch}>
      {activeTab === "triage" && <TriageConsole onOpenActor={goToActorSearch} onOpenCampaign={() => setActiveTab("campaign-intelligence")} />}
      {activeTab === "overview" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="space-y-4">
              <ExecutiveThreatSummary
                onNavigateToActors={() => setActiveTab("threat-actors")}
                onNavigateToCampaigns={() => setActiveTab("campaign-intelligence")}
                onNavigateToCountry={goToCountry}
                onNavigateToIndustry={goToIndustry}
                onNavigateTodayEvent={goToTodayEvent}
              />
              <WorldThreatMap onSelectCountry={goToCountry} />
            </div>
            <div className="space-y-4">
              <DailySummary />
              <CveSeverityDistribution onSelectSeverity={goToCveSeverity} />
            </div>
          </div>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <TopMalware />
            <ThreatScoreTrend />
            <CampaignVolumeTrend />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <TopThreatActors onSelectActor={goToActorSearch} />
            <TopCves />
          </div>
          <TopMitreTechniques />
        </div>
      )}
      {activeTab === "cves" && (
        <>
          <CveStatsHeader />
          <CveTable initialSeverity={cveSeverityFilter} />
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <CveProgramActivity />
            <ExploitIntelligence />
          </div>
        </>
      )}
      {activeTab === "remediation-tracker" && <RemediationTracker />}
      {activeTab === "correlation-engine" && <CorrelationEngine />}
      {activeTab === "attack-techniques" && (
        <>
          <AttackTacticHeatmap />
          <AttackTechniques />
        </>
      )}
      {activeTab === "threat-actors" && (
        <ThreatActorsHub
          countryFilter={countryFilter}
          onClearCountryFilter={() => setCountryFilter(null)}
          industryFilter={industryFilter}
          onClearIndustryFilter={() => setIndustryFilter(null)}
          initialDateRange={ransomwareDateRange}
        />
      )}
      {activeTab === "github-intel" && <GithubIntel />}
      {activeTab === "malware-intelligence" && <MalwareIntelligence initialSection={malwareSection} initialDateRange={malwareDateRange} />}
      {activeTab === "actor-intelligence" && <ThreatActorIntelligence initialQuery={actorSearchQuery} />}
      {activeTab === "campaign-intelligence" && <CampaignIntelligence />}
      {activeTab === "darkweb-intelligence" && <DarkWebIntelligence />}
      {activeTab === "ai-summarization" && <AiSummarization />}
      {activeTab === "news" && <SecurityNews />}
      {activeTab === "watchlist" && <Watchlist />}
      {activeTab === "ai-assistant" && <Chatbot />}
      {activeTab === "sources" && (
        <>
          <SourcesHealthPanel />
          <McpServerPanel />
        </>
      )}
    </DashboardLayout>
    <CveDetailDrawer />
    <MalwareDetailDrawer />
    </SelectionProvider>
  );
}
