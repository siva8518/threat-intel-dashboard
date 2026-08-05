import { useState } from "react";
import { Bot, BrainCircuit, Bug, Building2, Crosshair, Eye, Flame, Ghost, Github, LayoutDashboard, Newspaper, ShieldAlert, Siren, Skull, Telescope, UserSearch, Wifi } from "lucide-react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { InvestigationWorkspace } from "@/components/dashboard/InvestigationWorkspace";
import { CveHub } from "@/components/dashboard/CveHub";
import { HuntingDetectionHub } from "@/components/dashboard/HuntingDetectionHub";
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
import { EmergingThreats } from "@/components/dashboard/EmergingThreats";
import { IndustryIntelligence } from "@/components/dashboard/IndustryIntelligence";
import { EmergingThreatsFeed } from "@/components/dashboard/EmergingThreatsFeed";
import { Watchlist } from "@/components/dashboard/Watchlist";
import { CveDetailDrawer } from "@/components/dashboard/CveDetailDrawer";
import { MalwareDetailDrawer } from "@/components/dashboard/MalwareDetailDrawer";
import type { TodayEventKey } from "@/components/dashboard/TopSecurityEventsToday";
import { EMPTY_DATE_RANGE, type DateRange } from "@/components/dashboard/DateRangeFilter";
import { SelectionProvider } from "@/context/SelectionContext";
import type { Severity } from "@/types/threat-intel";

const TABS = [
  { id: "triage", label: "Investigation Workspace", icon: Siren },
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "cves", label: "Latest CVEs", icon: ShieldAlert },
  { id: "attack-techniques", label: "ATT&CK Techniques", icon: ShieldAlert },
  { id: "threat-actors", label: "Ransomware Data", icon: Skull },
  { id: "github-intel", label: "GitHub Intel", icon: Github },
  { id: "malware-intelligence", label: "Malware Intelligence", icon: Bug },
  { id: "actor-intelligence", label: "Threat Actor Intelligence", icon: UserSearch },
  { id: "campaign-intelligence", label: "Campaign Intelligence", icon: Crosshair },
  { id: "darkweb-intelligence", label: "Dark Web Intelligence", icon: Ghost },
  { id: "ai-summarization", label: "AI Summarization", icon: BrainCircuit },
  { id: "emerging-threats", label: "Emerging Threats", icon: Flame },
  { id: "industry-intelligence", label: "Industry Intelligence", icon: Building2 },
  { id: "hunting-detection", label: "Hunting & Detection", icon: Telescope },
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
  const [huntingDetectionSection, setHuntingDetectionSection] = useState<"hunting" | "backlog">("hunting");
  const [triageInitialQuery, setTriageInitialQuery] = useState<string | null>(null);
  const [campaignSearchQuery, setCampaignSearchQuery] = useState<string | null>(null);
  const [malwareSearchQuery, setMalwareSearchQuery] = useState<string | null>(null);
  const [aiSummarySearchQuery, setAiSummarySearchQuery] = useState<string | null>(null);

  /**
   * The Investigation Workspace tab's node-detail-panel jump-off points --
   * each entity type gets a real next step into a tab that has richer,
   * purpose-built tooling than the Workspace's own compact relationship view
   * (the full entity record for actor/campaign/malware, the full report
   * body for report). No new data source, just wiring existing
   * search-prefill patterns (see goToActorSearch above) into the tabs that
   * didn't have one yet.
   */
  function goToTriageInvestigate(query: string) {
    setTriageInitialQuery(query);
    setActiveTab("triage");
  }

  function goToCampaignSearch(name: string) {
    setCampaignSearchQuery(name);
    setActiveTab("campaign-intelligence");
  }

  function goToMalwareSearch(name: string) {
    setMalwareSearchQuery(name);
    setActiveTab("malware-intelligence");
  }

  function goToAiSummarySearch(title: string) {
    setAiSummarySearchQuery(title);
    setActiveTab("ai-summarization");
  }

  function goToDetectionGaps() {
    setHuntingDetectionSection("backlog");
    setActiveTab("hunting-detection");
  }

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
        // Correlation Engine tab removed -- this stat counts today's OTX
        // actor/pulse signals, which the Ransomware Data tab's merged
        // threat-actor list (server/correlate.js#mergeThreatActors) already
        // folds in, same as newRansomwareVictims below.
        setActiveTab("threat-actors");
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
      {activeTab === "triage" && (
        <InvestigationWorkspace
          onOpenActor={goToActorSearch}
          onOpenCampaign={() => setActiveTab("campaign-intelligence")}
          goToCampaignSearch={goToCampaignSearch}
          goToMalwareSearch={goToMalwareSearch}
          goToAiSummarySearch={goToAiSummarySearch}
          initialQuery={triageInitialQuery}
        />
      )}
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
                onNavigateToDetectionGaps={goToDetectionGaps}
              />
              <WorldThreatMap onSelectCountry={goToCountry} />
            </div>
            <div className="space-y-4">
              <DailySummary />
              <CveSeverityDistribution onSelectSeverity={goToCveSeverity} />
              <EmergingThreatsFeed onOpenTab={() => setActiveTab("emerging-threats")} />
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
      {activeTab === "cves" && <CveHub initialSeverity={cveSeverityFilter} />}
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
      {activeTab === "malware-intelligence" && (
        <MalwareIntelligence initialSection={malwareSection} initialDateRange={malwareDateRange} onOpenInvestigationGraph={(_type, key) => goToTriageInvestigate(key)} initialQuery={malwareSearchQuery} />
      )}
      {activeTab === "actor-intelligence" && <ThreatActorIntelligence initialQuery={actorSearchQuery} onOpenInvestigationGraph={(_type, key) => goToTriageInvestigate(key)} />}
      {activeTab === "campaign-intelligence" && <CampaignIntelligence onOpenInvestigationGraph={(_type, key) => goToTriageInvestigate(key)} initialQuery={campaignSearchQuery} />}
      {activeTab === "darkweb-intelligence" && <DarkWebIntelligence />}
      {activeTab === "ai-summarization" && <AiSummarization initialQuery={aiSummarySearchQuery} />}
      {activeTab === "emerging-threats" && <EmergingThreats />}
      {activeTab === "industry-intelligence" && <IndustryIntelligence />}
      {activeTab === "hunting-detection" && <HuntingDetectionHub initialSection={huntingDetectionSection} />}
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
