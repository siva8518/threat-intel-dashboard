import { useState } from "react";
import { Bot, Bug, Github, LayoutDashboard, Network, Newspaper, Search, ShieldAlert, Skull, UserSearch, Wifi } from "lucide-react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
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
import { IocsHub } from "@/components/dashboard/IocsHub";
import { CorrelationEngine } from "@/components/dashboard/CorrelationEngine";
import { AttackTechniques } from "@/components/dashboard/AttackTechniques";
import { AttackTacticHeatmap } from "@/components/dashboard/AttackTacticHeatmap";
import { ThreatActorsHub } from "@/components/dashboard/ThreatActorsHub";
import { ThreatActorProfiles } from "@/components/dashboard/ThreatActorProfiles";
import { SecurityNews } from "@/components/dashboard/SecurityNews";
import { SourcesHealthPanel } from "@/components/dashboard/SourcesHealthPanel";
import { McpServerPanel } from "@/components/dashboard/McpServerPanel";
import { GithubIntel } from "@/components/dashboard/GithubIntel";
import { Chatbot } from "@/components/dashboard/Chatbot";
import { MalwareIntelligence } from "@/components/dashboard/MalwareIntelligence";
import { CveDetailDrawer } from "@/components/dashboard/CveDetailDrawer";
import { MalwareDetailDrawer } from "@/components/dashboard/MalwareDetailDrawer";
import { SelectionProvider } from "@/context/SelectionContext";
import type { Severity } from "@/types/threat-intel";

const TABS = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "cves", label: "Latest CVEs", icon: ShieldAlert },
  { id: "threat-feed", label: "IOCs", icon: Search },
  { id: "correlation-engine", label: "Correlation Engine", icon: Network },
  { id: "actor-profiles", label: "Threat Actor Profiles", icon: UserSearch },
  { id: "attack-techniques", label: "ATT&CK Techniques", icon: ShieldAlert },
  { id: "threat-actors", label: "Ransomware Data", icon: Skull },
  { id: "github-intel", label: "GitHub Intel", icon: Github },
  { id: "malware-intelligence", label: "Malware Intelligence", icon: Bug },
  { id: "news", label: "Security News", icon: Newspaper },
  { id: "ai-assistant", label: "AI Assistant", icon: Bot },
  { id: "sources", label: "Sources", icon: Wifi },
] as const;

type TabId = (typeof TABS)[number]["id"];

export function DashboardPage() {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [countryFilter, setCountryFilter] = useState<string | null>(null);
  const [industryFilter, setIndustryFilter] = useState<string | null>(null);
  const [newsSourceFilter, setNewsSourceFilter] = useState<string | null>(null);
  const [actorSearchQuery, setActorSearchQuery] = useState<string | null>(null);
  const [cveSeverityFilter, setCveSeverityFilter] = useState<Severity | null>(null);

  function goToActorSearch(name: string) {
    setActorSearchQuery(name);
    setActiveTab("actor-profiles");
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

  function goToNewsSource(source: string) {
    setNewsSourceFilter(source);
    setActiveTab("news");
  }

  return (
    <SelectionProvider>
    <DashboardLayout tabs={TABS} activeTab={activeTab} onTabChange={(id) => setActiveTab(id as TabId)} onSelectActor={goToActorSearch}>
      {activeTab === "overview" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="space-y-4">
              <ExecutiveThreatSummary
                onNavigateToActors={() => setActiveTab("threat-actors")}
                onNavigateToCountry={goToCountry}
                onNavigateToIndustry={goToIndustry}
                onNavigateTodayEvent={(tab) => setActiveTab(tab)}
              />
              <WorldThreatMap onSelectCountry={goToCountry} />
            </div>
            <div className="space-y-4">
              <div className="grid grid-cols-1 items-start gap-4 sm:grid-cols-2">
                <DailySummary onNavigateTab={(tab) => setActiveTab(tab)} onNavigateNewsSource={goToNewsSource} />
                <CveSeverityDistribution onSelectSeverity={goToCveSeverity} />
              </div>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <TopMalware />
                <ThreatScoreTrend />
                <CampaignVolumeTrend />
              </div>
            </div>
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <TopThreatActors onNavigateToActors={() => setActiveTab("threat-actors")} />
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
      {activeTab === "threat-feed" && <IocsHub />}
      {activeTab === "correlation-engine" && <CorrelationEngine />}
      {activeTab === "actor-profiles" && <ThreatActorProfiles initialQuery={actorSearchQuery} />}
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
        />
      )}
      {activeTab === "github-intel" && <GithubIntel />}
      {activeTab === "malware-intelligence" && <MalwareIntelligence />}
      {activeTab === "news" && <SecurityNews initialSourceFilter={newsSourceFilter} />}
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
