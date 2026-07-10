import { useState } from "react";
import { Github, LayoutDashboard, Network, Newspaper, Search, ShieldAlert, Skull, Radar, UserSearch, Wifi } from "lucide-react";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { ExecutiveThreatSummary } from "@/components/dashboard/ExecutiveThreatSummary";
import { TopThreatActorsToday } from "@/components/dashboard/TopThreatActorsToday";
import { CveStatsHeader } from "@/components/dashboard/CveStatsHeader";
import { CveTable } from "@/components/dashboard/CveTable";
import { CveProgramActivity } from "@/components/dashboard/CveProgramActivity";
import { ThreatFeedTable } from "@/components/dashboard/ThreatFeedTable";
import { CorrelationEngine } from "@/components/dashboard/CorrelationEngine";
import { AttackTechniques } from "@/components/dashboard/AttackTechniques";
import { ThreatActorsHub } from "@/components/dashboard/ThreatActorsHub";
import { ThreatActorProfiles } from "@/components/dashboard/ThreatActorProfiles";
import { IocSearch } from "@/components/dashboard/IocSearch";
import { SecurityNews } from "@/components/dashboard/SecurityNews";
import { SourcesHealthPanel } from "@/components/dashboard/SourcesHealthPanel";
import { McpServerPanel } from "@/components/dashboard/McpServerPanel";
import { GithubIntel } from "@/components/dashboard/GithubIntel";
import { CveDetailDrawer } from "@/components/dashboard/CveDetailDrawer";
import { MalwareDetailDrawer } from "@/components/dashboard/MalwareDetailDrawer";
import { SelectionProvider } from "@/context/SelectionContext";

const TABS = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "cves", label: "Latest CVEs", icon: ShieldAlert },
  { id: "threat-feed", label: "Threat Feed", icon: Radar },
  { id: "correlation-engine", label: "Correlation Engine", icon: Network },
  { id: "actor-profiles", label: "Threat Actor Profiles", icon: UserSearch },
  { id: "attack-techniques", label: "ATT&CK Techniques", icon: ShieldAlert },
  { id: "threat-actors", label: "Threat Actors & Tools", icon: Skull },
  { id: "github-intel", label: "GitHub Intel", icon: Github },
  { id: "ioc-search", label: "IOC Search", icon: Search },
  { id: "news", label: "Security News", icon: Newspaper },
  { id: "sources", label: "Sources", icon: Wifi },
] as const;

type TabId = (typeof TABS)[number]["id"];

export function DashboardPage() {
  const [activeTab, setActiveTab] = useState<TabId>("overview");
  const [countryFilter, setCountryFilter] = useState<string | null>(null);
  const [industryFilter, setIndustryFilter] = useState<string | null>(null);
  const [newsSourceFilter, setNewsSourceFilter] = useState<string | null>(null);

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
    <DashboardLayout tabs={TABS} activeTab={activeTab} onTabChange={(id) => setActiveTab(id as TabId)}>
      {activeTab === "overview" && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <div className="xl:col-span-2">
            <ExecutiveThreatSummary
              onNavigateToActors={() => setActiveTab("threat-actors")}
              onNavigateToCountry={goToCountry}
              onNavigateToIndustry={goToIndustry}
              onNavigateTodayEvent={(tab) => setActiveTab(tab)}
              onNavigateSummaryTab={(tab) => setActiveTab(tab)}
              onNavigateNewsSource={goToNewsSource}
            />
          </div>
          <div className="xl:col-span-1">
            <TopThreatActorsToday onNavigateToActors={() => setActiveTab("threat-actors")} />
          </div>
        </div>
      )}
      {activeTab === "cves" && (
        <>
          <CveStatsHeader />
          <CveTable />
          <CveProgramActivity />
        </>
      )}
      {activeTab === "threat-feed" && <ThreatFeedTable />}
      {activeTab === "correlation-engine" && <CorrelationEngine />}
      {activeTab === "actor-profiles" && <ThreatActorProfiles />}
      {activeTab === "attack-techniques" && <AttackTechniques />}
      {activeTab === "threat-actors" && (
        <ThreatActorsHub
          countryFilter={countryFilter}
          onClearCountryFilter={() => setCountryFilter(null)}
          industryFilter={industryFilter}
          onClearIndustryFilter={() => setIndustryFilter(null)}
        />
      )}
      {activeTab === "github-intel" && <GithubIntel />}
      {activeTab === "ioc-search" && <IocSearch />}
      {activeTab === "news" && <SecurityNews initialSourceFilter={newsSourceFilter} />}
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
