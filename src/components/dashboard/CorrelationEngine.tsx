import { useState } from "react";
import { Bug, ExternalLink, Github, LayoutGrid, Link2, Share2, ShieldAlert, Skull, Swords, Target } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { CorrelationGraph } from "./CorrelationGraph";
import { useCorrelationEngine } from "@/hooks/useCorrelationEngine";
import { useSelection } from "@/context/SelectionContext";
import { fetchCveById } from "@/api/dashboardApi";
import type { CorrelationCard } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

function CardChip({ children, onClick, loading }: { children: React.ReactNode; onClick?: () => void; loading?: boolean }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!onClick || loading}
      className="rounded-full border border-white/10 bg-white/[0.03] px-2.5 py-1 text-xs transition-colors disabled:cursor-default enabled:cursor-pointer enabled:hover:border-primary/40 enabled:hover:bg-white/[0.06]"
    >
      {children}
    </button>
  );
}

function IntelligenceCard({ card }: { card: CorrelationCard }) {
  const { selectMalware, selectCve } = useSelection();
  const [loadingCve, setLoadingCve] = useState<string | null>(null);

  async function openCve(cveId: string) {
    setLoadingCve(cveId);
    try {
      const record = await fetchCveById(cveId);
      selectCve(record);
    } catch {
      // best-effort -- if the live NVD lookup fails, just don't open the drawer
    } finally {
      setLoadingCve(null);
    }
  }

  return (
    <Card className="space-y-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap gap-1">
          {Array.from({ length: card.entityTypeCount }).map((_, i) => (
            <span key={i} className="h-1.5 w-1.5 rounded-full bg-gradient-primary" />
          ))}
          <span className="ml-1 text-[11px] uppercase tracking-wider text-muted">
            {card.entityTypeCount} linked signal{card.entityTypeCount === 1 ? "" : "s"} · {card.recordCount} record
            {card.recordCount === 1 ? "" : "s"}
          </span>
        </div>
      </div>

      {card.malware.length > 0 && (
        <div>
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">
            <Bug className="h-3.5 w-3.5" /> Malware
          </div>
          <div className="flex flex-wrap gap-1.5">
            {card.malware.map((m) => (
              <CardChip key={m} onClick={() => selectMalware({ family: m, count: 0, sources: [], techniques: [], detectionRules: [] })}>
                {m}
              </CardChip>
            ))}
          </div>
        </div>
      )}

      {card.actors.length > 0 && (
        <div>
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">
            <Skull className="h-3.5 w-3.5" /> Threat Actors
          </div>
          <div className="flex flex-wrap gap-1.5">
            {card.actors.map((a) => (
              <Badge key={a} variant="danger">
                {a}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {card.cves.length > 0 && (
        <div>
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">
            <ShieldAlert className="h-3.5 w-3.5" /> CVEs
          </div>
          <div className="flex flex-wrap gap-1.5">
            {card.cves.map((c) => (
              <CardChip key={c.id} onClick={() => openCve(c.id)} loading={loadingCve === c.id}>
                <span className="font-mono">{c.id}</span>
                {c.knownExploited && <span className="ml-1 text-critical">KEV</span>}
              </CardChip>
            ))}
          </div>
        </div>
      )}

      {card.techniques.length > 0 && (
        <div>
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">
            <Swords className="h-3.5 w-3.5" /> MITRE Techniques
          </div>
          <div className="flex flex-wrap gap-1.5">
            {card.techniques.map((t) => (
              <a
                key={t.id}
                href={t.url}
                target="_blank"
                rel="noreferrer"
                title={t.tactic}
                className="rounded-md bg-primary/10 px-2 py-1 text-xs text-primary hover:underline"
              >
                {t.id}
              </a>
            ))}
          </div>
        </div>
      )}

      {card.iocs.length > 0 && (
        <div>
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">
            <Link2 className="h-3.5 w-3.5" /> Indicators
            {card.totalIocCount > card.iocs.length && <span className="normal-case">(+{card.totalIocCount - card.iocs.length} more)</span>}
          </div>
          <ul className="space-y-1 font-mono text-xs">
            {card.iocs.map((ioc) => (
              <li key={`${ioc.indicatorType}:${ioc.indicator}`} className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.02] px-2.5 py-1.5">
                <Badge variant="muted" className="shrink-0">
                  {ioc.indicatorType}
                </Badge>
                <span className="truncate">{ioc.indicator}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {card.githubRepos.length > 0 && (
        <div>
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">
            <Github className="h-3.5 w-3.5" /> GitHub PoCs
          </div>
          <ul className="space-y-1">
            {card.githubRepos.map((r) => (
              <li key={r.fullName}>
                <a
                  href={r.url}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center justify-between gap-2 rounded-lg border border-white/10 bg-white/[0.02] px-2.5 py-1.5 text-xs transition-colors hover:border-primary/40"
                >
                  <span className="truncate text-foreground">{r.fullName}</span>
                  <span className="shrink-0 text-muted">★ {r.stars}</span>
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}

      {card.ransomwareCampaigns.length > 0 && (
        <div>
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted">
            <Target className="h-3.5 w-3.5" /> Ransomware Campaigns
          </div>
          <ul className="space-y-1">
            {card.ransomwareCampaigns.map((c) => (
              <li key={c.id} className="rounded-lg border border-white/10 bg-white/[0.02] px-2.5 py-1.5 text-xs">
                <span className="font-medium text-foreground">{c.group}</span> vs.{" "}
                {c.sourceUrl ? (
                  <a href={c.sourceUrl} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                    {c.victim}
                    <ExternalLink className="ml-1 inline h-3 w-3" />
                  </a>
                ) : (
                  c.victim
                )}
                <span className="text-muted"> · {c.country}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

function GraphCard({ card }: { card: CorrelationCard }) {
  const { selectMalware, selectCve } = useSelection();

  async function openCve(cveId: string) {
    try {
      selectCve(await fetchCveById(cveId));
    } catch {
      // best-effort -- if the live NVD lookup fails, just don't open the drawer
    }
  }

  return (
    <Card className="p-4">
      <div className="mb-1 flex flex-wrap gap-1">
        {Array.from({ length: card.entityTypeCount }).map((_, i) => (
          <span key={i} className="h-1.5 w-1.5 rounded-full bg-gradient-primary" />
        ))}
        <span className="ml-1 text-[11px] uppercase tracking-wider text-muted">
          {card.entityTypeCount} linked signal{card.entityTypeCount === 1 ? "" : "s"} · {card.recordCount} record
          {card.recordCount === 1 ? "" : "s"}
        </span>
      </div>
      <CorrelationGraph
        card={card}
        onSelectMalware={(family) => selectMalware({ family, count: 0, sources: [], techniques: [], detectionRules: [] })}
        onSelectCve={openCve}
      />
    </Card>
  );
}

type ViewMode = "cards" | "graph";

export function CorrelationEngine() {
  const { cards, isLoading, isError, error } = useCorrelationEngine();
  const [viewMode, setViewMode] = useState<ViewMode>("cards");

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          Threat Correlation Engine{" "}
          <span className="text-muted" title="Automatically links live records sharing a CVE, malware family, threat actor, IP, domain, URL or hash into one card.">
            (unified intelligence, not isolated feed rows)
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="mb-3 text-sm text-muted">
          Every {viewMode === "cards" ? "card" : "graph"} below links two or more of the following signals from live
          data: CVE, malware family, threat actor, and IP/domain/URL/hash indicators. Click a malware family or CVE
          to open its full correlated detail view.
        </p>

        <div className="mb-4 flex gap-1.5">
          <button
            onClick={() => setViewMode("cards")}
            className={cn(
              "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
              viewMode === "cards" ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
            )}
          >
            <LayoutGrid className="h-3.5 w-3.5" />
            Cards
          </button>
          <button
            onClick={() => setViewMode("graph")}
            className={cn(
              "flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors",
              viewMode === "graph" ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
            )}
          >
            <Share2 className="h-3.5 w-3.5" />
            Graph
          </button>
        </div>

        {isLoading ? (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-64 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={(error as Error)?.message ?? "The correlation engine is unavailable right now."} />
        ) : cards.length === 0 ? (
          <EmptyState message="No cross-source correlations found in the current live data." />
        ) : viewMode === "cards" ? (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {cards.map((card, i) => (
              <IntelligenceCard key={i} card={card} />
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {cards.map((card, i) => (
              <GraphCard key={i} card={card} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
