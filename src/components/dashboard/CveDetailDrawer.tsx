import { Bug, ExternalLink, Github, Newspaper, ShieldAlert, Skull, Swords, Target } from "lucide-react";
import { DetailDrawer, DrawerSection } from "./DetailDrawer";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge } from "./SeverityBadge";
import { useSelection } from "@/context/SelectionContext";
import { useCveProfile } from "@/hooks/useCveProfile";

export function CveDetailDrawer() {
  const { selectedCve, clearSelection } = useSelection();
  const profile = useCveProfile(selectedCve?.id ?? null);

  return (
    <DetailDrawer
      open={Boolean(selectedCve)}
      onClose={clearSelection}
      title={
        <a
          href={selectedCve?.sourceUrl}
          target="_blank"
          rel="noreferrer"
          className="flex items-center gap-1.5 font-mono hover:underline"
        >
          {selectedCve?.id}
          <ExternalLink className="h-3.5 w-3.5" />
        </a>
      }
      subtitle={
        selectedCve && (
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={selectedCve.severity} />
            {selectedCve.knownExploited && <Badge variant="danger">Known Exploited</Badge>}
            {selectedCve.cvssScore !== null && <span>CVSS {selectedCve.cvssScore.toFixed(1)}</span>}
            {selectedCve.epssScore !== null && <span>EPSS {(selectedCve.epssScore * 100).toFixed(1)}%</span>}
          </div>
        )
      }
    >
      {selectedCve && (
        <>
          <p className="text-sm leading-relaxed text-muted">{selectedCve.description}</p>

          <DrawerSection title="Threat Actors" icon={<Skull className="h-4 w-4" />}>
            {profile.isLoading ? (
              <Skeleton className="h-16 w-full" />
            ) : profile.data?.relatedActors.length ? (
              <div className="flex flex-wrap gap-2">
                {profile.data.relatedActors.map((a) => (
                  <a
                    key={a.attackId}
                    href={a.url}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded-lg border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-foreground transition-colors hover:border-primary/40 hover:bg-white/[0.06]"
                  >
                    {a.name} <span className="text-muted">({a.attackId})</span>
                  </a>
                ))}
              </div>
            ) : (
              <p className="text-xs text-muted">No ATT&amp;CK-attributed actor cites this CVE.</p>
            )}
          </DrawerSection>

          <DrawerSection title="Related Campaigns" icon={<Target className="h-4 w-4" />}>
            {profile.isLoading ? (
              <Skeleton className="h-16 w-full" />
            ) : profile.data?.relatedCampaigns.length ? (
              <ul className="space-y-2">
                {profile.data.relatedCampaigns.map((c) => (
                  <li key={c.name} className="rounded-lg border border-white/10 bg-white/[0.03] p-3 text-xs">
                    <a href={c.url ?? undefined} target="_blank" rel="noreferrer" className="font-medium text-foreground hover:underline">
                      {c.name}
                    </a>
                    <p className="mt-1 text-muted">{c.description}</p>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted">No MITRE ATT&amp;CK campaign cites this CVE.</p>
            )}
          </DrawerSection>

          <DrawerSection title="MITRE Techniques" icon={<Swords className="h-4 w-4" />}>
            {profile.isLoading ? (
              <Skeleton className="h-10 w-full" />
            ) : profile.data?.relatedTechniques.length ? (
              <div className="flex flex-wrap gap-1.5">
                {profile.data.relatedTechniques.map((t) => (
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
            ) : (
              <p className="text-xs text-muted">No techniques attributed via a citing actor/malware.</p>
            )}
          </DrawerSection>

          <DrawerSection title="Related IOCs" icon={<ShieldAlert className="h-4 w-4" />}>
            {profile.isLoading ? (
              <Skeleton className="h-16 w-full" />
            ) : profile.data?.relatedIocs.length ? (
              <ul className="space-y-1.5 font-mono text-xs">
                {profile.data.relatedIocs.slice(0, 8).map((ioc) => (
                  <li key={ioc.id} className="flex items-center justify-between gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2">
                    <span className="truncate">{ioc.indicator}</span>
                    <Badge variant="muted" className="shrink-0">
                      {ioc.malwareFamily}
                    </Badge>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted">
                {profile.data?.relatedMalware.length
                  ? "None of the malware tied to this CVE currently appears in the live threat feed."
                  : "No malware family is attributed to this CVE, so there's nothing to match against the threat feed."}
              </p>
            )}
          </DrawerSection>

          <DrawerSection title="Exploits (Exploit-DB)" icon={<Bug className="h-4 w-4" />}>
            {profile.isLoading ? (
              <Skeleton className="h-12 w-full" />
            ) : profile.data?.exploits.length ? (
              <ul className="space-y-1.5">
                {profile.data.exploits.map((e) => (
                  <li key={e.exploitId}>
                    <a
                      href={e.url}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center justify-between gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs transition-colors hover:border-primary/40"
                    >
                      <span className="truncate text-foreground">{e.title}</span>
                      {e.verified && (
                        <Badge variant="low" className="shrink-0">
                          verified
                        </Badge>
                      )}
                    </a>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted">No Exploit-DB entry references this CVE ID.</p>
            )}
          </DrawerSection>

          <DrawerSection title="GitHub PoCs" icon={<Github className="h-4 w-4" />}>
            {profile.isLoading ? (
              <Skeleton className="h-12 w-full" />
            ) : profile.data?.githubPocs.length ? (
              <ul className="space-y-1.5">
                {profile.data.githubPocs.map((r) => (
                  <li key={r.fullName}>
                    <a
                      href={r.url}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center justify-between gap-2 rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs transition-colors hover:border-primary/40"
                    >
                      <span className="truncate text-foreground">{r.fullName}</span>
                      <span className="shrink-0 text-muted">★ {r.stars}</span>
                    </a>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted">No tracked GitHub repo mentions this CVE ID.</p>
            )}
          </DrawerSection>

          <DrawerSection title="News Mentions" icon={<Newspaper className="h-4 w-4" />}>
            {profile.isLoading ? (
              <Skeleton className="h-12 w-full" />
            ) : profile.data?.relatedNews.length ? (
              <ul className="space-y-1.5">
                {profile.data.relatedNews.map((n) => (
                  <li key={n.id}>
                    <a
                      href={n.link}
                      target="_blank"
                      rel="noreferrer"
                      className="block rounded-lg border border-white/10 bg-white/[0.03] px-3 py-2 text-xs text-foreground transition-colors hover:border-primary/40"
                    >
                      {n.title} <span className="text-muted">— {n.source}</span>
                    </a>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted">No tracked news article mentions this CVE ID by name.</p>
            )}
          </DrawerSection>

          <p className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-3 text-xs text-muted">
            Not shown: GreyNoise activity. GreyNoise's free tier is an IP-reputation lookup keyed on an IP
            address, and there's no CVE-to-IP relationship in this app's data to correlate against — showing
            a section here would just be empty or fabricated.
          </p>
        </>
      )}
    </DetailDrawer>
  );
}
