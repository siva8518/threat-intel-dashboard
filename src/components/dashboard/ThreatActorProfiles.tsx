import { useEffect, useMemo, useState } from "react";
import { ArrowLeft, Search } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { useThreatActorList, useThreatActorProfile, useThreatActorSearch } from "@/hooks/useThreatActorProfiles";
import type { ThreatActorSummary } from "@/types/threat-intel";

interface ThreatActorProfilesProps {
  /** Pre-fills the search box -- set from the platform search palette (see CommandPalette.tsx) when the user picks an actor result. */
  initialQuery?: string | null;
}

/**
 * Threat Actor Profile tab: MITRE ATT&CK Groups as the primary source
 * (name/aliases/description/country/motivation/industries/active-since/
 * malware/tools/techniques/campaigns), enriched with OTX, the deduped
 * threat feed (ThreatFox/MalwareBazaar/etc.), ransomware.live, security
 * news, and live NVD keyword search -- see server/actorProfile.js.
 */
export function ThreatActorProfiles({ initialQuery }: ThreatActorProfilesProps = {}) {
  const [query, setQuery] = useState(initialQuery ?? "");
  const [selected, setSelected] = useState<ThreatActorSummary | null>(null);
  const debouncedQuery = useDebouncedValue(query, 400);

  useEffect(() => {
    if (initialQuery) setQuery(initialQuery);
  }, [initialQuery]);

  const list = useThreatActorList();
  const search = useThreatActorSearch(debouncedQuery);

  const actors = debouncedQuery.trim() ? search.data?.actors : list.data?.actors;
  const isLoading = debouncedQuery.trim() ? search.isLoading : list.isLoading;

  if (selected) {
    return <ThreatActorDetail actor={selected} onBack={() => setSelected(null)} />;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          Threat Actor Profiles <span className="text-muted">(MITRE ATT&amp;CK, enriched with OTX, ThreatFox, MalwareBazaar &amp; security news)</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="relative w-full sm:w-96">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted" />
          <Input
            placeholder="Search by actor name or alias (e.g. APT29, Cozy Bear)…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-8"
          />
        </div>

        {isLoading && (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-16 w-full" />
            ))}
          </div>
        )}

        {!isLoading && (actors ?? []).length === 0 && (
          <p className="text-sm text-muted">No threat actors match "{query}".</p>
        )}

        {!isLoading && (actors?.length ?? 0) > 0 && (
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {actors!.map((actor) => (
              <button
                key={actor.attackId}
                onClick={() => setSelected(actor)}
                className="rounded-md border border-border p-3 text-left text-sm transition-colors hover:border-primary hover:bg-primary/5"
              >
                <div className="font-semibold text-foreground">{actor.name}</div>
                {actor.aliases.length > 0 && (
                  <div className="mt-0.5 truncate text-xs text-muted">aka {actor.aliases.join(", ")}</div>
                )}
                {actor.country && (
                  <Badge variant="muted" className="mt-1.5">
                    {actor.country}
                  </Badge>
                )}
              </button>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ThreatActorDetail({ actor, onBack }: { actor: ThreatActorSummary; onBack: () => void }) {
  const profile = useThreatActorProfile(actor.attackId);

  const timelineSample = useMemo(() => profile.data?.timeline.slice(0, 15) ?? [], [profile.data]);

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-2">
        <Button variant="ghost" onClick={onBack} className="-ml-2">
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to search
        </Button>
        <CardTitle className="text-base font-semibold text-foreground">{actor.name}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        {profile.isLoading && (
          <div className="space-y-2">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        )}

        {profile.isError && <p className="text-sm text-critical">{(profile.error as Error).message}</p>}

        {profile.data && (
          <>
            <Field label="Aliases">
              {profile.data.aliases.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {profile.data.aliases.map((alias) => (
                    <Badge key={alias} variant="muted">
                      {alias}
                    </Badge>
                  ))}
                </div>
              ) : (
                <Muted />
              )}
            </Field>

            <Field label="Description">
              <p className="text-sm leading-relaxed text-foreground">{profile.data.description || "No description available."}</p>
              {profile.data.url && (
                <a href={profile.data.url} target="_blank" rel="noreferrer" className="mt-1 inline-block text-xs text-primary hover:underline">
                  MITRE ATT&amp;CK reference ↗
                </a>
              )}
            </Field>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <Field label="Country">{profile.data.country ? <Badge variant="danger">{profile.data.country}</Badge> : <Muted />}</Field>
              <Field label="Active Since">{profile.data.activeSince ? <span className="text-sm">{profile.data.activeSince}</span> : <Muted />}</Field>
              <Field label="Motivation">
                {profile.data.motivations.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {profile.data.motivations.map((m) => (
                      <Badge key={m} variant="default">
                        {m}
                      </Badge>
                    ))}
                  </div>
                ) : (
                  <Muted />
                )}
              </Field>
            </div>

            <Field label="Target Industries">
              {profile.data.targetIndustries.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {profile.data.targetIndustries.map((industry) => (
                    <Badge key={industry} variant="medium">
                      {industry}
                    </Badge>
                  ))}
                </div>
              ) : (
                <Muted />
              )}
            </Field>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label={`Malware Used (${profile.data.malwareUsed.length})`}>
                {profile.data.malwareUsed.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {profile.data.malwareUsed.map((m) => (
                      <a key={m.name} href={m.url} target="_blank" rel="noreferrer">
                        <Badge variant="critical">{m.name}</Badge>
                      </a>
                    ))}
                  </div>
                ) : (
                  <Muted />
                )}
              </Field>
              <Field label={`Tools Used (${profile.data.toolsUsed.length})`}>
                {profile.data.toolsUsed.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {profile.data.toolsUsed.map((t) => (
                      <a key={t.name} href={t.url} target="_blank" rel="noreferrer">
                        <Badge variant="high">{t.name}</Badge>
                      </a>
                    ))}
                  </div>
                ) : (
                  <Muted />
                )}
              </Field>
            </div>

            <Field label={`Malware (Malpedia, ${profile.data.malpediaMalware.length})`}>
              {profile.data.malpediaMalware.length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {profile.data.malpediaMalware.map((m) => (
                    <a key={m.name} href={m.url} target="_blank" rel="noreferrer">
                      <Badge variant="medium">{m.name}</Badge>
                    </a>
                  ))}
                </div>
              ) : (
                <Muted />
              )}
            </Field>

            <Field label={`ATT&CK Techniques (${profile.data.techniques.length})`}>
              {profile.data.techniques.length > 0 ? (
                <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto">
                  {profile.data.techniques.map((t) => (
                    <a key={t.id} href={t.url} target="_blank" rel="noreferrer" title={t.name}>
                      <Badge variant="muted">{t.id}</Badge>
                    </a>
                  ))}
                </div>
              ) : (
                <Muted />
              )}
            </Field>

            <Field label={`Related Campaigns (${profile.data.relatedCampaigns.length})`}>
              {profile.data.relatedCampaigns.length > 0 ? (
                <ul className="space-y-1.5">
                  {profile.data.relatedCampaigns.map((c, i) => (
                    <li key={i} className="text-sm">
                      {c.url ? (
                        <a href={c.url} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                          {c.name}
                        </a>
                      ) : (
                        <span className="text-foreground">{c.name}</span>
                      )}{" "}
                      <span className="text-xs text-muted">
                        ({c.source}
                        {c.date ? `, ${new Date(c.date).toLocaleDateString()}` : ""})
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <Muted />
              )}
            </Field>

            <Field label={`Related CVEs (${profile.data.relatedCves.length})`}>
              {profile.data.relatedCves.length > 0 ? (
                <ul className="space-y-1.5">
                  {profile.data.relatedCves.map((cve) => (
                    <li key={cve.id} className="text-sm">
                      <a href={cve.sourceUrl} target="_blank" rel="noreferrer" className="font-mono text-primary hover:underline">
                        {cve.id}
                      </a>{" "}
                      <Badge variant={cve.severity === "UNKNOWN" ? "muted" : (cve.severity.toLowerCase() as "critical" | "high" | "medium" | "low")}>
                        {cve.severity}
                      </Badge>
                    </li>
                  ))}
                </ul>
              ) : (
                <Muted />
              )}
            </Field>

            <Field label={`Related Malware (live IOCs, ${profile.data.relatedMalware.length})`}>
              {profile.data.relatedMalware.length > 0 ? (
                <ul className="space-y-1">
                  {profile.data.relatedMalware.slice(0, 10).map((m, i) => (
                    <li key={i} className="truncate font-mono text-xs text-muted">
                      {m.malwareFamily} — {m.indicator}
                    </li>
                  ))}
                </ul>
              ) : (
                <Muted />
              )}
            </Field>

            <Field label={`Recent News (${profile.data.recentNews.length})`}>
              {profile.data.recentNews.length > 0 ? (
                <ul className="space-y-1.5">
                  {profile.data.recentNews.map((n) => (
                    <li key={n.id} className="text-sm">
                      <a href={n.link} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                        {n.title}
                      </a>{" "}
                      <span className="text-xs text-muted">({n.source})</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <Muted />
              )}
            </Field>

            <Field label="Timeline">
              {timelineSample.length > 0 ? (
                <ol className="space-y-1.5 border-l border-border pl-3">
                  {timelineSample.map((event, i) => (
                    <li key={i} className="text-sm">
                      <span className="text-xs text-muted">{new Date(event.date).toLocaleDateString()}</span>{" "}
                      {event.url ? (
                        <a href={event.url} target="_blank" rel="noreferrer" className="text-primary hover:underline">
                          {event.label}
                        </a>
                      ) : (
                        <span>{event.label}</span>
                      )}
                    </li>
                  ))}
                </ol>
              ) : (
                <Muted />
              )}
            </Field>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">{label}</p>
      {children}
    </div>
  );
}

function Muted() {
  return <span className="text-xs text-muted">Not available.</span>;
}
