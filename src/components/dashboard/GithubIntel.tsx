import { useMemo, useState } from "react";
import { ArrowLeft, Star, GitFork } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { useGithubIntelList, useGithubIntelStats, useGithubRepoDetail } from "@/hooks/useGithubIntel";
import type { GithubRepoDetail, GithubRepoSummary } from "@/types/threat-intel";

const CATEGORY_OPTIONS = [
  "Exploit PoC",
  "Malware",
  "IOC Feed",
  "Threat Hunting",
  "Detection Engineering",
  "Sigma Rules",
  "YARA Rules",
  "Suricata Rules",
  "DFIR Tool",
  "Threat Intelligence",
  "Security Tool",
  "Research",
];

function scoreVariant(score: number | null): "critical" | "high" | "medium" | "low" | "muted" {
  if (score == null) return "muted";
  if (score >= 70) return "critical";
  if (score >= 40) return "high";
  if (score >= 20) return "medium";
  return "low";
}

/**
 * GitHub Threat Intelligence: repos discovered via GitHub Search (Exploit
 * PoC/Sigma/YARA/Malware categories -- see server/githubIntel/categories.js),
 * classified, content-scanned for IOCs/CVEs/ATT&CK techniques, correlated
 * against this app's existing threat feed, and scored 0-100. Discovery runs
 * hourly (GitHub Search API is rate-limited to 10-30 req/min); enrichment
 * works through the backlog every 15 min -- so "pending enrichment" here is
 * normal, not stuck, especially right after this feature is first enabled.
 */
export function GithubIntel() {
  const [category, setCategory] = useState("");
  const [minScore, setMinScore] = useState(0);
  const [selected, setSelected] = useState<GithubRepoSummary | null>(null);

  const stats = useGithubIntelStats();
  const list = useGithubIntelList({ category: category || undefined, minScore: minScore || undefined });

  if (selected) {
    return <GithubRepoDetailView repo={selected} onBack={() => setSelected(null)} />;
  }

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3 md:flex-row md:items-center">
        <CardTitle className="text-base font-semibold text-foreground">
          GitHub Threat Intelligence{" "}
          <span className="text-muted">(auto-discovered PoC/malware/detection repos, classified &amp; scored)</span>
        </CardTitle>
        <div className="flex w-full flex-wrap gap-2 md:w-auto">
          <Select value={category} onChange={(e) => setCategory(e.target.value)}>
            <option value="">All categories</option>
            {CATEGORY_OPTIONS.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </Select>
          <Select value={minScore} onChange={(e) => setMinScore(Number(e.target.value))}>
            <option value={0}>Any score</option>
            <option value={20}>Score ≥ 20</option>
            <option value={40}>Score ≥ 40</option>
            <option value={70}>Score ≥ 70</option>
          </Select>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {stats.data && (
          <div className="flex flex-wrap gap-4 text-xs text-muted">
            <span>
              <span className="font-semibold text-foreground">{stats.data.totalRepos}</span> repos discovered
            </span>
            <span>
              <span className="font-semibold text-foreground">{stats.data.enrichedRepos}</span> enriched
            </span>
            <span>
              <span className="font-semibold text-foreground">{stats.data.pendingEnrichment}</span> pending (processed ~5 every 15 min)
            </span>
          </div>
        )}

        {list.isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 6 }).map((_, i) => (
              <Skeleton key={i} className="h-9 w-full" />
            ))}
          </div>
        ) : list.isError ? (
          <ErrorState message={(list.error as Error)?.message ?? "GitHub intel is currently unreachable."} />
        ) : (list.data?.repos.length ?? 0) === 0 ? (
          <EmptyState message="No repos matched the current filters yet -- discovery/enrichment may still be warming up." />
        ) : (
          <Table>
            <TableHead>
              <TableRow>
                <TableHeaderCell>Repository</TableHeaderCell>
                <TableHeaderCell>Categories</TableHeaderCell>
                <TableHeaderCell>Stars</TableHeaderCell>
                <TableHeaderCell>Score</TableHeaderCell>
                <TableHeaderCell>CVEs</TableHeaderCell>
                <TableHeaderCell>Feed Matches</TableHeaderCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {list.data!.repos.map((repo) => (
                <TableRow key={repo.fullName} className="cursor-pointer" onClick={() => setSelected(repo)}>
                  <TableCell className="max-w-xs">
                    <div className="truncate font-medium text-foreground">{repo.fullName}</div>
                    <div className="truncate text-xs text-muted">{repo.description}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {repo.categories.slice(0, 2).map((c) => (
                        <Badge key={c.category} variant="muted">
                          {c.category}
                        </Badge>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell className="whitespace-nowrap">{repo.stars.toLocaleString()}</TableCell>
                  <TableCell>
                    <Badge variant={scoreVariant(repo.threatScore)}>{repo.threatScore ?? "—"}</Badge>
                  </TableCell>
                  <TableCell>{repo.cveCount}</TableCell>
                  <TableCell>{repo.matchedFeedCount}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
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

function BadgeList({ items, variant = "muted" }: { items: string[]; variant?: "muted" | "critical" | "high" | "medium" | "low" | "default" }) {
  if (items.length === 0) return <Muted />;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item) => (
        <Badge key={item} variant={variant}>
          {item}
        </Badge>
      ))}
    </div>
  );
}

function GithubRepoDetailView({ repo, onBack }: { repo: GithubRepoSummary; onBack: () => void }) {
  const detail = useGithubRepoDetail(repo.fullName);
  const data: GithubRepoDetail | undefined = detail.data;

  const maxBreakdownContribution = useMemo(
    () => Math.max(1, ...(data?.threatScore?.breakdown.map((b) => b.contribution) ?? [1])),
    [data],
  );

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-2">
        <Button variant="ghost" onClick={onBack} className="-ml-2">
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to list
        </Button>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle className="text-base font-semibold text-foreground">{repo.fullName}</CardTitle>
          <a href={repo.url} target="_blank" rel="noreferrer" className="text-xs text-primary hover:underline">
            View on GitHub ↗
          </a>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        {detail.isLoading && (
          <div className="space-y-2">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        )}

        {detail.isError && <p className="text-sm text-critical">{(detail.error as Error).message}</p>}

        {data && (
          <>
            <p className="text-sm leading-relaxed text-foreground">{data.description || "No description available."}</p>

            <div className="flex flex-wrap items-center gap-4 text-xs text-muted">
              <span className="flex items-center gap-1">
                <Star className="h-3.5 w-3.5" /> {data.stars.toLocaleString()}
              </span>
              <span className="flex items-center gap-1">
                <GitFork className="h-3.5 w-3.5" /> {data.forks.toLocaleString()}
              </span>
              <span>Last commit {new Date(data.lastCommitDate).toLocaleDateString()}</span>
              {data.enrichmentError && <span className="text-critical">Last enrichment attempt failed: {data.enrichmentError}</span>}
            </div>

            <Field label="Categories">
              <div className="flex flex-wrap gap-1.5">
                {data.categories.map((c) => (
                  <Badge key={c.category} variant="default">
                    {c.category} ({Math.round(c.confidence * 100)}%)
                  </Badge>
                ))}
              </div>
            </Field>

            {data.threatScore && (
              <Field label={`Threat Score: ${data.threatScore.score}/100`}>
                <div className="space-y-1.5">
                  {data.threatScore.breakdown.map((b) => (
                    <div key={b.signal} className="flex items-center gap-2 text-xs">
                      <span className="w-40 shrink-0 text-muted">{b.signal}</span>
                      <div className="h-2 flex-1 rounded-full bg-border">
                        <div
                          className="h-2 rounded-full bg-primary"
                          style={{ width: `${(b.contribution / maxBreakdownContribution) * 100}%` }}
                        />
                      </div>
                      <span className="w-10 shrink-0 text-right text-muted">{b.contribution.toFixed(1)}</span>
                    </div>
                  ))}
                </div>
              </Field>
            )}

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label={`CVE IDs (${data.extracted.cveIds.length})`}>
                <BadgeList items={data.extracted.cveIds} variant="critical" />
              </Field>
              <Field label={`ATT&CK Techniques (${data.extracted.attackTechniques.length})`}>
                <BadgeList items={data.extracted.attackTechniques} />
              </Field>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label={`Malware/Ransomware Families (${data.extracted.malwareFamilies.length})`}>
                <BadgeList items={data.extracted.malwareFamilies} variant="high" />
              </Field>
              <Field label={`Threat Actor Mentions (${data.extracted.threatActorNames.length})`}>
                <BadgeList items={data.extracted.threatActorNames} />
              </Field>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label={`Domains/URLs (${data.extracted.domains.length + data.extracted.urls.length})`}>
                <BadgeList items={[...data.extracted.domains, ...data.extracted.urls].slice(0, 20)} />
              </Field>
              <Field label={`IPs (${data.extracted.ipv4.length + data.extracted.ipv6.length})`}>
                <BadgeList items={[...data.extracted.ipv4, ...data.extracted.ipv6]} />
              </Field>
            </div>

            <Field label={`File Hashes (${data.extracted.sha256.length + data.extracted.sha1.length + data.extracted.md5.length})`}>
              <div className="max-h-32 space-y-1 overflow-y-auto font-mono text-xs text-muted">
                {[...data.extracted.sha256, ...data.extracted.sha1, ...data.extracted.md5].slice(0, 20).map((h) => (
                  <div key={h} className="truncate">
                    {h}
                  </div>
                ))}
                {data.extracted.sha256.length + data.extracted.sha1.length + data.extracted.md5.length === 0 && <Muted />}
              </div>
            </Field>

            <Field label={`Correlated with Existing Threat Feed (${data.correlation.matches.length} matches, ${data.correlation.matchedFeeds}/${data.correlation.feedsChecked} feeds)`}>
              {data.correlation.matches.length > 0 ? (
                <ul className="space-y-1">
                  {data.correlation.matches.map((m, i) => (
                    <li key={i} className="text-sm">
                      <span className="font-mono text-xs">{m.indicator}</span>{" "}
                      <span className="text-xs text-muted">
                        seen in {m.sources.join(", ")} (family: {m.malwareFamily})
                      </span>
                    </li>
                  ))}
                </ul>
              ) : (
                <Muted />
              )}
            </Field>

            <Field label={`CVE Enrichment (${data.cveEnrichment.length})`}>
              {data.cveEnrichment.length > 0 ? (
                <ul className="space-y-1.5">
                  {data.cveEnrichment.map((cve) => (
                    <li key={cve.id} className="text-sm">
                      <a href={cve.sourceUrl} target="_blank" rel="noreferrer" className="font-mono text-primary hover:underline">
                        {cve.id}
                      </a>{" "}
                      <Badge variant={cve.severity === "UNKNOWN" ? "muted" : (cve.severity.toLowerCase() as "critical" | "high" | "medium" | "low")}>
                        {cve.severity}
                      </Badge>{" "}
                      {cve.knownExploited && <Badge variant="critical">KEV</Badge>}{" "}
                      {cve.epssScore != null && <span className="text-xs text-muted">EPSS {(cve.epssScore * 100).toFixed(1)}%</span>}
                    </li>
                  ))}
                </ul>
              ) : (
                <Muted />
              )}
            </Field>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field label={`YARA Rule Names (${data.extracted.yaraRuleNames.length})`}>
                <BadgeList items={data.extracted.yaraRuleNames} />
              </Field>
              <Field label={`Sigma Rule IDs (${data.extracted.sigmaRuleIds.length})`}>
                <BadgeList items={data.extracted.sigmaRuleIds} />
              </Field>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
