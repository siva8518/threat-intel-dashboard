import { Fragment, useEffect, useMemo, useState } from "react";
import { Check, Copy, ExternalLink, FileCode, Pencil, Radar, Sparkles, Wrench } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeaderCell, TableRow } from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge } from "./SeverityBadge";
import { ErrorState, EmptyState } from "./ErrorState";
import { useHuntingLibrary } from "@/hooks/useHuntingLibrary";
import { useDetectionBacklog } from "@/hooks/useDetectionBacklog";
import type { DetectionBacklogItem, DetectionBacklogStatus, DraftRule, HuntingQueryItem, HuntingQueryPlatform } from "@/types/threat-intel";
import { cn } from "@/lib/utils";

const SECTIONS = [
  { id: "hunting", label: "Hunting Queries", icon: Radar },
  { id: "backlog", label: "Detection Backlog", icon: Wrench },
] as const;
type SectionId = (typeof SECTIONS)[number]["id"];

// --- Hunting Queries -------------------------------------------------------

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      className="flex items-center gap-1 rounded-md border border-white/10 bg-white/[0.03] px-2 py-1 text-[11px] text-muted transition-colors hover:text-foreground"
    >
      {copied ? <Check className="h-3 w-3 text-low" /> : <Copy className="h-3 w-3" />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function HuntingQueryCard({ item }: { item: HuntingQueryItem }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant="cyan">{item.platformLabel}</Badge>
          <SeverityBadge severity={item.severity} />
          {item.cveIds.map((id) => (
            <Badge key={id} variant="danger">
              {id}
            </Badge>
          ))}
          {item.malware.map((m) => (
            <Badge key={m} variant="muted">
              {m}
            </Badge>
          ))}
          {item.threatActors.map((a) => (
            <Badge key={a} variant="high">
              {a}
            </Badge>
          ))}
        </div>
        <CopyButton text={item.query} />
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-words rounded-lg border border-white/[0.06] bg-black/20 p-2.5 font-mono text-xs text-foreground">
        {item.query}
      </pre>
      <a
        href={item.articleLink}
        target="_blank"
        rel="noreferrer"
        className="mt-2 flex items-center gap-1 text-xs text-muted hover:text-foreground"
      >
        <span className="truncate">
          {item.articleSource}: {item.articleTitle}
        </span>
        <ExternalLink className="h-3 w-3 shrink-0" />
      </a>
    </div>
  );
}

function HuntingQueriesSection() {
  const { data, isLoading, isError, error } = useHuntingLibrary();
  const [platform, setPlatform] = useState<HuntingQueryPlatform | "all">("all");
  const [search, setSearch] = useState("");

  const items = data?.items ?? [];

  const platformCounts = useMemo(() => {
    const counts: Partial<Record<HuntingQueryPlatform, number>> = {};
    for (const item of items) counts[item.platform] = (counts[item.platform] ?? 0) + 1;
    return counts;
  }, [items]);

  const platforms = useMemo(() => {
    const seen = new Map<HuntingQueryPlatform, string>();
    for (const item of items) seen.set(item.platform, item.platformLabel);
    return Array.from(seen.entries());
  }, [items]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((item) => {
      if (platform !== "all" && item.platform !== platform) return false;
      if (!q) return true;
      return (
        item.query.toLowerCase().includes(q) ||
        item.articleTitle.toLowerCase().includes(q) ||
        item.cveIds.some((id) => id.toLowerCase().includes(q)) ||
        item.malware.some((m) => m.toLowerCase().includes(q)) ||
        item.threatActors.some((a) => a.toLowerCase().includes(q))
      );
    });
  }, [items, platform, search]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <Input placeholder="Search queries, CVEs, malware, actors…" value={search} onChange={(e) => setSearch(e.target.value)} className="w-full sm:w-72" />
      </div>
      <div className="flex flex-wrap gap-1.5">
        <button
          onClick={() => setPlatform("all")}
          className={cn(
            "rounded-lg px-2.5 py-1 text-xs font-medium transition-colors",
            platform === "all" ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
          )}
        >
          All ({items.length})
        </button>
        {platforms.map(([p, label]) => (
          <button
            key={p}
            onClick={() => setPlatform(p)}
            className={cn(
              "rounded-lg px-2.5 py-1 text-xs font-medium transition-colors",
              platform === p ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
            )}
          >
            {label} ({platformCounts[p]})
          </button>
        ))}
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full" />
          ))}
        </div>
      ) : isError ? (
        <ErrorState message={(error as Error)?.message ?? "The Hunting Query Library is unavailable right now."} />
      ) : filtered.length === 0 ? (
        <EmptyState
          message={
            items.length === 0
              ? "No hunting queries yet -- generated from AI Summarization reports plus known-active malware/threat-actor entities; check back shortly."
              : "No queries match this search/platform filter."
          }
        />
      ) : (
        <div className="space-y-3">
          {filtered.map((item) => (
            <HuntingQueryCard key={item.id} item={item} />
          ))}
        </div>
      )}
    </div>
  );
}

// --- Detection Backlog ------------------------------------------------------

const DRAFT_CONFIDENCE_BADGE: Record<DraftRule["confidence"], "success" | "medium" | "muted"> = {
  High: "success",
  Medium: "medium",
  Low: "muted",
};

/** The AI-drafted candidate rule for one backlog item -- see server/detectionRuleDraft.js. Always framed as a starting point, never as validated/deploy-ready. */
function DraftRulePanel({ draft }: { draft: DraftRule }) {
  return (
    <div className="space-y-2 py-1">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <Badge variant={draft.format === "yara" ? "medium" : "cyan"}>{draft.format.toUpperCase()}</Badge>
          <span className="text-xs font-medium text-foreground">{draft.ruleTitle}</span>
          <Badge variant={DRAFT_CONFIDENCE_BADGE[draft.confidence]}>{draft.confidence} confidence</Badge>
        </div>
        <CopyButton text={draft.ruleContent} />
      </div>
      <p className="text-xs text-muted">{draft.explanation}</p>
      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-white/[0.06] bg-black/30 p-2.5 font-mono text-xs text-foreground">
        {draft.ruleContent}
      </pre>
      {draft.relatedRules.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] text-muted">Possibly related existing rules:</span>
          {draft.relatedRules.map((r) => (
            <a
              key={r.path}
              href={r.url}
              target="_blank"
              rel="noreferrer"
              className="text-[10px] text-primary hover:underline"
            >
              {r.label}: {r.path.split("/").pop()}
            </a>
          ))}
        </div>
      )}
      <p className="text-[10px] text-muted">AI-drafted starting point -- review, adapt, and test before deploying. Generated {new Date(draft.generatedAt).toLocaleString()}.</p>
    </div>
  );
}

const BACKLOG_STATUS_FILTERS: Array<DetectionBacklogStatus | "all"> = ["all", "open", "in_progress", "implemented", "wont_do"];

const BACKLOG_STATUS_LABEL: Record<DetectionBacklogStatus, string> = {
  open: "Open",
  in_progress: "In Progress",
  implemented: "Implemented",
  wont_do: "Won't Do",
};

const BACKLOG_STATUS_BADGE: Record<DetectionBacklogStatus, "muted" | "medium" | "success" | "cyan"> = {
  open: "muted",
  in_progress: "medium",
  implemented: "success",
  wont_do: "cyan",
};

function DetectionBacklogSection() {
  const { items, isLoading, isError, error, setStatus, clearStatus, isUpdating, draftRule, draftingId } = useDetectionBacklog();
  const [statusFilter, setStatusFilter] = useState<DetectionBacklogStatus | "all">("all");
  const [editingId, setEditingId] = useState<string | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const [expandedDraftId, setExpandedDraftId] = useState<string | null>(null);
  const [draftErrors, setDraftErrors] = useState<Record<string, string>>({});

  async function requestDraftRule(item: DetectionBacklogItem) {
    setDraftErrors((prev) => ({ ...prev, [item.id]: "" }));
    try {
      await draftRule(item.id);
      setExpandedDraftId(item.id);
    } catch (err) {
      setDraftErrors((prev) => ({ ...prev, [item.id]: (err as Error)?.message ?? "Failed to draft a rule." }));
    }
  }

  const counts = useMemo(() => {
    const c: Record<DetectionBacklogStatus, number> = { open: 0, in_progress: 0, implemented: 0, wont_do: 0 };
    for (const item of items) c[item.status] += 1;
    return c;
  }, [items]);

  const filtered = useMemo(() => (statusFilter === "all" ? items : items.filter((i) => i.status === statusFilter)), [items, statusFilter]);

  function startEditingNote(item: DetectionBacklogItem) {
    setEditingId(item.id);
    setNoteDraft(item.note ?? "");
  }

  async function saveNote(item: DetectionBacklogItem) {
    await setStatus({ id: item.id, status: item.status, note: noteDraft });
    setEditingId(null);
  }

  async function changeStatus(item: DetectionBacklogItem, status: DetectionBacklogStatus) {
    if (status === "open" && item.note === null) {
      await clearStatus(item.id);
    } else {
      await setStatus({ id: item.id, status, note: item.note });
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1.5">
        {BACKLOG_STATUS_FILTERS.map((s) => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={cn(
              "rounded-lg px-2.5 py-1 text-xs font-medium transition-colors",
              statusFilter === s ? "bg-gradient-primary text-white shadow-glow-primary" : "border border-white/10 bg-white/[0.03] text-muted hover:text-foreground",
            )}
          >
            {s === "all" ? `All (${items.length})` : `${BACKLOG_STATUS_LABEL[s]} (${counts[s]})`}
          </button>
        ))}
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-10 w-full" />
          ))}
        </div>
      ) : isError ? (
        <ErrorState message={(error as Error)?.message ?? "The Detection Backlog is unavailable right now."} />
      ) : filtered.length === 0 ? (
        <EmptyState
          message={
            items.length === 0
              ? "No detection-engineering gaps identified yet -- generated from AI Summarization reports plus known-active malware/threat-actor entities; check back shortly."
              : "No items match this status filter."
          }
        />
      ) : (
        <Table>
          <TableHead>
            <TableRow>
              <TableHeaderCell>Category</TableHeaderCell>
              <TableHeaderCell>Gap</TableHeaderCell>
              <TableHeaderCell>Source</TableHeaderCell>
              <TableHeaderCell>Status</TableHeaderCell>
              <TableHeaderCell>Note</TableHeaderCell>
              <TableHeaderCell>Draft Rule</TableHeaderCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filtered.map((item) => (
              <Fragment key={item.id}>
              <TableRow>
                <TableCell>
                  <Badge variant="cyan">{item.categoryLabel}</Badge>
                  <div className="mt-1">
                    <SeverityBadge severity={item.severity} />
                  </div>
                </TableCell>
                <TableCell className="max-w-md text-xs text-foreground">{item.description}</TableCell>
                <TableCell className="max-w-[10rem]">
                  <a href={item.articleLink} target="_blank" rel="noreferrer" className="flex items-center gap-1 text-xs text-primary hover:underline">
                    <span className="truncate">{item.articleSource}</span>
                    <ExternalLink className="h-3 w-3 shrink-0" />
                  </a>
                  {item.cveIds.map((id) => (
                    <Badge key={id} variant="danger" className="mt-1">
                      {id}
                    </Badge>
                  ))}
                </TableCell>
                <TableCell>
                  <Select value={item.status} onChange={(e) => changeStatus(item, e.target.value as DetectionBacklogStatus)} className="text-xs">
                    {(Object.keys(BACKLOG_STATUS_LABEL) as DetectionBacklogStatus[]).map((s) => (
                      <option key={s} value={s}>
                        {BACKLOG_STATUS_LABEL[s]}
                      </option>
                    ))}
                  </Select>
                  <Badge variant={BACKLOG_STATUS_BADGE[item.status]} className="mt-1">
                    {BACKLOG_STATUS_LABEL[item.status]}
                  </Badge>
                </TableCell>
                <TableCell className="max-w-[12rem]">
                  {editingId === item.id ? (
                    <div className="flex flex-col gap-1.5">
                      <Input
                        autoFocus
                        value={noteDraft}
                        onChange={(e) => setNoteDraft(e.target.value)}
                        placeholder="e.g. Built as Sentinel rule DET-118"
                        className="text-xs"
                      />
                      <div className="flex gap-1.5">
                        <Button type="button" size="sm" onClick={() => saveNote(item)} disabled={isUpdating}>
                          Save
                        </Button>
                        <Button type="button" size="sm" variant="outline" onClick={() => setEditingId(null)}>
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <button type="button" onClick={() => startEditingNote(item)} className="flex items-start gap-1 text-left text-xs text-muted hover:text-foreground">
                      <Pencil className="mt-0.5 h-3 w-3 shrink-0" />
                      <span className="line-clamp-2">{item.note ?? "Add note"}</span>
                    </button>
                  )}
                  {item.statusUpdatedAt && <p className="mt-1 text-[10px] text-muted">Updated {new Date(item.statusUpdatedAt).toLocaleDateString()}</p>}
                </TableCell>
                <TableCell className="max-w-[10rem]">
                  <div className="flex flex-col items-start gap-1">
                    {item.draftRule ? (
                      <button
                        type="button"
                        onClick={() => setExpandedDraftId(expandedDraftId === item.id ? null : item.id)}
                        className="flex items-center gap-1 text-xs text-primary hover:underline"
                      >
                        <FileCode className="h-3 w-3" />
                        {expandedDraftId === item.id ? "Hide draft" : "View draft"}
                      </button>
                    ) : (
                      <Button type="button" size="sm" variant="outline" onClick={() => requestDraftRule(item)} disabled={draftingId === item.id}>
                        <Sparkles className="h-3 w-3" />
                        {draftingId === item.id ? "Drafting…" : "Draft Rule"}
                      </Button>
                    )}
                    {item.draftRule && (
                      <Button type="button" size="sm" variant="outline" onClick={() => requestDraftRule(item)} disabled={draftingId === item.id}>
                        {draftingId === item.id ? "Redrafting…" : "Regenerate"}
                      </Button>
                    )}
                    {draftErrors[item.id] && <p className="text-[10px] text-critical">{draftErrors[item.id]}</p>}
                  </div>
                </TableCell>
              </TableRow>
              {expandedDraftId === item.id && item.draftRule && (
                <TableRow key={`${item.id}::draft`}>
                  <TableCell colSpan={6} className="bg-black/20">
                    <DraftRulePanel draft={item.draftRule} />
                  </TableCell>
                </TableRow>
              )}
              </Fragment>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

// --- Shell -------------------------------------------------------------

/**
 * Every AI Summarization report already generates real hunting queries and
 * detection-engineering gaps grounded in that specific article (see
 * server/aiThreatSummary.js), but that output was locked inside individual
 * reports with no way to browse across them -- a hunter wanting "every
 * Sigma rule we've generated" or Detection Engineering wanting "everything
 * still open" had no single place to look. This rolls both up: a searchable
 * read-only library for hunting queries, and a trackable backlog (mirrors
 * the Remediation Tracker's workflow) for detection gaps.
 */
interface HuntingDetectionHubProps {
  /** Deep-link target set by clicking the Overview tab's "Detection Gaps" stat -- see DashboardPage.tsx#goToTodayEvent-style navigation. */
  initialSection?: SectionId;
}

export function HuntingDetectionHub({ initialSection }: HuntingDetectionHubProps = {}) {
  const [section, setSection] = useState<SectionId>(initialSection ?? "hunting");

  useEffect(() => {
    if (initialSection) setSection(initialSection);
  }, [initialSection]);

  return (
    <Card>
      <CardHeader className="flex-col items-start gap-3">
        <div className="flex w-full flex-col items-start gap-1 md:flex-row md:items-center md:justify-between">
          <div>
            <CardTitle className="text-base font-semibold text-foreground">Hunting &amp; Detection</CardTitle>
            <p className="mt-1 text-xs text-muted">
              Hunting queries and detection-engineering gaps rolled up from every AI Summarization report plus active Malware/Threat Actor Intelligence
              entities (live indicators, ATT&amp;CK techniques, public YARA/Sigma rule matches) -- a searchable library for Hunt, a trackable backlog for
              Detection Engineering.
            </p>
          </div>
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
        </div>
      </CardHeader>
      <CardContent>{section === "hunting" ? <HuntingQueriesSection /> : <DetectionBacklogSection />}</CardContent>
    </Card>
  );
}
