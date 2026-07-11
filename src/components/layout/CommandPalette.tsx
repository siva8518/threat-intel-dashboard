import { useEffect, useState } from "react";
import { Search, ShieldAlert, UserSearch } from "lucide-react";
import { AnimatePresence, motion } from "framer-motion";
import { Command } from "cmdk";
import type { TabItem } from "./TopTabs";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import { useSelection } from "@/context/SelectionContext";
import { fetchCveById, fetchCves, searchThreatActorProfiles } from "@/api/dashboardApi";
import type { CveRecord, ThreatActorSummary } from "@/types/threat-intel";

const CVE_ID_PATTERN = /^cve-\d{4}-\d+$/i;

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  tabs: readonly TabItem[];
  onNavigate: (id: string) => void;
  onSelectActor: (name: string) => void;
}

/**
 * Floating Cmd/Ctrl+K palette. With an empty query it's still the quick
 * tab-jump list; once you type it becomes real platform search -- CVEs
 * (exact ID lookup, or a keyword search across the last 30 days) and threat
 * actors (name/alias), fetched live and grouped below "Navigate". Built on
 * cmdk (fuzzy list/keyboard nav) inside a hand-rolled Framer Motion overlay
 * rather than cmdk's own <Command.Dialog> (a Radix Dialog under the hood)
 * -- that unmounts instantly on close, which would skip the exit animation
 * entirely.
 */
export function CommandPalette({ open, onOpenChange, tabs, onNavigate, onSelectActor }: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebouncedValue(query, 300);
  const [cveResults, setCveResults] = useState<CveRecord[]>([]);
  const [actorResults, setActorResults] = useState<ThreatActorSummary[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const { selectCve } = useSelection();

  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  useEffect(() => {
    const trimmed = debouncedQuery.trim();
    if (!trimmed) {
      setCveResults([]);
      setActorResults([]);
      return;
    }

    let cancelled = false;
    setIsSearching(true);

    const cvePromise = CVE_ID_PATTERN.test(trimmed)
      ? fetchCveById(trimmed.toUpperCase())
          .then((record) => [record])
          .catch(() => [])
      : fetchCves({ keyword: trimmed, pageSize: 5 })
          .then((result) => result.records)
          .catch(() => []);

    const actorPromise = searchThreatActorProfiles(trimmed)
      .then((result) => result.actors)
      .catch(() => []);

    Promise.all([cvePromise, actorPromise]).then(([cves, actors]) => {
      if (cancelled) return;
      setCveResults(cves.slice(0, 5));
      setActorResults(actors.slice(0, 5));
      setIsSearching(false);
    });

    return () => {
      cancelled = true;
    };
  }, [debouncedQuery]);

  function go(id: string) {
    onNavigate(id);
    onOpenChange(false);
  }

  function openCve(record: CveRecord) {
    selectCve(record);
    onOpenChange(false);
  }

  function openActor(name: string) {
    onSelectActor(name);
    onOpenChange(false);
  }

  const trimmedQuery = query.trim();
  const hasResults = cveResults.length > 0 || actorResults.length > 0;

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[14vh] backdrop-blur-sm"
          onClick={() => onOpenChange(false)}
        >
          <motion.div
            initial={{ opacity: 0, y: -12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            onClick={(e) => e.stopPropagation()}
            className="glass-panel w-full max-w-lg overflow-hidden shadow-popover"
          >
            <Command shouldFilter={false}>
              <div className="flex items-center gap-2 border-b border-white/[0.06] px-4">
                <Search className="h-4 w-4 shrink-0 text-muted" />
                <Command.Input
                  autoFocus
                  value={query}
                  onValueChange={setQuery}
                  placeholder="Search CVEs, threat actors, or jump to a section…"
                  className="h-12 w-full bg-transparent text-sm text-foreground outline-none placeholder:text-muted/60"
                />
                <kbd className="shrink-0 rounded border border-white/10 bg-white/5 px-1.5 py-0.5 text-[10px] text-muted">
                  ESC
                </kbd>
              </div>
              <Command.List className="max-h-96 overflow-y-auto p-2">
                {trimmedQuery ? (
                  <>
                    {isSearching && <div className="px-3 py-6 text-center text-sm text-muted">Searching…</div>}
                    {!isSearching && !hasResults && (
                      <div className="px-3 py-6 text-center text-sm text-muted">No CVEs or threat actors matched "{trimmedQuery}".</div>
                    )}
                    {cveResults.length > 0 && (
                      <Command.Group
                        heading="CVEs"
                        className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted/60 [&_[cmdk-group-items]]:mt-1"
                      >
                        {cveResults.map((cve) => (
                          <Command.Item
                            key={cve.id}
                            value={cve.id}
                            onSelect={() => openCve(cve)}
                            className="flex cursor-pointer items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm text-foreground transition-colors data-[selected=true]:bg-white/[0.08]"
                          >
                            <ShieldAlert className="h-4 w-4 shrink-0 text-primary" />
                            <span className="min-w-0 flex-1 truncate">
                              <span className="font-mono">{cve.id}</span>{" "}
                              <span className="text-muted">
                                {cve.vendor} {cve.product}
                              </span>
                            </span>
                            {cve.knownExploited && <span className="shrink-0 text-[10px] font-semibold text-critical">KEV</span>}
                          </Command.Item>
                        ))}
                      </Command.Group>
                    )}
                    {actorResults.length > 0 && (
                      <Command.Group
                        heading="Threat Actors"
                        className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted/60 [&_[cmdk-group-items]]:mt-1"
                      >
                        {actorResults.map((actor) => (
                          <Command.Item
                            key={actor.attackId}
                            value={actor.attackId}
                            onSelect={() => openActor(actor.name)}
                            className="flex cursor-pointer items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm text-foreground transition-colors data-[selected=true]:bg-white/[0.08]"
                          >
                            <UserSearch className="h-4 w-4 shrink-0 text-primary" />
                            <span className="min-w-0 flex-1 truncate">
                              {actor.name}
                              {actor.aliases.length > 0 && <span className="text-muted"> · {actor.aliases.slice(0, 2).join(", ")}</span>}
                            </span>
                            {actor.country && <span className="shrink-0 text-xs text-muted">{actor.country}</span>}
                          </Command.Item>
                        ))}
                      </Command.Group>
                    )}
                  </>
                ) : (
                  <Command.Group
                    heading="Navigate"
                    className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-muted/60 [&_[cmdk-group-items]]:mt-1"
                  >
                    {tabs.map(({ id, label, icon: Icon }) => (
                      <Command.Item
                        key={id}
                        value={label}
                        onSelect={() => go(id)}
                        className="flex cursor-pointer items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm text-foreground transition-colors data-[selected=true]:bg-white/[0.08]"
                      >
                        <Icon className="h-4 w-4 text-primary" />
                        {label}
                      </Command.Item>
                    ))}
                  </Command.Group>
                )}
              </Command.List>
            </Command>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
