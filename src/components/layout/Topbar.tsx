import { Radar, Search } from "lucide-react";
import { RefreshBar } from "@/components/dashboard/RefreshBar";
import { useSourcesHealth } from "@/hooks/useSourcesHealth";

interface TopbarProps {
  onOpenPalette: () => void;
}

// Per-source online/offline status used to live here as a dot-list under the
// title; moved to its own "Sources" tab (SourcesHealthPanel) since the list
// grew to 24 entries and no longer fit cleanly in a header bar.
export function Topbar({ onOpenPalette }: TopbarProps) {
  const { onlineCount, totalCount } = useSourcesHealth();
  const allOnline = totalCount > 0 && onlineCount === totalCount;

  return (
    <header className="sticky top-0 z-40 flex flex-col gap-3 border-b border-white/[0.06] bg-background/70 px-4 py-3 backdrop-blur-xl md:flex-row md:items-center md:justify-between">
      <div className="flex items-center gap-3">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-primary shadow-glow-primary">
          <Radar className="h-5 w-5 text-white" />
        </div>
        <div>
          <h1 className="text-base font-semibold leading-tight tracking-tight">
            <span className="text-gradient">Threat Intelligence</span>{" "}
            <span className="text-foreground">Platform</span>
          </h1>
          <div className="flex items-center gap-1.5 text-xs text-muted">
            <span className={`relative flex h-1.5 w-1.5 rounded-full ${allOnline ? "bg-low" : "bg-medium"}`}>
              <span className={`absolute inset-0 animate-ping rounded-full ${allOnline ? "bg-low" : "bg-medium"} opacity-75`} />
            </span>
            {onlineCount}/{totalCount || "–"} sources online
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onOpenPalette}
          className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-muted transition-colors hover:border-white/20 hover:bg-white/[0.07] hover:text-foreground"
        >
          <Search className="h-3.5 w-3.5" />
          Search or jump to…
          <kbd className="rounded border border-white/10 bg-white/5 px-1.5 py-0.5 font-sans text-[10px]">⌘K</kbd>
        </button>
        <RefreshBar />
      </div>
    </header>
  );
}
