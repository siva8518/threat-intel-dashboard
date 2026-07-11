import { Clock, ClipboardList } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "./ErrorState";
import { useDailySummary } from "@/hooks/useDailySummary";
import { useSelection } from "@/context/SelectionContext";
import type { DailySummaryBullet } from "@/types/threat-intel";

function formatReadingTime(seconds: number) {
  if (seconds < 60) return `${seconds} seconds`;
  const minutes = Math.round(seconds / 60);
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

export type DailySummaryTargetTab = "cves" | "threat-actors" | "threat-feed";

interface DailySummaryProps {
  onNavigateTab: (tab: DailySummaryTargetTab) => void;
  onNavigateNewsSource: (source: string) => void;
}

/** Short rule-based rollup of today's activity -- see server/dailySummary.js. Its own standalone card, paired next to Executive Dashboard AI at the top of Overview. */
export function DailySummary({ onNavigateTab, onNavigateNewsSource }: DailySummaryProps) {
  const { data, isLoading, isError, error } = useDailySummary();
  const { selectMalware } = useSelection();

  function handleClick(bullet: DailySummaryBullet) {
    if (!bullet.action) return;
    switch (bullet.action.type) {
      case "tab":
        onNavigateTab(bullet.action.tab);
        break;
      case "malware":
        selectMalware({ family: bullet.action.family, count: 0, sources: [], techniques: [], detectionRules: [] });
        break;
      case "news-source":
        onNavigateNewsSource(bullet.action.source);
        break;
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-1.5 text-base font-semibold text-foreground">
          <ClipboardList className="h-4 w-4 text-primary" />
          Daily Summary
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton key={i} className="h-4 w-full" />
            ))}
          </div>
        ) : isError || !data ? (
          <ErrorState message={error?.message ?? "The Daily Summary is unavailable right now."} />
        ) : (
          <div>
            <p className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted">Today's Summary</p>
            <ul className="space-y-1">
              {data.bullets.map((bullet, i) => (
                <li key={i}>
                  <button
                    type="button"
                    onClick={() => handleClick(bullet)}
                    disabled={!bullet.action}
                    className="flex w-full items-start gap-2 rounded-lg px-1.5 py-1 text-left text-sm text-foreground transition-colors enabled:cursor-pointer enabled:hover:bg-white/[0.05]"
                  >
                    <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-primary" />
                    <span>{bullet.text}</span>
                  </button>
                </li>
              ))}
            </ul>
            <div className="mt-3 flex items-center gap-1.5 border-t border-white/[0.06] pt-2 text-xs text-muted">
              <Clock className="h-3.5 w-3.5" />
              Estimated reading time: {formatReadingTime(data.readingTimeSeconds)}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
