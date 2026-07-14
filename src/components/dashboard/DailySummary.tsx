import { ClipboardList } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "./ErrorState";
import { BreakingNewsStrip, useBreakingNews } from "./BreakingNewsStrip";

/**
 * Top News strip (see BreakingNewsStrip.tsx) for the Overview tab -- the
 * "Today's Summary" bullet rollup that used to live below it was removed;
 * this card is now just that strip in its own titled card.
 */
export function DailySummary() {
  const { items, isLoading, isError, error } = useBreakingNews();

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
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className="h-8 w-full" />
            ))}
          </div>
        ) : isError ? (
          <ErrorState message={error?.message ?? "Top news is unavailable right now."} />
        ) : items.length === 0 ? (
          <EmptyState message="No critical/high severity headlines in the last 6 hours." />
        ) : (
          <BreakingNewsStrip items={items} />
        )}
      </CardContent>
    </Card>
  );
}
