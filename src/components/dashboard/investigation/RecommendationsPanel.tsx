// Standalone "Recommendations" section -- the AI Investigation Summary's
// (graphInsights.js) own recommendations list, pulled out of
// AiGraphInsightsPanel.tsx into its own top-level home instead of living
// inside that panel's card.
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Section } from "../reportPrimitives";

interface RecommendationsPanelProps {
  recommendations: string[] | null;
  pending: boolean;
  model?: string | null;
}

export function RecommendationsPanel({ recommendations, pending, model }: RecommendationsPanelProps) {
  if (pending && !recommendations) {
    return (
      <Section title="Recommendations">
        <div className="space-y-2">
          <Skeleton className="h-4 w-full" />
          <Skeleton className="h-4 w-5/6" />
        </div>
      </Section>
    );
  }

  if (!recommendations || recommendations.length === 0) return null;

  return (
    <Section title="Recommendations">
      <div className="rounded-xl border border-primary/20 bg-primary/[0.04] p-3">
        <ul className="list-disc space-y-1 pl-4 text-sm text-foreground">
          {recommendations.map((line, i) => (
            <li key={i}>{line}</li>
          ))}
        </ul>
      </div>
      {model && (
        <Badge variant="muted" className="mt-2">
          AI-generated — {model}
        </Badge>
      )}
    </Section>
  );
}
