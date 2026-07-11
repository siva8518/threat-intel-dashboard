import { useState } from "react";
import { Search } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useIocSearch } from "@/hooks/useIocSearch";
import type { IocSearchIndicatorType } from "@/types/threat-intel";

const VERDICT_VARIANT = {
  malicious: "critical",
  suspicious: "high",
  clean: "low",
  unknown: "muted",
} as const;

export function IocSearch() {
  const [type, setType] = useState<IocSearchIndicatorType>("ip");
  const [value, setValue] = useState("");
  const search = useIocSearch();

  function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!value.trim()) return;
    search.mutate({ type, value: value.trim() });
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          IOC Search{" "}
          <span className="text-muted">
            (correlates OTX, AbuseIPDB, Pulsedive, VirusTotal, GreyNoise, Shodan, Hybrid Analysis, LeakIX, crt.sh, RIPEstat, Team Cymru &amp; Hudson Rock live)
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <form onSubmit={onSubmit} className="flex flex-wrap gap-2">
          <Select value={type} onChange={(e) => setType(e.target.value as IocSearchIndicatorType)}>
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="hash">File Hash</option>
          </Select>
          <Input
            placeholder="Enter an indicator to look up…"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            className="w-full sm:w-72"
          />
          <Button type="submit" disabled={search.isPending || !value.trim()}>
            <Search className="h-3.5 w-3.5" />
            Search
          </Button>
        </form>

        {search.isPending && (
          <div className="space-y-2">
            <Skeleton className="h-8 w-full" />
            <Skeleton className="h-8 w-full" />
          </div>
        )}

        {search.isError && (
          <p className="text-sm text-critical">{(search.error as Error).message}</p>
        )}

        {search.data && (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm">{search.data.indicator}</span>
              <Badge variant={VERDICT_VARIANT[search.data.correlatedVerdict]}>{search.data.correlatedVerdict.toUpperCase()}</Badge>
            </div>

            {search.data.results.length > 0 && (
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {search.data.results.map((result) => (
                  <div key={result.source} className="rounded-md border border-border p-3 text-xs">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-semibold">{result.source}</span>
                      <Badge variant={VERDICT_VARIANT[result.verdict]}>{result.verdict}</Badge>
                    </div>
                    <pre className="whitespace-pre-wrap break-words text-muted">
                      {JSON.stringify(
                        Object.fromEntries(Object.entries(result).filter(([k]) => k !== "source" && k !== "verdict")),
                        null,
                        2,
                      )}
                    </pre>
                  </div>
                ))}
              </div>
            )}

            {search.data.notConfigured.length > 0 && (
              <p className="text-xs text-muted">
                Not configured (missing API key): {search.data.notConfigured.join(", ")}
              </p>
            )}

            {search.data.rateLimited.length > 0 && (
              <p className="text-xs text-medium">
                Rate limited, try again shortly: {search.data.rateLimited.join(", ")}
              </p>
            )}

            {search.data.results.length === 0 && search.data.notConfigured.length === 0 && search.data.rateLimited.length === 0 && (
              <p className="text-xs text-muted">No source supports looking up this indicator type.</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
