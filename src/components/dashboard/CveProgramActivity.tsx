import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useCveProgramActivity } from "@/hooks/useCveProgramActivity";

/**
 * The CVE Program's (cve.org) own recent record activity -- which CVE IDs
 * were just reserved or updated, straight from their cvelistV5 repository.
 * Distinct from the Latest CVEs table above, which is NVD's enriched view
 * (CVSS/CPE data attached, often published a day or more after reservation).
 */
export function CveProgramActivity() {
  const activity = useCveProgramActivity();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold text-foreground">
          CVE Program Activity <span className="text-muted">(cve.org, raw reservation feed)</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {activity.isLoading && (
          <div className="space-y-2">
            <Skeleton className="h-6 w-full" />
            <Skeleton className="h-6 w-full" />
          </div>
        )}

        {activity.isError && <p className="text-sm text-critical">{(activity.error as Error).message}</p>}

        {activity.data && (
          <>
            <div className="flex flex-wrap gap-4 text-sm">
              <span>
                <Badge variant="low">New</Badge> <span className="ml-1 font-semibold">{activity.data.newCves.length}</span>
              </span>
              <span>
                <Badge variant="medium">Updated</Badge> <span className="ml-1 font-semibold">{activity.data.updatedCves.length}</span>
              </span>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Newly Reserved</p>
                <ul className="space-y-1">
                  {activity.data.newCves.slice(0, 8).map((entry) => (
                    <li key={entry.cveId} className="truncate text-sm">
                      <a href={entry.url} target="_blank" rel="noreferrer" className="font-mono text-primary hover:underline">
                        {entry.cveId}
                      </a>
                    </li>
                  ))}
                  {activity.data.newCves.length === 0 && <span className="text-xs text-muted">None in the current sync cycle.</span>}
                </ul>
              </div>
              <div>
                <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Recently Updated</p>
                <ul className="space-y-1">
                  {activity.data.updatedCves.slice(0, 8).map((entry) => (
                    <li key={entry.cveId} className="truncate text-sm">
                      <a href={entry.url} target="_blank" rel="noreferrer" className="font-mono text-primary hover:underline">
                        {entry.cveId}
                      </a>
                    </li>
                  ))}
                  {activity.data.updatedCves.length === 0 && <span className="text-xs text-muted">None in the current sync cycle.</span>}
                </ul>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
