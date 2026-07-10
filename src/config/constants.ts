// Central place for tunables so components don't hardcode magic numbers.

/** How often React Query silently refetches every dashboard data source. */
export const AUTO_REFRESH_MS = 15 * 60 * 1000; // 15 minutes

/** How long a successful response is considered fresh (no refetch on mount/focus). */
export const STALE_TIME_MS = 5 * 60 * 1000; // 5 minutes

export const CVSS_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
