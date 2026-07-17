// Shared "is this ISO date within the last N days" predicate -- every
// backend timeframe filter in this app (Top Threat Actors/CVEs/MITRE
// Techniques) uses this same definition, so switching the selector behaves
// identically no matter which underlying data source is being filtered.
export function withinDays(dateValue, days) {
  if (!days) return true; // no window selected (null/undefined/0/NaN) -- everything counts, all-time
  if (!dateValue) return false;
  const cutoffMs = Date.now() - days * 24 * 60 * 60 * 1000;
  return new Date(dateValue).getTime() >= cutoffMs;
}
