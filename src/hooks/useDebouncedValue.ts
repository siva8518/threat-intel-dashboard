import { useEffect, useState } from "react";

/**
 * Delays propagating a fast-changing value (e.g. search input keystrokes) so
 * dependent queries don't fire on every keystroke. Necessary here because
 * NVD's unauthenticated rate limit (5 requests/30s) gets exhausted within a
 * handful of keystrokes otherwise -- confirmed live: typing "WordPress" with
 * no debounce produced a run of HTTP 429s.
 */
export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}
