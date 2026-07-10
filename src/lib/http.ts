// Confirmed live: on Render's free tier, an idle instance spinning back up
// (cold start) can take up to ~50s -- a 12s timeout here meant every first
// page load after the free instance went to sleep hard-failed with a raw
// "Dashboard API timed out after 12000ms" error, even though the backend
// was genuinely still booting, not actually broken. 60s comfortably covers
// that without meaningfully changing the experience on an always-warm
// backend (local dev, or Render's paid tier), where responses are fast
// regardless of the ceiling.
const DEFAULT_TIMEOUT_MS = 60_000;

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly source: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

interface RequestOptions extends RequestInit {
  /** Human-readable name of the upstream source, used in error messages. */
  source: string;
  timeoutMs?: number;
}

async function request(url: string, options: RequestOptions): Promise<Response> {
  const { source, timeoutMs = DEFAULT_TIMEOUT_MS, ...init } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) {
      throw new ApiError(
        `${source} responded with ${response.status} ${response.statusText}`,
        source,
        response.status,
      );
    }
    return response;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError(`${source} timed out after ${timeoutMs}ms`, source);
    }
    throw new ApiError(`${source} is unreachable: ${(error as Error).message}`, source);
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchJson<T>(url: string, options: RequestOptions): Promise<T> {
  const response = await request(url, options);
  return (await response.json()) as T;
}

export async function fetchText(url: string, options: RequestOptions): Promise<string> {
  const response = await request(url, options);
  return response.text();
}
