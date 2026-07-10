const DEFAULT_TIMEOUT_MS = 12_000;

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
