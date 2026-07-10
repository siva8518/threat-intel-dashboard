const DEFAULT_TIMEOUT_MS = 15_000;

export class ApiError extends Error {
  constructor(message, source, status) {
    super(message);
    this.name = "ApiError";
    this.source = source;
    this.status = status;
  }
}

async function request(url, { source, timeoutMs = DEFAULT_TIMEOUT_MS, ...init }) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, { ...init, signal: controller.signal });
    if (!response.ok) {
      throw new ApiError(`${source} responded with ${response.status} ${response.statusText}`, source, response.status);
    }
    return response;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error.name === "AbortError") throw new ApiError(`${source} timed out after ${timeoutMs}ms`, source);
    throw new ApiError(`${source} is unreachable: ${error.message}`, source);
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchJson(url, options) {
  const response = await request(url, options);
  // A 204 has no body -- response.json() would throw trying to parse an
  // empty string (confirmed live: LeakIX returns 204, not 200 + `[]`/`{}`,
  // for a query with zero results). No other connector in this app currently
  // triggers a 204, so this is a safe, backward-compatible addition.
  if (response.status === 204) return null;
  return response.json();
}

export async function fetchText(url, options) {
  const response = await request(url, options);
  return response.text();
}
