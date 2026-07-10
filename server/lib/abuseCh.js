import { ApiError } from "./http.js";

/**
 * abuse.ch unified authentication in 2023-2024: ThreatFox, URLHaus and
 * MalwareBazaar all require the same free Auth-Key from
 * https://auth.abuse.ch/, read here from ABUSECH_AUTH_KEY. Confirmed live
 * during the original build -- URLHaus used to be keyless. Feodo Tracker is
 * a separate, still-keyless abuse.ch feed and doesn't use this.
 */
export class AbuseChAuthError extends ApiError {
  constructor(source) {
    super(
      `${source} requires a free Auth-Key from https://auth.abuse.ch/ (set ABUSECH_AUTH_KEY on the server)`,
      source,
      401,
    );
  }
}

export function abuseChHeaders(extra = {}) {
  const headers = { ...extra };
  if (process.env.ABUSECH_AUTH_KEY) headers["Auth-Key"] = process.env.ABUSECH_AUTH_KEY;
  return headers;
}
