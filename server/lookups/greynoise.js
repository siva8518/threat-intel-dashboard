import { ApiError, fetchJson } from "../lib/http.js";

const GREYNOISE_URL = "https://api.greynoise.io/v3/community";

/**
 * GreyNoise's free Community API only supports single-IP lookups (no bulk
 * feed, and no domain/hash/url support at all) -- on-demand only, called
 * live from the IOC Search route.
 */
export async function checkIndicator(type, value) {
  if (type !== "ip") throw new ApiError("GreyNoise only supports IP lookups", "GreyNoise");

  const apiKey = process.env.GREYNOISE_API_KEY;
  if (!apiKey) {
    throw new ApiError("GreyNoise requires a free Community API key from greynoise.io (set GREYNOISE_API_KEY on the server)", "GreyNoise", 401);
  }

  const data = await fetchJson(`${GREYNOISE_URL}/${value}`, { source: "GreyNoise", headers: { key: apiKey } });

  return {
    source: "GreyNoise",
    classification: data.classification ?? "unknown",
    name: data.name ?? null,
    riot: Boolean(data.riot), // "riot" = known benign business service (CDN, search engine crawler, etc.)
    verdict: data.classification === "malicious" ? "malicious" : data.riot ? "clean" : "unknown",
  };
}
