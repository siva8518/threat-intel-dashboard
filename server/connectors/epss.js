import zlib from "node:zlib";
import { ApiError } from "../lib/http.js";

// FIRST publishes a daily bulk CSV snapshot (gzipped) of EPSS scores for
// every scored CVE. Pulling this once/day and caching a lookup map is far
// more efficient than querying the JSON API (api.first.org) per CVE, and
// avoids needing to paginate through hundreds of thousands of records.
const EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const TIMEOUT_MS = 30_000;

/** FIRST EPSS (Exploit Prediction Scoring System). Free, no API key. */
export default {
  id: "epss",
  label: "FIRST EPSS",
  intervalMs: 24 * 60 * 60 * 1000, // EPSS scores are recalculated once/day
  async fetch() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let response;
    try {
      response = await fetch(EPSS_CSV_URL, { signal: controller.signal });
    } catch (error) {
      throw new ApiError(`FIRST EPSS is unreachable: ${error.message}`, "FIRST EPSS");
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      throw new ApiError(`FIRST EPSS responded with ${response.status} ${response.statusText}`, "FIRST EPSS", response.status);
    }

    const buffer = Buffer.from(await response.arrayBuffer());
    const csv = zlib.gunzipSync(buffer).toString("utf-8");

    // Row 1 is a "#model_version:...,score_date:..." comment, row 2 is the
    // column header ("cve,epss,percentile") -- data starts at row 3.
    const scores = {};
    const lines = csv.split("\n");
    for (let i = 2; i < lines.length; i++) {
      const [cve, epss, percentile] = lines[i].split(",");
      if (!cve) continue;
      scores[cve] = { score: Number(epss), percentile: Number(percentile) };
    }
    return scores;
  },
};
