// Backend aggregation service. Unlike the original thin reverse-proxy
// version, this process owns scheduling, caching, retries and correlation
// for every threat-intel source -- see server/scheduler.js and
// server/connectors/. The frontend only ever talks to /api/dashboard/* and
// /api/ioc-search, both mounted below, which serve already-normalized,
// already-correlated JSON.
//
// "dotenv/config" must load before anything else in this file, since every
// connector reads its API key from process.env at import/call time. Node has
// no built-in .env loading -- this was missing for a while, silently making
// every key in .env a no-op for the standalone backend process (Vite's dev
// proxy had its own env loading, which masked this until that proxy was
// replaced by the current backend architecture).
import "dotenv/config";
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connectors } from "./connectors/index.js";
import { startScheduler } from "./scheduler.js";
import { router as dashboardRouter } from "./routes/dashboard.js";
import { router as chatRouter } from "./routes/chat.js";
import { startRagIndexer } from "./rag/indexer.js";
import { startMalwareExtractionJob } from "./malwareExtractionJob.js";
import { startAttackTechniqueExtractionJob } from "./attackTechniqueExtractionJob.js";
import { startThreatActorExtractionJob } from "./threatActorExtractionJob.js";
import { startCampaignExtractionJob } from "./campaignExtractionJob.js";
import { log } from "./lib/log.js";

const app = express();
app.use(express.json());

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distDir = path.join(__dirname, "..", "dist");
const PORT = process.env.PORT || 8080;

// Mounted at /api: dashboard.js defines routes as "/dashboard/summary",
// "/dashboard/cves", ..., and "/ioc-search", which land at
// /api/dashboard/summary, /api/dashboard/cves, ..., /api/ioc-search.
app.use("/api", dashboardRouter);
app.use("/api", chatRouter);

// In production this also serves the built frontend; in dev, Vite serves the
// frontend itself and only proxies /api/* here (see vite.config.ts).
app.use(express.static(distDir));
app.get("*", (_req, res) => {
  res.sendFile(path.join(distDir, "index.html"), (err) => {
    if (err) res.status(404).send("Not built yet -- run `npm run build`, or use `npm run dev` for local development.");
  });
});

startScheduler(connectors);
startRagIndexer();
startMalwareExtractionJob();
startAttackTechniqueExtractionJob();
startThreatActorExtractionJob();
startCampaignExtractionJob();

app.listen(PORT, () => {
  log.info("server", `Threat Intel Dashboard backend listening on port ${PORT}`);
  log.info("server", `${connectors.length} connectors registered, background sync starting now`);
});
