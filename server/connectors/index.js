import cisaKev from "./cisaKev.js";
import nvd from "./nvd.js";
import epss from "./epss.js";
import attack from "./attack.js";
import urlhaus from "./urlhaus.js";
import threatfox from "./threatfox.js";
import malwareBazaar from "./malwareBazaar.js";
import feodoTracker from "./feodoTracker.js";
import openphish from "./openphish.js";
import otx from "./otx.js";
import abuseipdb from "./abuseipdb.js";
import ransomwareLive from "./ransomwareLive.js";
import ransomwatch from "./ransomwatch.js";
import ransomlook from "./ransomlook.js";
import ransomwareGroups from "./ransomwareGroups.js";
import newsFeeds from "./newsFeeds.js";
import pulsedive from "./pulsedive.js";
import phishtank from "./phishtank.js";
import emergingThreats from "./emergingThreats.js";
import spamhaus from "./spamhaus.js";
import cveProject from "./cveProject.js";
import malpedia from "./malpedia.js";
import exploitdb from "./exploitdb.js";
import vulncheckKev from "./vulncheckKev.js";
import detectionRules from "./detectionRules.js";
import { githubDiscoveryConnector, githubEnrichmentConnector } from "../githubIntel/index.js";

/** Every scheduled (bulk, background-synced) connector. IOC-search lookups live in server/lookups/ instead. */
export const connectors = [
  cisaKev,
  nvd,
  epss,
  attack,
  urlhaus,
  threatfox,
  malwareBazaar,
  feodoTracker,
  openphish,
  otx,
  abuseipdb,
  ransomwareLive,
  ransomwatch,
  ransomlook,
  ransomwareGroups,
  newsFeeds,
  pulsedive,
  phishtank,
  emergingThreats,
  spamhaus,
  cveProject,
  malpedia,
  exploitdb,
  vulncheckKev,
  detectionRules,
  githubDiscoveryConnector,
  githubEnrichmentConnector,
];
