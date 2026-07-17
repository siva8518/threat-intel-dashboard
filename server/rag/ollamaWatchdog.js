// Detects Ollama's own recurring "Stopping..." unload deadlock (confirmed
// live on this machine, Ollama 0.32.0 -- a loaded model repeatedly fails to
// cleanly unload and then never responds to any new request again, roughly
// every 10-15 minutes) and restarts the Ollama process automatically -- the
// same manual fix (`taskkill /F /IM ollama.exe`) that unstuck it every time
// this was diagnosed by hand this session. The tray launcher ("ollama
// app.exe") already auto-relaunches a killed ollama.exe within a couple
// seconds on its own -- confirmed live, repeatedly -- so this only needs to
// clear the wedged process, not start Ollama itself.
//
// server/rag/ollamaClient.js -- the single choke point all Ollama I/O runs
// through -- reports every failure/success here, so this stays a passive
// observer rather than something every caller has to remember to wire up.
import { exec } from "node:child_process";
import { platform } from "node:os";
import { log } from "../lib/log.js";

const RESTART_COOLDOWN_MS = 60_000; // don't restart more often than this even if failures keep arriving -- a fresh restart needs a few seconds before it's fair to judge again
const MAX_AUTO_RESTARTS = 20; // guards against restart-looping forever if Ollama is genuinely just not installed/running, not merely stuck -- that's the ordinary "not configured" case this app already handles quietly elsewhere

let lastRestartAt = 0;
let restartCount = 0;
let giveUpWarned = false;

function restartOllama() {
  // No POSIX equivalent of "ollama app.exe" tray auto-relaunch was ever
  // confirmed live -- this app only runs on Windows in practice (see
  // system environment), so the non-Windows branch is best-effort only.
  const cmd = platform() === "win32" ? "taskkill /F /IM ollama.exe" : "pkill -f ollama";
  exec(cmd, (error) => {
    if (error) {
      // Most common cause: nothing to kill because Ollama isn't running at
      // all -- that's the ordinary "not installed" case, not the deadlock
      // this watchdog targets, so this is expected noise, not a real failure.
      log.warn("ollama-watchdog", `restart command found nothing to kill (${error.message.split("\n")[0]}) -- Ollama may simply not be running`);
      return;
    }
    log.warn("ollama-watchdog", "Ollama process killed after a failed request -- its tray launcher should relaunch it within a few seconds");
  });
}

/** Called from ollamaClient.js whenever a request comes back unreachable/timed out. */
export function recordOllamaFailure() {
  const now = Date.now();
  if (now - lastRestartAt < RESTART_COOLDOWN_MS) return;
  if (restartCount >= MAX_AUTO_RESTARTS) {
    if (!giveUpWarned) {
      log.warn("ollama-watchdog", `hit ${MAX_AUTO_RESTARTS} auto-restarts this run, giving up for this process's lifetime -- Ollama needs a manual look`);
      giveUpWarned = true;
    }
    return;
  }
  lastRestartAt = now;
  restartCount += 1;
  log.warn("ollama-watchdog", `Ollama request failed (auto-restart ${restartCount}/${MAX_AUTO_RESTARTS}) -- restarting Ollama automatically`);
  restartOllama();
}

/** Called from ollamaClient.js whenever a request completes successfully -- resets the counter so a single blip long ago doesn't count against the cap forever. */
export function recordOllamaSuccess() {
  restartCount = 0;
  giveUpWarned = false;
}
