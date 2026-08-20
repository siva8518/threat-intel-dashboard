// In-memory circuit breaker + health tracking for the AI provider chain.
// Deliberately in-memory, not persisted -- unlike the request log (see
// aiRequestLog.js), a cooldown is only ever meaningful relative to *this*
// process's clock, and a dev restart (or a fresh deploy) legitimately
// warrants giving every provider a clean slate rather than replaying stale
// state from disk.
//
// aiRouter.js consults isInCooldown() before attempting a provider and
// calls recordSuccess()/recordFailure() after every attempt -- this is the
// concrete mechanism behind "if a provider 429s, don't hammer it again on
// the very next unrelated request; skip it until the cooldown clears."

// Base cooldown per failure reason, escalated (see cooldownForFailure) on
// repeated back-to-back failures for the two reasons given a range rather
// than a fixed duration, capped at MAX_COOLDOWN_MS below. Durations are a
// direct requirement, not a guess: rate limits get a full hour (a 429 rarely
// clears sooner, and hammering it just burns the failover budget on every
// other call in that window); a 5xx/timeout gets 5-10 min (genuinely
// transient, worth retrying soon); quota/billing exhaustion gets a full day
// (it never self-resolves faster than that, whether it's a daily quota reset
// or an operator adding funds); 401/403 gets the same day-long window so a
// bad/revoked key doesn't get hammered every few minutes -- there's nothing
// to retry into, only an operator fixing the key ends it early (the manual
// override already exists elsewhere in this app for exactly this shape of
// problem, see server/sandbox/sandboxProviderHealth.js#resetSandboxHealth).
const BASE_COOLDOWN_MS = {
  rate_limited: 60 * 60_000,
  quota_exceeded: 24 * 60 * 60_000,
  timeout: 5 * 60_000,
  server_error: 5 * 60_000,
  network_error: 5 * 60_000,
  auth_error: 24 * 60 * 60_000,
  other: 5 * 60_000,
};

const MAX_COOLDOWN_MS = {
  rate_limited: 60 * 60_000,
  quota_exceeded: 24 * 60 * 60_000,
  timeout: 10 * 60_000,
  server_error: 10 * 60_000,
  network_error: 10 * 60_000,
  auth_error: 24 * 60 * 60_000,
  other: 10 * 60_000,
};

const MAX_LATENCY_SAMPLES = 20;

/** @type {Map<string, ReturnType<typeof freshState>>} */
const state = new Map();

function freshState() {
  return {
    consecutiveFailures: 0,
    cooldownUntil: null,
    cooldownReason: null,
    lastSuccessAt: null,
    lastFailureAt: null,
    lastFailureReason: null,
    totalSuccess: 0,
    totalFailure: 0,
    rateLimitCount: 0,
    timeoutCount: 0,
    authErrorCount: 0,
    latenciesMs: [],
  };
}

function getOrCreate(label) {
  if (!state.has(label)) state.set(label, freshState());
  return state.get(label);
}

/**
 * Cooldown duration for one failure, escalated by consecutive-failure count
 * (doubling, capped at 4 doublings) and floored by the upstream's own
 * Retry-After header when the provider sent one (rate_limited only --
 * that's the one case where the upstream told us exactly how long to wait).
 */
function cooldownForFailure(reason, consecutiveFailures, retryAfterMs) {
  const base = BASE_COOLDOWN_MS[reason] ?? BASE_COOLDOWN_MS.other;
  const max = MAX_COOLDOWN_MS[reason] ?? MAX_COOLDOWN_MS.other;
  const escalated = base * 2 ** Math.min(consecutiveFailures - 1, 4);
  const withUpstreamFloor = reason === "rate_limited" && retryAfterMs ? Math.max(escalated, retryAfterMs) : escalated;
  return Math.min(withUpstreamFloor, max);
}

/** Whether `label` is currently cooling down from a recent failure -- aiRouter.js skips straight past it without attempting a request when true. */
export function isInCooldown(label) {
  const s = state.get(label);
  return Boolean(s?.cooldownUntil && s.cooldownUntil > Date.now());
}

/** Ms remaining in the current cooldown, or 0 if not cooling down. */
export function cooldownRemainingMs(label) {
  const s = state.get(label);
  if (!s?.cooldownUntil) return 0;
  return Math.max(0, s.cooldownUntil - Date.now());
}

/**
 * True exactly once per cooldown cycle: the cooldown window has elapsed
 * (isInCooldown() now returns false) but nothing has actually re-verified
 * the provider yet -- recordSuccess()/recordFailure() are the only two
 * things that ever change cooldownUntil, so "still set, but now in the
 * past" is a precise, self-clearing signal that aiRouter.js uses to run one
 * cheap health-check call before letting real production traffic reach a
 * provider that was just failing. Once that health check (or the real
 * request) resolves either way, cooldownUntil gets reset (to null on
 * success, to a fresh future timestamp on failure) and this goes false on
 * its own -- no separate flag to remember to clear.
 */
export function isPendingHealthCheck(label) {
  const s = state.get(label);
  return Boolean(s?.cooldownUntil && s.cooldownUntil <= Date.now());
}

/** Most recent failure reason recorded for `label`, or null if it has never failed. */
export function getLastFailureReason(label) {
  return state.get(label)?.lastFailureReason ?? null;
}

export function recordSuccess(label, latencyMs) {
  const s = getOrCreate(label);
  s.consecutiveFailures = 0;
  s.cooldownUntil = null;
  s.cooldownReason = null;
  s.lastSuccessAt = Date.now();
  s.totalSuccess += 1;
  s.latenciesMs.push(latencyMs);
  if (s.latenciesMs.length > MAX_LATENCY_SAMPLES) s.latenciesMs.shift();
}

/**
 * @param {string} label
 * @param {import("./aiProviderError.js").AIProviderFailureReason} reason
 * @param {{retryAfterMs?: number}} [opts]
 */
export function recordFailure(label, reason, { retryAfterMs } = {}) {
  const s = getOrCreate(label);
  s.consecutiveFailures += 1;
  s.lastFailureAt = Date.now();
  s.lastFailureReason = reason;
  s.totalFailure += 1;
  if (reason === "rate_limited") s.rateLimitCount += 1;
  if (reason === "timeout") s.timeoutCount += 1;
  if (reason === "auth_error") s.authErrorCount += 1;

  // not_configured isn't a real failure (no key set, nothing to cool down)
  // -- aiRouter.js already skips these before ever calling recordFailure,
  // but guard here too in case that ever changes.
  if (reason === "not_configured") return;

  const cooldownMs = cooldownForFailure(reason, s.consecutiveFailures, retryAfterMs);
  s.cooldownUntil = Date.now() + cooldownMs;
  s.cooldownReason = reason;
}

function averageLatency(latenciesMs) {
  if (latenciesMs.length === 0) return null;
  return Math.round(latenciesMs.reduce((a, b) => a + b, 0) / latenciesMs.length);
}

/**
 * Canonical uppercase state enum -- AVAILABLE | RATE_LIMITED | COOLING_DOWN |
 * QUOTA_EXCEEDED | AUTH_ERROR | ERROR | NOT_CONFIGURED. Additive alongside
 * the lowercase status/statusLabel pair below (which the existing AI
 * Provider Health panel already renders) rather than replacing them, so
 * this is a pure API addition, not a UI change. The three reason-specific
 * states only apply while actively cooling down for that exact reason;
 * COOLING_DOWN is the generic bucket for the rest (timeout/server_error/
 * network_error/other). ERROR is distinct from all of those: it's the
 * "cooldown just expired but nothing has re-verified this provider yet"
 * window (see isPendingHealthCheck above) -- a provider stays ERROR, not
 * AVAILABLE, until a real health check or request actually succeeds, so a
 * timer running out is never mistaken for the provider being healthy again.
 */
function stateFor(label, configured) {
  if (!configured) return "NOT_CONFIGURED";
  if (isPendingHealthCheck(label)) return "ERROR";
  if (isInCooldown(label)) {
    const reason = state.get(label)?.cooldownReason;
    if (reason === "rate_limited") return "RATE_LIMITED";
    if (reason === "quota_exceeded") return "QUOTA_EXCEEDED";
    if (reason === "auth_error") return "AUTH_ERROR";
    return "COOLING_DOWN";
  }
  return "AVAILABLE";
}

/**
 * Human-readable status for the admin health panel -- mirrors the exact
 * "Gemini ● HEALTHY" / "Groq ● RATE LIMITED — retry in 42 seconds" shape.
 */
function statusFor(label, configured) {
  if (!configured) return { status: "unconfigured", statusLabel: "Not Configured" };
  const s = state.get(label);
  if (!s || (!s.lastFailureAt && !s.lastSuccessAt)) return { status: "healthy", statusLabel: "Healthy" };
  if (isInCooldown(label)) {
    const seconds = Math.ceil(cooldownRemainingMs(label) / 1000);
    const reasonLabel = s.cooldownReason === "auth_error" ? "Authentication Problem" : s.cooldownReason === "quota_exceeded" ? "Quota Exceeded" : s.cooldownReason === "rate_limited" ? "Rate Limited" : "Temporarily Unavailable";
    return { status: s.cooldownReason === "auth_error" ? "misconfigured" : "cooldown", statusLabel: `${reasonLabel} — retry in ${seconds}s` };
  }
  return { status: "healthy", statusLabel: "Healthy" };
}

/**
 * Full per-provider snapshot for the admin AI Provider Health panel.
 * @param {{label: string, model: string, configured: boolean}[]} providers
 */
export function getHealthSnapshot(providers) {
  return providers.map(({ label, model, configured }) => {
    const s = state.get(label) ?? freshState();
    const total = s.totalSuccess + s.totalFailure;
    return {
      label,
      model,
      configured,
      state: stateFor(label, configured),
      ...statusFor(label, configured),
      cooldownRemainingMs: cooldownRemainingMs(label),
      successRate: total > 0 ? Math.round((s.totalSuccess / total) * 100) : null,
      avgLatencyMs: averageLatency(s.latenciesMs),
      totalSuccess: s.totalSuccess,
      totalFailure: s.totalFailure,
      rateLimitCount: s.rateLimitCount,
      timeoutCount: s.timeoutCount,
      authErrorCount: s.authErrorCount,
      lastSuccessAt: s.lastSuccessAt ? new Date(s.lastSuccessAt).toISOString() : null,
      lastFailureAt: s.lastFailureAt ? new Date(s.lastFailureAt).toISOString() : null,
      lastFailureReason: s.lastFailureReason,
    };
  });
}
