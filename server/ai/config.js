// Central place for the AI Router's own provider credentials/model
// overrides -- kept scoped to just this subsystem (server/ai/) rather than
// a project-wide env-config refactor; every other connector/lookup in this
// app still reads process.env directly at its own call site (see
// server/connectors/*.js), same as before. This file
// exists because the AIRouter is explicitly meant to make "add a 5th
// provider" a two-file change (one entry here + one new providers/*.js) --
// without it, each provider's env var name/default model would live
// scattered across the provider files instead.
// `fastModel` is each provider's smaller/cheaper tier -- opted into per-call
// via summarize(prompt, {tier: "fast"}) / summarizeJson(prompt, opts, {tier:
// "fast"}) (see aiRouter.js), for high-volume callers like
// server/combinedExtraction.js that run continuously against dozens of
// articles per cycle and need a materially higher free-tier rate limit more
// than they need the larger model's extra quality on a lightweight
// six-category name/ID extraction. Every other caller omits `tier` and gets
// each provider's normal `model` as before -- this is purely additive.
// `contextWindow` (tokens, approximate) lets aiRouter.js skip a provider
// for the one call in this app that genuinely needs a lot of headroom
// (server/aiThreatSummary.js's 25+ section structured report, an
// 11.5k+ token completion) instead of discovering the hard way that a
// smaller free-tier model truncated or rejected it. These are best-effort
// figures from each provider's published model card at the time this was
// written, not something this app can verify live -- treat as a soft
// routing hint, not a guarantee, and bump via env override if a provider
// changes its served context length.
export const AI_ROUTER_CONFIG = {
  gemini: {
    apiKey: process.env.GEMINI_API_KEY,
    // Confirmed live that a pinned "gemini-2.5-flash" 404s for newer API
    // keys ("no longer available to new users" per Google's own error) --
    // using Google's maintained "-latest" alias instead of a pinned version
    // avoids this exact breakage recurring every time a model gets retired.
    model: process.env.GEMINI_MODEL || "gemini-flash-latest",
    // Flash-Lite: Google's own lighter/faster/higher-quota tier below Flash.
    fastModel: process.env.GEMINI_FAST_MODEL || "gemini-flash-lite-latest",
    contextWindow: Number(process.env.GEMINI_CONTEXT_WINDOW) || 1_000_000,
  },
  groq: {
    apiKey: process.env.GROQ_API_KEY,
    model: process.env.GROQ_CHAT_MODEL || "llama-3.3-70b-versatile",
    // Same env var server/combinedExtraction.js already read directly for
    // this before it moved onto the router -- kept so existing deployments'
    // .env configuration doesn't need to change. llama-3.1-8b-instant was
    // decommissioned by Groq (confirmed live: 404 model_not_found) --
    // replaced with a currently-available small/fast model.
    fastModel: process.env.GROQ_EXTRACTION_MODEL || "openai/gpt-oss-20b",
    contextWindow: Number(process.env.GROQ_CONTEXT_WINDOW) || 128_000,
  },
  cohere: {
    apiKey: process.env.COHERE_API_KEY,
    // Confirmed live that the undated "command-r" was retired ("removed on
    // September 15, 2025" per Cohere's own error) -- command-r-08-2024 is
    // the last still-live dated snapshot of the same model family. Unlike
    // Gemini, Cohere has no "-latest" alias, so this will need bumping by
    // hand again once this snapshot is retired too.
    model: process.env.COHERE_MODEL || "command-r-08-2024",
    // Command R7B: Cohere's own lightweight tier of the same model family.
    fastModel: process.env.COHERE_FAST_MODEL || "command-r7b-12-2024",
    contextWindow: Number(process.env.COHERE_CONTEXT_WINDOW) || 128_000,
  },
  // -- Everything below is free-tier-friendly, every key optional and
  // independently skippable (see providers/*.js's isConfigured()).
  // OpenRouter is a MODEL ROUTER, not a single model -- OPENROUTER_MODEL
  // picks which upstream model it forwards to. Defaults to a ":free"-tagged
  // model (OpenRouter's own convention for its no-cost tier); verify current
  // availability at https://openrouter.ai/models?max_price=0 since free
  // model availability there rotates over time.
  openrouter: {
    apiKey: process.env.OPENROUTER_API_KEY,
    model: process.env.OPENROUTER_MODEL || "meta-llama/llama-3.3-70b-instruct:free",
    fastModel: process.env.OPENROUTER_FAST_MODEL || "meta-llama/llama-3.1-8b-instruct:free",
    contextWindow: Number(process.env.OPENROUTER_CONTEXT_WINDOW) || 8_000,
  },
  huggingface: {
    apiKey: process.env.HUGGINGFACE_API_KEY,
    // Served through HF's unified Inference Providers router
    // (router.huggingface.co) -- model catalog and monthly free credit
    // amount both vary by account, verify at https://huggingface.co/settings/inference-providers
    model: process.env.HUGGINGFACE_MODEL || "meta-llama/Llama-3.3-70B-Instruct",
    fastModel: process.env.HUGGINGFACE_FAST_MODEL || "meta-llama/Llama-3.1-8B-Instruct",
    contextWindow: Number(process.env.HUGGINGFACE_CONTEXT_WINDOW) || 8_000,
  },
  together: {
    apiKey: process.env.TOGETHER_API_KEY,
    // Together AI's free tier is trial-credit-based rather than permanently
    // free like the others here -- the "-Free" suffixed model below is
    // Together's own designated no-cost model at time of writing, verify at
    // https://api.together.ai/models before relying on it long-term.
    model: process.env.TOGETHER_MODEL || "meta-llama/Llama-3.3-70B-Instruct-Turbo-Free",
    fastModel: process.env.TOGETHER_FAST_MODEL || "meta-llama/Llama-3.2-3B-Instruct-Turbo",
    contextWindow: Number(process.env.TOGETHER_CONTEXT_WINDOW) || 8_000,
  },
  // Cloudflare Workers AI needs a 2nd credential (account ID, not just a
  // token) and has its own request/response envelope, not the OpenAI chat
  // shape every other provider here uses -- see providers/cloudflareProvider.js.
  cloudflare: {
    apiKey: process.env.CLOUDFLARE_API_TOKEN,
    accountId: process.env.CLOUDFLARE_ACCOUNT_ID,
    model: process.env.CLOUDFLARE_MODEL || "@cf/meta/llama-3.3-70b-instruct-fp8-fast",
    fastModel: process.env.CLOUDFLARE_FAST_MODEL || "@cf/meta/llama-3.1-8b-instruct-fast",
    contextWindow: Number(process.env.CLOUDFLARE_CONTEXT_WINDOW) || 24_000,
  },
  // GitHub Models -- free for any GitHub account (rate limits scale with
  // Copilot subscription tier), auth via a fine-grained PAT with "Models"
  // read permission, OpenAI-compatible endpoint.
  githubModels: {
    apiKey: process.env.GITHUB_MODELS_TOKEN,
    model: process.env.GITHUB_MODELS_MODEL || "openai/gpt-4o-mini",
    fastModel: process.env.GITHUB_MODELS_FAST_MODEL || "meta/Meta-Llama-3.1-8B-Instruct",
    contextWindow: Number(process.env.GITHUB_MODELS_CONTEXT_WINDOW) || 16_000,
  },
  // Ollama Cloud -- free, no-credit-card signup at ollama.com, generate a
  // key under Settings -> API Keys. Free tier is GPU-time-based (session
  // limits resetting every 5h, weekly limits every 7 days) rather than a
  // fixed per-day request count like the others here -- see
  // https://docs.ollama.com/cloud. Own request/response envelope, see
  // providers/ollamaProvider.js.
  ollama: {
    apiKey: process.env.OLLAMA_API_KEY,
    model: process.env.OLLAMA_MODEL || "gpt-oss",
    fastModel: process.env.OLLAMA_FAST_MODEL || "gemma4",
    contextWindow: Number(process.env.OLLAMA_CONTEXT_WINDOW) || 32_000,
  },
};
