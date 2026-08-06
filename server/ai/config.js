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
  },
  mistral: {
    apiKey: process.env.MISTRAL_API_KEY,
    model: process.env.MISTRAL_MODEL || "mistral-small-latest",
    // Ministral 8B: Mistral's dedicated small/edge model family, well below Small.
    fastModel: process.env.MISTRAL_FAST_MODEL || "ministral-8b-latest",
  },
  groq: {
    apiKey: process.env.GROQ_API_KEY,
    model: process.env.GROQ_CHAT_MODEL || "llama-3.3-70b-versatile",
    // Same env var server/combinedExtraction.js already read directly for
    // this before it moved onto the router -- kept so existing deployments'
    // .env configuration doesn't need to change.
    fastModel: process.env.GROQ_EXTRACTION_MODEL || "llama-3.1-8b-instant",
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
  },
};
