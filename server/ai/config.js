// Central place for the AI Router's own provider credentials/model
// overrides -- kept scoped to just this subsystem (server/ai/) rather than
// a project-wide env-config refactor; every other connector/lookup in this
// app still reads process.env directly at its own call site (see
// server/groqClient.js, server/connectors/*.js), same as before. This file
// exists because the AIRouter is explicitly meant to make "add a 5th
// provider" a two-file change (one entry here + one new providers/*.js) --
// without it, each provider's env var name/default model would live
// scattered across the provider files instead.
export const AI_ROUTER_CONFIG = {
  gemini: {
    apiKey: process.env.GEMINI_API_KEY,
    // Confirmed live that a pinned "gemini-2.5-flash" 404s for newer API
    // keys ("no longer available to new users" per Google's own error) --
    // using Google's maintained "-latest" alias instead of a pinned version
    // avoids this exact breakage recurring every time a model gets retired.
    model: process.env.GEMINI_MODEL || "gemini-flash-latest",
  },
  qwen: {
    // Qwen is served through OpenRouter's single unified API, not its own
    // vendor endpoint -- one OpenRouter key covers every model on their
    // platform, so this deliberately reuses OPENROUTER_API_KEY rather than
    // introducing a Qwen-specific key that doesn't exist.
    apiKey: process.env.OPENROUTER_API_KEY,
    model: process.env.OPENROUTER_QWEN_MODEL || "qwen/qwen3-32b",
  },
  groq: {
    // Same key this app already uses for server/groqClient.js's structured
    // report/extraction calls -- one Groq account, one key, both consumers.
    apiKey: process.env.GROQ_API_KEY,
    model: process.env.GROQ_CHAT_MODEL || "llama-3.3-70b-versatile",
  },
  cohere: {
    apiKey: process.env.COHERE_API_KEY,
    // Confirmed live that the undated "command-r" was retired ("removed on
    // September 15, 2025" per Cohere's own error) -- command-r-08-2024 is
    // the last still-live dated snapshot of the same model family. Unlike
    // Gemini, Cohere has no "-latest" alias, so this will need bumping by
    // hand again once this snapshot is retired too.
    model: process.env.COHERE_MODEL || "command-r-08-2024",
  },
};
