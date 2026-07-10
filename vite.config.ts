import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = path.dirname(fileURLToPath(import.meta.url));

// The backend (server/index.js) is now a real aggregation service -- it owns
// scheduling, caching, retries and correlation for every source (see
// server/scheduler.js) -- not just a passthrough proxy. That means it has to
// run as a persistent process in dev too, so `npm run dev` starts both it
// and Vite together (see package.json). Vite's job here shrinks to a single
// proxy rule: forward /api/* to that local backend.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(rootDir, "./src"),
    },
  },
  server: {
    port: 5173,
    // Binds to all network interfaces, not just localhost, so a phone on the
    // same WiFi can reach this dev server via the PC's LAN IP. The /api
    // proxy target below stays `localhost:8080` regardless -- that proxying
    // happens server-side on this same machine, not from the phone's browser.
    host: true,
    proxy: {
      "/api": {
        target: `http://localhost:${process.env.PORT || 8080}`,
        changeOrigin: true,
      },
    },
  },
});
