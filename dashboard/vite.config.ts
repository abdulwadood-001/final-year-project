import path from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";

// Plain client-side SPA: built to static files that Nginx serves next to the API.
// `npm run dev` proxies /api (REST + WebSocket) to a running HoneyBot-IoT API.
const API = process.env["HONEYBOT_API"] ?? "http://127.0.0.1:5000";

export default defineConfig({
  plugins: [
    // must run before the React plugin: generates src/routeTree.gen.ts from src/routes/
    tanstackRouter({ target: "react", autoCodeSplitting: true }),
    react(),
    tailwindcss(),
  ],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  server: {
    port: 5173,
    proxy: { "/api": { target: API, changeOrigin: true, ws: true } },
  },
  build: { sourcemap: false, chunkSizeWarningLimit: 1500 },
});
