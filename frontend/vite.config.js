import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The FastAPI backend runs on 8000. Proxying through /api keeps the frontend on
// one origin in development, so there is no CORS preflight and no base URL for
// the client to guess. The client's VITE_API_BASE defaults to this prefix.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});