import { defineConfig } from "vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import { nitro } from "nitro/vite";
import viteReact from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  server: { port: 3000 },
  plugins: [
    tailwindcss(),
    tanstackStart({ router: { quoteStyle: "double", semicolons: true } }),
    nitro({
      preset: "node-server",
      compressPublicAssets: { gzip: true, brotli: true },
      routeRules: { "/assets/**": { headers: { "cache-control": "public, max-age=31536000, immutable" } } },
    }),
    viteReact(),
  ],
});
