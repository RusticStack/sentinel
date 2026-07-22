import { defineConfig } from "vite";
import { fresh } from "@fresh/plugin-vite";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [fresh(), tailwindcss()],
  server: {
    port: 8000,
    // Deno's fs.watch throws if a watched path disappears mid-edit (editor
    // temps, partial uploads). Ignore static junk so HMR doesn't kill the
    // process: do not ignore routes/_*.tsx (Fresh conventions).
    watch: {
      ignored: [
        "**/.git/**",
        "**/node_modules/**",
        "**/_fresh/**",
        "**/static/_*",
        "**/*~",
        "**/*.swp",
        "**/*.tmp",
      ],
    },
  },
});
