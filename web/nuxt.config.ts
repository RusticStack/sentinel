// Sentinel's web interface: a Nuxt server that renders the pages, streams
// live run and log updates to the browser, and proxies the controller's
// own routes (API, OAuth, GitHub sign-in, MCP) so everything is one origin.
// The controller stays the only authority: this process holds no
// credential of its own and forwards the browser's session as it came.
export default defineNuxtConfig({
  compatibilityDate: "2026-09-01",
  modules: ["@nuxt/ui"],
  css: ["~/assets/css/main.css"],
  devtools: { enabled: false },
  telemetry: false,

  // Self-hosted and possibly offline: no web fonts fetched at build time,
  // icons bundled from the local Lucide set instead of the Iconify API.
  ui: { fonts: false, theme: { colors: ["primary", "neutral", "success", "warning", "error", "info"] } },
  icon: {
    serverBundle: { collections: ["lucide"] },
    // Icons named at run time (state badges) are bundled explicitly; the
    // rest are found by scanning the components.
    clientBundle: {
      scan: true,
      sizeLimitKb: 256,
      icons: [
        "lucide:circle-check", "lucide:circle-x", "lucide:timer-off", "lucide:ban", "lucide:skip-forward",
        "lucide:loader-circle", "lucide:git-merge", "lucide:circle-dashed", "lucide:radio", "lucide:wifi-off",
        "lucide:circle-power", "lucide:pause", "lucide:play", "lucide:check", "lucide:circle-alert",
      ],
    },
  },

  runtimeConfig: {
    // The controller's API listener (`api_listen`), reached server-side:
    // NUXT_SENTINEL_API=http://127.0.0.1:7080
    sentinelApi: "http://127.0.0.1:7080",
    // The header the reverse proxy in front of this process sets to the
    // real client address (`x-forwarded-for`, `x-real-ip`, ...):
    // NUXT_CLIENT_IP_HEADER=x-forwarded-for. Empty (the default) counts
    // every client under the socket peer and trusts no header, so a client
    // can never choose its own rate-limit bucket. Set it only when this
    // process is reachable through that proxy alone.
    clientIpHeader: "",
  },

  app: {
    head: {
      htmlAttrs: { lang: "en" },
      title: "Sentinel",
      meta: [{ name: "referrer", content: "no-referrer" }],
      link: [{ rel: "icon", href: "data:," }],
    },
  },

  nitro: {
    preset: "node-server",
    compressPublicAssets: { gzip: true, brotli: true },
    routeRules: {
      "/**": {
        headers: {
          "x-frame-options": "DENY",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
          "permissions-policy": "accelerometer=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), microphone=(), midi=(), payment=(), serial=(), usb=(), interest-cohort=()",
        },
      },
      // Built assets are named by content.
      "/_nuxt/**": { headers: { "cache-control": "public, max-age=31536000, immutable" } },
    },
  },

  typescript: { strict: true },
});
