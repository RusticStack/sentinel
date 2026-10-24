export default defineNuxtConfig({
  compatibilityDate: "2026-09-01",
  modules: ["@nuxt/ui"],
  css: ["~/assets/css/main.css"],
  devtools: { enabled: false },
  telemetry: false,

  ui: { fonts: false, theme: { colors: ["primary", "neutral", "success", "warning", "error", "info"] } },
  colorMode: { disableTransition: false },
  icon: {
    // Inline svg: the css mode adds a <style> element that the hash-only style-src refuses.
    mode: "svg",
    serverBundle: { collections: ["lucide"] },
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
    sentinelApi: "http://127.0.0.1:7080",
    // Empty trusts no header, so a client can never choose its own rate-limit bucket.
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
      "/_nuxt/**": { headers: { "cache-control": "public, max-age=31536000, immutable" } },
    },
  },

  typescript: { strict: true },
});
