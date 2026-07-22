import { appBaseUrl, optionalEnv } from "../lib/env.ts";
import { define } from "../utils.ts";

const DESCRIPTION =
  "Sentinel: monitor self-hosted GitHub Actions runners, system health, and workflow runs.";

/** Prefer configured public origin for absolute OG URLs; fall back to request. */
function publicOrigin(url: URL): string {
  const configured = optionalEnv("APP_BASE_URL");
  if (configured) {
    try {
      return appBaseUrl(url);
    } catch {
      // Invalid APP_BASE_URL: use request origin below.
    }
  }
  return url.origin;
}

export default define.page(function App({ Component, url }) {
  const origin = publicOrigin(url);
  const ogImage = `${origin}/og-image.jpg`;
  const canonical = `${origin}${url.pathname === "/" ? "" : url.pathname}`;

  return (
    <html lang="en" class="theme-sentinel">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta name="color-scheme" content="light" />
        <meta name="theme-color" content="#ffdb1e" />
        <meta name="description" content={DESCRIPTION} />
        <title>Sentinel</title>

        <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
        <link
          rel="icon"
          href="/favicon-32x32.png"
          type="image/png"
          sizes="32x32"
        />
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <link
          rel="apple-touch-icon"
          href="/apple-touch-icon.png"
          sizes="180x180"
        />

        <meta property="og:type" content="website" />
        <meta property="og:site_name" content="Sentinel" />
        <meta property="og:title" content="Sentinel" />
        <meta property="og:description" content={DESCRIPTION} />
        <meta property="og:url" content={canonical} />
        <meta property="og:image" content={ogImage} />
        <meta property="og:image:width" content="1200" />
        <meta property="og:image:height" content="630" />
        <meta property="og:image:alt" content="Sentinel: runner monitoring" />
        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content="Sentinel" />
        <meta name="twitter:description" content={DESCRIPTION} />
        <meta name="twitter:image" content={ogImage} />
        <link rel="canonical" href={canonical} />
      </head>
      <body class="theme-sentinel min-h-screen">
        <a
          href="#main"
          class="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-accent focus:px-3 focus:py-2 focus:text-sm focus:font-semibold focus:text-accent-ink"
        >
          Skip to content
        </a>
        <Component />
      </body>
    </html>
  );
});
