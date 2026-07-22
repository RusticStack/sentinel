import { define } from "../utils.ts";

export default define.page(function App({ Component }) {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta
          name="description"
          content="Sentinel — monitor self-hosted GitHub Actions runners, system health, and workflow runs."
        />
        <title>Sentinel</title>
        <link rel="icon" href="/favicon.ico" sizes="any" />
      </head>
      <body class="min-h-screen">
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
