# Sentinel

A new, fully open-source, self-hosted CI engine being designed for fast feedback, local-first caching, multi-machine workers, and readable diagnostics for humans and coding agents.

**Status: planning; the new CI engine is not implemented yet.** See [plan.md](plan.md) for architecture, milestones, performance targets, and release criteria.

The new implementation will use a Rust core and its own pipeline format. GitHub will remain the forge, with results published through Checks. The default deployment will use embedded SQLite and Sentinel-owned local storage, with optional external S3 and Tailcat-connected workers.

## Legacy dashboard

The original Deno/Fresh GitHub Actions runner dashboard and its full history are preserved on [`legacy`](https://github.com/RusticStack/sentinel/tree/legacy). This `main` branch begins the from-scratch replacement.

## License

[MIT](LICENSE).
