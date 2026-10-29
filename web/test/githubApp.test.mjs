// Which installation links the setup page may follow.
import assert from "node:assert/strict";
import test from "node:test";
import { isGithubUrl } from "../src/lib/githubApp.ts";

test("an https link is followed, and plain http only to a loopback host", () => {
  for (const ok of [
    "https://github.com/apps/acme-ci/installations/new?state=abc",
    "https://ghe.corp.example/apps/acme-ci/installations/new",
    "http://localhost:9/apps/acme-ci/installations/new?state=abc",
    "http://127.0.0.1:9/apps/acme-ci/installations/new",
    "http://[::1]:9/apps/acme-ci/installations/new",
    "http://github.localhost:9/apps/acme-ci/installations/new",
  ]) assert.equal(isGithubUrl(ok), true, ok);
});

test("anything else is refused: other schemes, plain http to a real host, credentials, junk", () => {
  for (const bad of [
    "http://github.com/apps/acme-ci/installations/new",
    "http://evil.example/apps/x/installations/new",
    "http://localhost.evil.example/apps/x/installations/new",
    "http://127.0.0.1.evil.example/",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https://user:pass@github.com/apps/x",
    "https://user@github.com/apps/x",
    "http://user:pass@localhost:9/",
    "//github.com/apps/x",
    "/apps/x/installations/new",
    "",
    "not a url",
  ]) assert.equal(isGithubUrl(bad), false, bad);
  assert.equal(isGithubUrl(undefined), false);
  assert.equal(isGithubUrl(null), false);
});
