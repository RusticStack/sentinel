/**
 * Unit tests for Vigil SOC client (mocked fetch).
 */
import { assertEquals, assertRejects } from "@std/assert";
import { cache } from "./cache.ts";
import {
  getFinding,
  isVigilConfigured,
  jwtExpiryMs,
  listAgents,
  listCases,
  listFindings,
  loadSecuritySnapshot,
  resetVigilAuthForTests,
  VigilApiError,
} from "./vigil.ts";

const PREV_URL = Deno.env.get("VIGIL_URL");
const PREV_USER = Deno.env.get("VIGIL_USERNAME");
const PREV_PASS = Deno.env.get("VIGIL_PASSWORD");

function setVigilEnv(on: boolean) {
  if (on) {
    Deno.env.set("VIGIL_URL", "http://vigil.test:6987");
    Deno.env.set("VIGIL_USERNAME", "sentinel");
    Deno.env.set("VIGIL_PASSWORD", "secret");
  } else {
    Deno.env.delete("VIGIL_URL");
    Deno.env.delete("VIGIL_USERNAME");
    Deno.env.delete("VIGIL_PASSWORD");
  }
}

function restoreEnv() {
  if (PREV_URL != null) Deno.env.set("VIGIL_URL", PREV_URL);
  else Deno.env.delete("VIGIL_URL");
  if (PREV_USER != null) Deno.env.set("VIGIL_USERNAME", PREV_USER);
  else Deno.env.delete("VIGIL_USERNAME");
  if (PREV_PASS != null) Deno.env.set("VIGIL_PASSWORD", PREV_PASS);
  else Deno.env.delete("VIGIL_PASSWORD");
}

function mockFetchRouter(
  routes: Record<
    string,
    (req: Request) => Response | Promise<Response>
  >,
): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (input, init) => {
    const req = input instanceof Request
      ? input
      : new Request(String(input), init);
    const url = new URL(req.url);
    const key = `${req.method} ${url.pathname}`;
    const handler = routes[key];
    if (!handler) {
      return Promise.resolve(
        new Response(`unexpected ${key}`, { status: 599 }),
      );
    }
    return Promise.resolve(handler(req));
  };
  return () => {
    globalThis.fetch = original;
  };
}

function sampleFinding(id = "f-1") {
  return {
    finding_id: id,
    description: "Suspicious login",
    severity: "high",
    status: "new",
    data_source: "splunk",
    timestamp: "2026-07-22T12:00:00Z",
    anomaly_score: 0.91,
    mitre_predictions: { "T1078": 0.8 },
    entity_context: { user: "alice" },
    ai_enrichment: null,
    cluster_id: null,
    external_id: null,
    created_at: "2026-07-22T12:00:00Z",
    updated_at: "2026-07-22T12:00:00Z",
  };
}

Deno.test("isVigilConfigured reflects VIGIL_URL", () => {
  try {
    setVigilEnv(false);
    assertEquals(isVigilConfigured(), false);
    setVigilEnv(true);
    assertEquals(isVigilConfigured(), true);
  } finally {
    restoreEnv();
  }
});

Deno.test("jwtExpiryMs reads exp claim", () => {
  // {"exp":1700000000} base64url
  const payload = btoa(JSON.stringify({ exp: 1_700_000_000 }))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  const token = `hdr.${payload}.sig`;
  assertEquals(jwtExpiryMs(token), 1_700_000_000_000);
  assertEquals(jwtExpiryMs("not-a-jwt"), null);
});

Deno.test("listFindings logs in and caches results", async () => {
  cache.clear();
  resetVigilAuthForTests();
  setVigilEnv(true);
  let loginCalls = 0;
  const restore = mockFetchRouter({
    "POST /api/auth/login": () => {
      loginCalls += 1;
      return Response.json({
        access_token: "access-1",
        refresh_token: "refresh-1",
        token_type: "bearer",
        user: {},
      });
    },
    "GET /api/findings": (req) => {
      const auth = req.headers.get("Authorization");
      assertEquals(auth, "Bearer access-1");
      return Response.json({
        findings: [sampleFinding("f-1"), sampleFinding("f-2")],
        total: 2,
        offset: 0,
        limit: 50,
        has_more: false,
      });
    },
  });

  try {
    const first = await listFindings({ limit: 50 });
    assertEquals(first.total, 2);
    assertEquals(first.findings[0]?.findingId, "f-1");
    assertEquals(first.findings[0]?.severity, "high");
    assertEquals(loginCalls, 1);

    // Cached: no second login or findings call needed for same key
    const second = await listFindings({ limit: 50 });
    assertEquals(second.total, 2);
    assertEquals(loginCalls, 1);
  } finally {
    restore();
    cache.clear();
    resetVigilAuthForTests();
    restoreEnv();
  }
});

Deno.test("getFinding maps detail and 404", async () => {
  cache.clear();
  resetVigilAuthForTests();
  setVigilEnv(true);
  const restore = mockFetchRouter({
    "POST /api/auth/login": () =>
      Response.json({
        access_token: "a",
        refresh_token: "r",
        token_type: "bearer",
        user: {},
      }),
    "GET /api/findings/f-missing": () =>
      new Response(JSON.stringify({ detail: "Finding not found" }), {
        status: 404,
      }),
    "GET /api/findings/f-ok": () => Response.json(sampleFinding("f-ok")),
  });

  try {
    const ok = await getFinding("f-ok");
    assertEquals(ok.findingId, "f-ok");
    assertEquals(ok.dataSource, "splunk");

    await assertRejects(
      () => getFinding("f-missing"),
      VigilApiError,
      "Finding not found",
    );
  } finally {
    restore();
    cache.clear();
    resetVigilAuthForTests();
    restoreEnv();
  }
});

Deno.test("listCases and listAgents normalize payloads", async () => {
  cache.clear();
  resetVigilAuthForTests();
  setVigilEnv(true);
  const restore = mockFetchRouter({
    "POST /api/auth/login": () =>
      Response.json({
        access_token: "a",
        refresh_token: "r",
        token_type: "bearer",
        user: {},
      }),
    "GET /api/cases": () =>
      Response.json({
        cases: [{
          case_id: "c-1",
          title: "Incident",
          description: "desc",
          status: "open",
          priority: "high",
          assignee: null,
          tags: ["phish"],
          mitre_techniques: ["T1566"],
          finding_ids: ["f-1"],
          created_at: "2026-07-22T00:00:00Z",
          updated_at: "2026-07-22T00:00:00Z",
        }],
        total: 1,
      }),
    "GET /api/agents/agents": () =>
      Response.json({
        agents: [{
          id: "triage",
          name: "Triage Agent",
          description: "Quick triage",
          specialization: "triage",
          icon: null,
          color: null,
        }],
        current_agent: "triage",
      }),
  });

  try {
    const cases = await listCases();
    assertEquals(cases.total, 1);
    assertEquals(cases.cases[0]?.caseId, "c-1");
    assertEquals(cases.cases[0]?.mitreTechniques, ["T1566"]);

    const agents = await listAgents();
    assertEquals(agents.agents.length, 1);
    assertEquals(agents.currentAgent, "triage");
  } finally {
    restore();
    cache.clear();
    resetVigilAuthForTests();
    restoreEnv();
  }
});

Deno.test("loadSecuritySnapshot returns null when unset", async () => {
  setVigilEnv(false);
  try {
    assertEquals(await loadSecuritySnapshot(), null);
  } finally {
    restoreEnv();
  }
});

Deno.test("loadSecuritySnapshot soft-fails with error field", async () => {
  cache.clear();
  resetVigilAuthForTests();
  setVigilEnv(true);
  const restore = mockFetchRouter({
    "POST /api/auth/login": () => new Response("nope", { status: 401 }),
  });

  try {
    const snap = await loadSecuritySnapshot();
    assertEquals(snap?.enabled, true);
    assertEquals(snap?.findingsTotal, 0);
    assertEquals(typeof snap?.error, "string");
  } finally {
    restore();
    cache.clear();
    resetVigilAuthForTests();
    restoreEnv();
  }
});

Deno.test("401 triggers re-login then succeeds", async () => {
  cache.clear();
  resetVigilAuthForTests();
  setVigilEnv(true);
  let findingsHits = 0;
  let loginHits = 0;
  const restore = mockFetchRouter({
    "POST /api/auth/login": () => {
      loginHits += 1;
      return Response.json({
        access_token: `access-${loginHits}`,
        refresh_token: `refresh-${loginHits}`,
        token_type: "bearer",
        user: {},
      });
    },
    "GET /api/findings": (req) => {
      findingsHits += 1;
      const auth = req.headers.get("Authorization");
      if (findingsHits === 1) {
        assertEquals(auth, "Bearer access-1");
        return new Response("expired", { status: 401 });
      }
      assertEquals(auth, "Bearer access-2");
      return Response.json({
        findings: [sampleFinding()],
        total: 1,
      });
    },
  });

  try {
    const result = await listFindings({ limit: 10 });
    assertEquals(result.total, 1);
    assertEquals(loginHits, 2);
    assertEquals(findingsHits, 2);
  } finally {
    restore();
    cache.clear();
    resetVigilAuthForTests();
    restoreEnv();
  }
});
