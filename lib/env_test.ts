import { assertEquals, assertThrows } from "@std/assert";
import { appBaseUrl, cookiesMustBeSecure, runnerCount } from "./env.ts";

Deno.test("appBaseUrl allows loopback without APP_BASE_URL", () => {
  Deno.env.delete("APP_BASE_URL");
  assertEquals(
    appBaseUrl(new URL("http://localhost:8000/auth/login")),
    "http://localhost:8000",
  );
  assertEquals(
    appBaseUrl(new URL("http://127.0.0.1:8000/")),
    "http://127.0.0.1:8000",
  );
});

Deno.test("appBaseUrl requires APP_BASE_URL off loopback", () => {
  Deno.env.delete("APP_BASE_URL");
  assertThrows(
    () => appBaseUrl(new URL("https://sentinel.example.com/")),
    Error,
    "APP_BASE_URL is required",
  );
});

Deno.test("appBaseUrl and cookiesMustBeSecure honor APP_BASE_URL", () => {
  Deno.env.set("APP_BASE_URL", "https://sentinel.example.com/");
  try {
    assertEquals(
      appBaseUrl(new URL("http://internal:3000/")),
      "https://sentinel.example.com",
    );
    assertEquals(
      cookiesMustBeSecure(new URL("http://internal:3000/")),
      true,
    );
  } finally {
    Deno.env.delete("APP_BASE_URL");
  }
});

Deno.test("runnerCount defaults to 4 and parses RUNNER_COUNT", () => {
  Deno.env.delete("RUNNER_COUNT");
  assertEquals(runnerCount(), 4);
  Deno.env.set("RUNNER_COUNT", "6");
  assertEquals(runnerCount(), 6);
  Deno.env.set("RUNNER_COUNT", "nope");
  assertEquals(runnerCount(), 4);
  Deno.env.delete("RUNNER_COUNT");
});
