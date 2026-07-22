import { assertEquals, assertExists } from "@std/assert";
import { cache, TtlCache } from "./cache.ts";

Deno.test("TtlCache stores and returns values", () => {
  const c = new TtlCache();
  c.set("a", 42, 60_000);
  assertEquals(c.get<number>("a"), 42);
});

Deno.test("TtlCache expires entries", async () => {
  const c = new TtlCache();
  c.set("a", "x", 20);
  assertEquals(c.get<string>("a"), "x");
  await new Promise((r) => setTimeout(r, 30));
  assertEquals(c.get<string>("a"), undefined);
});

Deno.test("shared cache singleton works", () => {
  cache.clear();
  cache.set("probe", true, 60_000);
  assertEquals(cache.get<boolean>("probe"), true);
  cache.delete("probe");
  assertEquals(cache.get<boolean>("probe"), undefined);
  assertExists(cache);
});
