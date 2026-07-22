import { assertEquals } from "@std/assert";
import { parseRepoName, REPO_NAME_MAX_LENGTH } from "./validate.ts";

Deno.test("parseRepoName accepts bare GitHub repo names", () => {
  assertEquals(parseRepoName("sentinel"), "sentinel");
  assertEquals(parseRepoName("my-repo"), "my-repo");
  assertEquals(parseRepoName("my_repo"), "my_repo");
  assertEquals(parseRepoName("repo.name"), "repo.name");
  assertEquals(parseRepoName("Repo123"), "Repo123");
  assertEquals(parseRepoName("  sentinel  "), "sentinel");
});

Deno.test("parseRepoName rejects empty or missing", () => {
  assertEquals(parseRepoName(null), null);
  assertEquals(parseRepoName(undefined), null);
  assertEquals(parseRepoName(""), null);
  assertEquals(parseRepoName("   "), null);
});

Deno.test("parseRepoName rejects path tricks and org/name", () => {
  assertEquals(parseRepoName("../etc"), null);
  assertEquals(parseRepoName("foo/bar"), null);
  assertEquals(parseRepoName("foo\\bar"), null);
  assertEquals(parseRepoName("foo bar"), null);
  assertEquals(parseRepoName("repo%20name"), null);
  assertEquals(parseRepoName("repo;rm"), null);
  assertEquals(parseRepoName("acme/sentinel"), null);
});

Deno.test("parseRepoName enforces max length", () => {
  assertEquals(
    parseRepoName("a".repeat(REPO_NAME_MAX_LENGTH)),
    "a".repeat(100),
  );
  assertEquals(parseRepoName("a".repeat(REPO_NAME_MAX_LENGTH + 1)), null);
});
