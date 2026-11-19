// The artifact browser's pure parts: the tree the manifest becomes, the path search over it, and the request paths the
// page builds — each entry previewed as an attachment, downloaded through its digest, and the whole artifact archived.
import assert from "node:assert/strict";
import test from "node:test";
import { archiveUrl, dirName, entryUrl, fileName, filter, previewUrl, tree } from "../src/lib/artifacts.ts";

const RUN = "run_0b9c7a1e-3f52-4d6a-9a1e-7c2f1d5b8e40";
const ARTIFACT = "arf_0b9c7a1e-3f52-4d6a-9a1e-7c2f1d5b8e40";
const entry = (path, len = 10, preview = null) => ({ path, digest: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", len, mode: 0o644, preview });

test("entries become a tree with directories above their files", () => {
  const nodes = tree([entry("logs/build.txt"), entry("reports/pass.png"), entry("README.md"), entry("logs/deep/trace.txt")]);
  assert.deepEqual(nodes.map((n) => [n.name, n.dir]), [["logs", true], ["reports", true], ["README.md", false]]);
  const logs = nodes[0];
  assert.deepEqual(logs.children.map((n) => n.name), ["deep", "build.txt"], "directories first, then names");
  assert.equal(logs.children[0].children[0].path, "logs/deep/trace.txt");
});

test("a directory shared by many entries is created once and holds them all", () => {
  const many = Array.from({ length: 200 }, (_, i) => entry(`dist/part-${String(i).padStart(3, "0")}.bin`));
  const nodes = tree(many);
  assert.equal(nodes.length, 1);
  assert.equal(nodes[0].children.length, 200);
  assert.equal(nodes[0].children[0].name, "part-000.bin");
  assert.equal(nodes[0].children[199].name, "part-199.bin");
});

test("a file at the top level has no directory and a deep one names every segment", () => {
  const nodes = tree([entry("a/b/c/d.txt")]);
  assert.equal(nodes[0].path, "a");
  assert.equal(nodes[0].children[0].path, "a/b");
  assert.equal(nodes[0].children[0].children[0].path, "a/b/c");
  assert.equal(nodes[0].children[0].children[0].children[0].path, "a/b/c/d.txt");
  assert.equal(nodes[0].children[0].children[0].children[0].len, 10);
  assert.equal(nodes[0].children[0].children[0].children[0].preview, null);
});

test("an empty manifest is an empty tree", () => {
  assert.deepEqual(tree([]), []);
});

test("the path search keeps the entries whose path holds the text, whatever its case", () => {
  const entries = [entry("logs/build.txt"), entry("logs/test.log"), entry("reports/pass.png")];
  assert.deepEqual(filter(entries, "BUILD").map((e) => e.path), ["logs/build.txt"]);
  assert.deepEqual(filter(entries, "logs/").map((e) => e.path), ["logs/build.txt", "logs/test.log"]);
  assert.deepEqual(filter(entries, "  pass.png ").map((e) => e.path), ["reports/pass.png"]);
  assert.equal(filter(entries, "").length, 3, "an empty search shows everything");
  assert.equal(filter(entries, "   ").length, 3, "spaces are not a search");
  assert.deepEqual(filter(entries, "nothing-here"), []);
});

test("a preview is asked for by the entry path, encoded, so a slash or space never splits the request", () => {
  assert.equal(previewUrl(RUN, ARTIFACT, "logs/build.txt"), `/api/v1/runs/${RUN}/artifacts/${ARTIFACT}/preview?path=logs%2Fbuild.txt`);
  assert.equal(previewUrl(RUN, ARTIFACT, "reports/my pass #1.png"), `/api/v1/runs/${RUN}/artifacts/${ARTIFACT}/preview?path=reports%2Fmy%20pass%20%231.png`);
});

test("an entry downloads through its digest and the artifact through its archive", () => {
  assert.equal(entryUrl("acme", "abc"), "/api/v1/tenants/acme/objects/abc");
  assert.equal(archiveUrl(RUN, ARTIFACT, "tar"), `/api/v1/runs/${RUN}/artifacts/${ARTIFACT}/archive?format=tar`);
  assert.equal(archiveUrl(RUN, ARTIFACT, "zip"), `/api/v1/runs/${RUN}/artifacts/${ARTIFACT}/archive?format=zip`);
});

test("a path's last segment is its file name and the rest is its directory", () => {
  assert.equal(fileName("logs/build.txt"), "build.txt");
  assert.equal(fileName("build.txt"), "build.txt");
  assert.equal(dirName("logs/build.txt"), "logs");
  assert.equal(dirName("a/b/c.txt"), "a/b");
  assert.equal(dirName("c.txt"), "");
});
