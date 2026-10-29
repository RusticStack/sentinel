// Run with node --test through test/ts-register.mjs (pnpm test:unit).
import assert from "node:assert/strict";
import test from "node:test";
import {
  digestVerdict, enrollmentError, identityCommand, installCommand, MAX_GIB, parseIdentityLine, parseTerms, rollbackCommand,
  scrub, secretFileCommand, sha256Hex, statedDigest, uninstallCommand, workerName,
} from "../src/lib/enrollment.ts";

const HEX = "0123456789abcdef".repeat(4);
const WORKER = "wrk_0b6d3f5a-1c2e-4a7b-9d8c-5e4f3a2b1c0d";
const blank = { cpu: "", memoryGiB: "", diskGiB: "", priority: "0", lifetimeHours: "1" };
const terms = (over) => parseTerms({ ...blank, ...over });

test("empty ceilings mean no ceiling, and the defaults are neutral priority for an hour", () => {
  const r = terms({});
  assert.deepEqual(r, { ok: true, value: { priority: 0, lifetime_ms: 3_600_000 } });
  assert.ok(!("cpu_millis" in r.value) && !("memory_bytes" in r.value) && !("disk_bytes" in r.value));
});

test("ceilings are converted exactly: cores to millicores, whole GiB to bytes", () => {
  const r = terms({ cpu: "4", memoryGiB: "16", diskGiB: "200", priority: "-5", lifetimeHours: "24" });
  assert.deepEqual(r.value, { cpu_millis: 4000, memory_bytes: 16 * 2 ** 30, disk_bytes: 200 * 2 ** 30, priority: -5, lifetime_ms: 86_400_000 });
  assert.equal(terms({ cpu: "0.5" }).value.cpu_millis, 500);
  assert.equal(terms({ cpu: "2.25" }).value.cpu_millis, 2250);
  assert.equal(terms({ cpu: " 1.001 " }).value.cpu_millis, 1001);
  assert.equal(terms({ memoryGiB: String(MAX_GIB) }).value.memory_bytes, MAX_GIB * 2 ** 30);
  assert.ok(Number.isSafeInteger(MAX_GIB * 2 ** 30));
});

test("a ceiling that is zero, negative, fractional, huge, or not a number is refused with the field named", () => {
  for (const [over, field] of [
    [{ cpu: "0" }, "cpu"], [{ cpu: "-1" }, "cpu"], [{ cpu: "1.0001" }, "cpu"], [{ cpu: "1e3" }, "cpu"], [{ cpu: "abc" }, "cpu"], [{ cpu: "100001" }, "cpu"], [{ cpu: "0.000" }, "cpu"],
    [{ memoryGiB: "0" }, "memoryGiB"], [{ memoryGiB: "-4" }, "memoryGiB"], [{ memoryGiB: "1.5" }, "memoryGiB"],
    [{ memoryGiB: String(MAX_GIB + 1) }, "memoryGiB"], [{ memoryGiB: "9007199254740993" }, "memoryGiB"], [{ memoryGiB: "0x10" }, "memoryGiB"],
    [{ diskGiB: "0" }, "diskGiB"], [{ diskGiB: "12 GiB" }, "diskGiB"], [{ diskGiB: "NaN" }, "diskGiB"], [{ diskGiB: "Infinity" }, "diskGiB"],
    [{ priority: "101" }, "priority"], [{ priority: "-101" }, "priority"], [{ priority: "1.5" }, "priority"], [{ priority: "+3" }, "priority"], [{ priority: "x" }, "priority"],
    [{ lifetimeHours: "0" }, "lifetimeHours"], [{ lifetimeHours: "25" }, "lifetimeHours"], [{ lifetimeHours: "1.5" }, "lifetimeHours"], [{ lifetimeHours: "-1" }, "lifetimeHours"],
  ]) {
    const r = terms(over);
    assert.equal(r.ok, false, JSON.stringify(over));
    assert.equal(r.field, field, JSON.stringify(over));
    assert.ok(r.message.length > 10);
  }
  assert.equal(terms({ priority: "100" }).ok, true);
  assert.equal(terms({ priority: "-100" }).ok, true);
  assert.equal(terms({ priority: "-0" }).value.priority, 0);
  assert.ok(Object.is(terms({ priority: "-0" }).value.priority, 0));
});

test("only the exact identity line is accepted", () => {
  const good = `nodekey:${HEX} ${WORKER}`;
  assert.deepEqual(parseIdentityLine(good), { worker: WORKER, node_key: `nodekey:${HEX}` });
  assert.deepEqual(parseIdentityLine(`  ${good}\n`), { worker: WORKER, node_key: `nodekey:${HEX}` });
  assert.deepEqual(parseIdentityLine(`nodekey:${HEX}\t${WORKER}`)?.worker, WORKER);
  for (const bad of [
    "", `nodekey:${HEX}`, WORKER, `${WORKER} nodekey:${HEX}`,
    `nodekey:${HEX}\n${WORKER}\nnodekey:${HEX} ${WORKER}`,
    `nodekey:${HEX} ${WORKER} extra`,
    `nodekey:${HEX} ${HEX}`,
    `nodekey:${HEX.slice(1)} ${WORKER}`, `nodekey:${HEX}0 ${WORKER}`,
    `nodekey:${HEX.toUpperCase()} ${WORKER}`, `NODEKEY:${HEX} ${WORKER}`, `key:${HEX} ${WORKER}`,
    `nodekey:${HEX} wrk_${HEX}`, `nodekey:${HEX} ${WORKER.toUpperCase()}`, `nodekey:${HEX} tok_0b6d3f5a-1c2e-4a7b-9d8c-5e4f3a2b1c0d`,
    `nodekey:${"g".repeat(64)} ${WORKER}`, `nodekey:${HEX} ${WORKER}`.padEnd(300, " ") + "x",
  ]) {
    assert.equal(parseIdentityLine(bad), null, JSON.stringify(bad).slice(0, 80));
  }
});

test("the 409, 404 and 429 states read as plain sentences per action", () => {
  const conflict = { status: 409, code: "conflict", message: "not allowed from the current state" };
  const missing = { status: 404, code: "not_found", message: "not found" };
  const limited = { status: 429, code: "rate_limited", message: "too many requests; retry later", details: { retry_after_ms: 6000 } };
  assert.match(enrollmentError(conflict, "download").text, /no longer pending.*redeemed, withdrawn or has expired/);
  assert.match(enrollmentError(conflict, "withdraw").text, /already used, withdrawn or expired/);
  assert.match(enrollmentError(conflict, "node-key").text, /no longer pending.*different worker or key/);
  assert.match(enrollmentError({ ...conflict, message: "this controller has no Tailcat helper configured; choose transport \"direct\"" }, "issue").text, /no Tailcat helper configured/);
  assert.match(enrollmentError(missing, "issue").text, /pool does not exist or is no longer active/);
  assert.match(enrollmentError(missing, "withdraw").text, /already used, withdrawn or gone/);
  assert.match(enrollmentError(missing, "node-key").text, /does not exist any more/);
  assert.match(enrollmentError(missing, "uninstall").text, /not enrolled any more/);
  const wait = enrollmentError(limited, "issue");
  assert.match(wait.text, /Too many requests.*6 seconds/);
  assert.equal(wait.retryMs, 6000);
  assert.equal(enrollmentError({ ...limited, details: {} }, "issue").retryMs, 1000);
  assert.match(enrollmentError({ status: 0, code: "network", message: "HTTP 0" }, "issue").text, /secret is lost for good/);
  assert.doesNotMatch(enrollmentError({ status: 0, code: "network", message: "HTTP 0" }, "withdraw").text, /secret is lost/);
  assert.match(enrollmentError({ status: 403, code: "forbidden", message: "step-up required", details: { step_up: true } }, "issue").text, /second factor/);
  assert.match(enrollmentError({ status: 403, code: "forbidden", message: "not permitted" }, "issue").text, /not permitted/);
});

test("no sentence repeats a secret-shaped value the controller or the person supplied", () => {
  const secrets = [`sntl_${HEX}`, `nodekey:${HEX}`, HEX, HEX.toUpperCase()];
  for (const secret of secrets) {
    for (const context of ["issue", "withdraw", "node-key", "download", "uninstall", "load"]) {
      for (const code of ["conflict", "invalid_request", "not_found", "forbidden", "rate_limited", "network", "http_500", "unauthenticated"]) {
        const { text } = enrollmentError({ status: 400, code, message: `bad value ${secret} here`, details: { echoed: secret } }, context);
        assert.ok(!text.includes(HEX) && !text.includes(HEX.toUpperCase()), `${context} ${code}: ${text}`);
      }
    }
  }
  assert.equal(scrub(`a sntl_${HEX} b nodekey:${HEX} c`), "a … b … c");
  assert.equal(scrub("x".repeat(500)).length, 300);
});

test("the commands name no secret value and the worker name falls back when the script would refuse it", () => {
  const commands = [installCommand("rack-7"), secretFileCommand(), identityCommand(), rollbackCommand(), uninstallCommand()];
  for (const c of commands) {
    assert.doesNotMatch(c, /sntl_|nodekey:|[0-9a-f]{64}/);
    assert.match(c, /^sudo /);
  }
  assert.equal(installCommand("rack-7"), "sudo sh sentinel-worker-bootstrap.sh install --name rack-7 --secret-file /root/enrollment");
  for (const bad of ["", " ", "a b", "x;rm -rf /", "$(id)", "-rf", "../x", "a".repeat(64), "wörker", "a\nb"]) {
    assert.equal(workerName(bad), "build-1", JSON.stringify(bad));
    assert.ok(!installCommand(bad).includes(bad.trim()) || bad.trim() === "");
  }
  assert.equal(workerName("  build_2.eu-1 "), "build_2.eu-1");
});

test("a digest is verified only when it was computed and every stated digest agrees", async () => {
  const bytes = new TextEncoder().encode("#!/bin/sh\necho hi\n");
  const computed = await sha256Hex(bytes.buffer);
  assert.match(computed, /^[0-9a-f]{64}$/);
  // The FIPS 180-2 test vector for "abc".
  assert.equal(await sha256Hex(new TextEncoder().encode("abc").buffer), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(digestVerdict(computed, [computed, computed]), "verified");
  assert.equal(digestVerdict(computed, [computed, null]), "verified");
  assert.equal(digestVerdict(computed, [computed, HEX]), "mismatch");
  assert.equal(digestVerdict(computed, [HEX]), "mismatch");
  assert.equal(digestVerdict(computed, [null, undefined, ""]), "mismatch");
  assert.equal(digestVerdict(computed, []), "mismatch");
  assert.equal(digestVerdict(null, [computed]), "unverified");
  assert.equal(digestVerdict(null, []), "unverified");
});

test("without Web Crypto the digest is unavailable rather than wrong", async () => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });
  try {
    assert.equal(await sha256Hex(new ArrayBuffer(4)), null);
  } finally {
    if (saved) Object.defineProperty(globalThis, "crypto", saved);
  }
});

test("the page prints only a digest the controller stated, never a null", () => {
  assert.equal(statedDigest([null, undefined, ""]), null);
  assert.equal(statedDigest([]), null);
  assert.equal(statedDigest([null, HEX]), HEX);
  assert.equal(statedDigest([HEX, "f".repeat(64)]), HEX);
});
