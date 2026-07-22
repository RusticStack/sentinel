import { assertEquals } from "@std/assert";
import {
  isLinuxHost,
  parseDfH,
  parseFreeM,
  parseLoadavg,
  parseLscpuModel,
  parseNproc,
  parseSystemctlShow,
  parseUptimeP,
  runnerServiceUnit,
} from "./system.ts";

Deno.env.set("GH_ORG", "acme");

Deno.test("parseFreeM extracts Mem line", () => {
  const sample =
    `              total        used        free      shared  buff/cache   available
Mem:           7937        2145         312         180        5479        5244
Swap:          2047           0        2047
`;
  assertEquals(parseFreeM(sample), {
    totalMb: 7937,
    usedMb: 2145,
    availableMb: 5244,
  });
});

Deno.test("parseDfH extracts root filesystem row", () => {
  const sample = `Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        58G   12G   44G  22% /
`;
  assertEquals(parseDfH(sample), {
    filesystem: "/dev/sda1",
    size: "58G",
    used: "12G",
    available: "44G",
    usePercent: 22,
    mount: "/",
  });
});

Deno.test("parseLoadavg reads three averages", () => {
  assertEquals(parseLoadavg("0.15 0.10 0.05 1/234 5678\n"), {
    load1: 0.15,
    load5: 0.10,
    load15: 0.05,
  });
  assertEquals(parseLoadavg("bad"), null);
});

Deno.test("parseUptimeP trims output", () => {
  assertEquals(parseUptimeP("  up 2 weeks, 1 day  \n"), "up 2 weeks, 1 day");
  assertEquals(parseUptimeP("   "), null);
});

Deno.test("parseNproc and parseLscpuModel", () => {
  assertEquals(parseNproc("4\n"), 4);
  assertEquals(parseNproc("x"), null);
  assertEquals(
    parseLscpuModel("Architecture: aarch64\nModel name: Neoverse-N1\n"),
    "Neoverse-N1",
  );
});

Deno.test("parseSystemctlShow maps properties", () => {
  const sample = `ActiveState=active
SubState=running
MainPID=1234
MemoryCurrent=1048576
`;
  assertEquals(parseSystemctlShow(sample), {
    activeState: "active",
    subState: "running",
    mainPid: 1234,
    memoryCurrentBytes: 1048576,
  });
});

Deno.test("runnerServiceUnit follows Actions naming", () => {
  assertEquals(
    runnerServiceUnit("runner-1", "acme"),
    "actions.runner.acme.runner-1.service",
  );
});

Deno.test("isLinuxHost detects linux vs windows", () => {
  assertEquals(isLinuxHost("linux"), true);
  assertEquals(isLinuxHost("windows"), false);
});
