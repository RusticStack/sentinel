/**
 * Host system metrics via Deno.Command (Linux).
 * On Windows / non-Linux, collectors degrade gracefully (null fields).
 */
import { githubOrg, runnerCount } from "./env.ts";
import type { MetricSample } from "./metric_series.ts";

export type MemoryMetrics = {
  totalMb: number;
  usedMb: number;
  availableMb: number;
};

export type DiskMetrics = {
  filesystem: string;
  size: string;
  used: string;
  available: string;
  usePercent: number;
  mount: string;
};

export type LoadMetrics = {
  load1: number;
  load5: number;
  load15: number;
};

export type CpuMetrics = {
  cores: number | null;
  model: string | null;
};

export type ServiceStatus = {
  unit: string;
  activeState: string | null;
  subState: string | null;
  mainPid: number | null;
  memoryCurrentBytes: number | null;
  available: boolean;
  error?: string;
};

export type SystemMetrics = {
  platform: string;
  available: boolean;
  memory: MemoryMetrics | null;
  disk: DiskMetrics | null;
  load: LoadMetrics | null;
  uptime: string | null;
  cpu: CpuMetrics | null;
  expectedRunners: number;
  error?: string;
};

/** System metrics plus optional KV-backed sparkline history. */
export type SystemMetricsPayload = SystemMetrics & {
  history?: MetricSample[];
};

const decoder = new TextDecoder();

/** True when we expect Linux host metrics (production target). */
export function isLinuxHost(os = Deno.build.os): boolean {
  return os === "linux";
}

/**
 * GitHub Actions default systemd unit:
 * `actions.runner.{org}.{runnerName}.service`
 */
export function runnerServiceUnit(
  runnerName: string,
  org = githubOrg(),
): string {
  return `actions.runner.${org}.${runnerName}.service`;
}

export async function runCommand(
  cmd: string,
  args: string[] = [],
): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  try {
    const command = new Deno.Command(cmd, {
      args,
      stdout: "piped",
      stderr: "piped",
    });
    const { code, stdout, stderr, success } = await command.output();
    return {
      ok: success,
      code,
      stdout: decoder.decode(stdout),
      stderr: decoder.decode(stderr),
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, code: -1, stdout: "", stderr: message };
  }
}

/** Parse `free -m` (prefer Mem: line). */
export function parseFreeM(output: string): MemoryMetrics | null {
  const lines = output.split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(
      /^Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/,
    );
    if (m) {
      return {
        totalMb: Number(m[1]),
        usedMb: Number(m[2]),
        availableMb: Number(m[6]),
      };
    }
  }
  return null;
}

/** Parse `df -h /` (skip header; take first data row). */
export function parseDfH(output: string): DiskMetrics | null {
  const lines = output.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return null;
  // Filesystem Size Used Avail Use% Mounted on
  const parts = lines[1]!.trim().split(/\s+/);
  if (parts.length < 6) return null;
  const useRaw = parts[4]!.replace(/%$/, "");
  const usePercent = Number.parseInt(useRaw, 10);
  return {
    filesystem: parts[0]!,
    size: parts[1]!,
    used: parts[2]!,
    available: parts[3]!,
    usePercent: Number.isFinite(usePercent) ? usePercent : 0,
    mount: parts.slice(5).join(" ") || "/",
  };
}

/** Parse `/proc/loadavg` (`0.12 0.34 0.56 1/234 5678`). */
export function parseLoadavg(output: string): LoadMetrics | null {
  const parts = output.trim().split(/\s+/);
  if (parts.length < 3) return null;
  const load1 = Number(parts[0]);
  const load5 = Number(parts[1]);
  const load15 = Number(parts[2]);
  if (![load1, load5, load15].every(Number.isFinite)) return null;
  return { load1, load5, load15 };
}

/** Parse `uptime -p` (`up 2 weeks, 3 days, 4 hours`). */
export function parseUptimeP(output: string): string | null {
  const text = output.trim();
  return text.length > 0 ? text : null;
}

/** Parse `nproc` stdout. */
export function parseNproc(output: string): number | null {
  const n = Number.parseInt(output.trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

/** Parse `lscpu` for Model name. */
export function parseLscpuModel(output: string): string | null {
  for (const line of output.split(/\r?\n/)) {
    const m = line.match(/^Model name:\s*(.+)\s*$/i);
    if (m?.[1]) return m[1].trim();
  }
  return null;
}

/** Parse `systemctl show` Key=Value lines. */
export function parseSystemctlShow(output: string): {
  activeState: string | null;
  subState: string | null;
  mainPid: number | null;
  memoryCurrentBytes: number | null;
} {
  const map = new Map<string, string>();
  for (const line of output.split(/\r?\n/)) {
    const idx = line.indexOf("=");
    if (idx <= 0) continue;
    map.set(line.slice(0, idx), line.slice(idx + 1));
  }
  const pidRaw = map.get("MainPID");
  const memRaw = map.get("MemoryCurrent");
  const mainPid = pidRaw != null ? Number.parseInt(pidRaw, 10) : NaN;
  const memoryCurrentBytes = memRaw != null && memRaw !== "[not set]"
    ? Number.parseInt(memRaw, 10)
    : NaN;
  return {
    activeState: map.get("ActiveState") ?? null,
    subState: map.get("SubState") ?? null,
    mainPid: Number.isFinite(mainPid) && mainPid > 0 ? mainPid : null,
    memoryCurrentBytes: Number.isFinite(memoryCurrentBytes)
      ? memoryCurrentBytes
      : null,
  };
}

async function readProcLoadavg(): Promise<string | null> {
  try {
    return await Deno.readTextFile("/proc/loadavg");
  } catch {
    return null;
  }
}

export async function getServiceStatus(
  unit: string,
): Promise<ServiceStatus> {
  if (!isLinuxHost()) {
    return {
      unit,
      activeState: null,
      subState: null,
      mainPid: null,
      memoryCurrentBytes: null,
      available: false,
      error: "systemd status requires Linux",
    };
  }

  const result = await runCommand("systemctl", [
    "show",
    unit,
    "--property=ActiveState,SubState,MainPID,MemoryCurrent",
    "--no-pager",
  ]);

  if (!result.ok) {
    return {
      unit,
      activeState: null,
      subState: null,
      mainPid: null,
      memoryCurrentBytes: null,
      available: false,
      error: result.stderr.trim() || `systemctl failed (${result.code})`,
    };
  }

  const parsed = parseSystemctlShow(result.stdout);
  return {
    unit,
    ...parsed,
    available: true,
  };
}

export async function getSystemMetrics(): Promise<SystemMetrics> {
  const expectedRunners = runnerCount();
  const platform = Deno.build.os;

  if (!isLinuxHost()) {
    return {
      platform,
      available: false,
      memory: null,
      disk: null,
      load: null,
      uptime: null,
      cpu: null,
      expectedRunners,
      error: "Host metrics require Linux (graceful degrade on this OS)",
    };
  }

  const [freeRes, dfRes, uptimeRes, nprocRes, lscpuRes, loadRaw] = await Promise
    .all([
      runCommand("free", ["-m"]),
      runCommand("df", ["-h", "/"]),
      runCommand("uptime", ["-p"]),
      runCommand("nproc"),
      runCommand("lscpu"),
      readProcLoadavg(),
    ]);

  const memory = freeRes.ok ? parseFreeM(freeRes.stdout) : null;
  const disk = dfRes.ok ? parseDfH(dfRes.stdout) : null;
  const uptime = uptimeRes.ok ? parseUptimeP(uptimeRes.stdout) : null;
  const cores = nprocRes.ok ? parseNproc(nprocRes.stdout) : null;
  const model = lscpuRes.ok ? parseLscpuModel(lscpuRes.stdout) : null;
  const load = loadRaw ? parseLoadavg(loadRaw) : null;

  const anyOk = memory != null || disk != null || load != null ||
    uptime != null || cores != null || model != null;

  return {
    platform,
    available: anyOk,
    memory,
    disk,
    load,
    uptime,
    cpu: { cores, model },
    expectedRunners,
    error: anyOk ? undefined : "Failed to collect host metrics",
  };
}
