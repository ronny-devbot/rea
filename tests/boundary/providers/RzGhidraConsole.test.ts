import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import pino from "pino";
import { afterEach, describe, expect, it } from "vitest";

import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisTimeoutError,
} from "../../../src/domain/analysisErrorCore.js";
import {
  RzGhidraConsole,
  type RzGhidraConsoleConfig,
} from "../../../src/rizinghidra/RzGhidraConsole.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import {
  writeFakeRizin,
  type RzGhidraFakeOptions,
} from "./RzGhidraConsole.fixtures.js";

const REAL_RIZIN = join(homedir(), "reverse", "install", "bin", "rizin");
const realRizinAvailable = existsSync(REAL_RIZIN);

const logger = pino({ enabled: false });
const consoles: RzGhidraConsole[] = [];
const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

afterEach(async () => {
  for (const subject of consoles.splice(0)) {
    await subject.close().catch(() => undefined);
    // No zombies: every spawned rizin must be reaped by the time a test ends.
    expect(subject.observedExit()).not.toBeUndefined();
  }
});

const createConsole = (
  config: RzGhidraConsoleConfig,
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): RzGhidraConsole => new RzGhidraConsole(config, logger, environment);

const startConsole = async (
  directory: string,
  name: string,
  fakeOptions: RzGhidraFakeOptions = {},
  config: Partial<RzGhidraConsoleConfig> = {},
  environment: Readonly<NodeJS.ProcessEnv> = process.env,
): Promise<RzGhidraConsole> => {
  const fake = await writeFakeRizin(directory, name, fakeOptions);
  const subject = createConsole(
    { path: "/tmp/rz-ghidra-fake-target", ...config, rizinCommand: fake },
    environment,
  );
  const opened = await subject.open();
  if (!opened.ok) throw opened.error;
  // Track only successfully spawned consoles; spawn failures own no process.
  consoles.push(subject);
  return subject;
};

describe("RzGhidraConsole (fake rizin) — command framing", () => {
  it("waits for the init NUL and frames multi-KB responses", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const subject = await startConsole(directory, "fake-rizin");
    const echo = await subject.send("hello");
    expect(echo.ok).toBe(true);
    if (echo.ok) expect(echo.value).toBe("ECHO:hello\n");
    const big = await subject.send("big");
    expect(big.ok).toBe(true);
    if (big.ok) {
      expect(big.value.length).toBe(200_000);
      expect(big.value).toBe("x".repeat(200_000));
    }
  });

  it("queues concurrent sends strictly serially in call order", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const subject = await startConsole(directory, "fake-rizin");
    const order: string[] = [];
    const first = subject.send("SLOW").then((result) => {
      order.push("first");
      return result;
    });
    // Let the first command reach the fake before the second is sent.
    await sleep(150);
    const second = subject.send("second").then((result) => {
      order.push("second");
      return result;
    });
    const [firstResult, secondResult] = await Promise.all([first, second]);
    expect(firstResult.ok).toBe(true);
    expect(secondResult.ok).toBe(true);
    if (firstResult.ok && secondResult.ok) {
      expect(firstResult.value).toBe("slow-done\n");
      expect(secondResult.value).toBe("ECHO:second\n");
    }
    expect(order).toEqual(["first", "second"]);
  });

  it("times out a slow command and keeps the session broken", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const subject = await startConsole(directory, "fake-rizin");
    const timedOut = await subject.send("SLOW", { timeoutMs: 200 });
    expect(timedOut.ok).toBe(false);
    if (!timedOut.ok)
      expect(timedOut.error).toBeInstanceOf(AnalysisTimeoutError);
    const after = await subject.send("hello");
    expect(after.ok).toBe(false);
    if (!after.ok) expect(after.error).toBeInstanceOf(AnalysisTimeoutError);
  });

  it("surfaces a typed cancellation and keeps the session broken", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const subject = await startConsole(directory, "fake-rizin");
    const controller = new AbortController();
    const pending = subject.send("SLOW", { signal: controller.signal });
    await sleep(100);
    controller.abort();
    const cancelled = await pending;
    expect(cancelled.ok).toBe(false);
    if (!cancelled.ok)
      expect(cancelled.error).toBeInstanceOf(AnalysisCancelledError);
    const after = await subject.send("hello");
    expect(after.ok).toBe(false);
  });

  it("rejects a pending send with a typed error when rizin exits mid-command", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const subject = await startConsole(directory, "fake-rizin");
    const died = await subject.send("die");
    expect(died.ok).toBe(false);
    if (!died.ok)
      expect(died.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
    expect(subject.observedExit()).toMatchObject({ code: 7, signal: null });
  });

  it("reports a typed startup timeout when the init NUL never arrives", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const fake = await writeFakeRizin(directory, "fake-rizin", {
      noInitNul: true,
    });
    const subject = createConsole({
      path: "/tmp/rz-ghidra-fake-target",
      rizinCommand: fake,
      startupTimeoutMs: 200,
    });
    const opened = await subject.open();
    expect(opened.ok).toBe(false);
    if (!opened.ok) expect(opened.error).toBeInstanceOf(AnalysisTimeoutError);
    await subject.close();
  });
});

describe("RzGhidraConsole (fake rizin) — startup and shutdown", () => {
  it("resolves the rizin binary from REA_RIZIN_COMMAND when config omits it", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const fake = await writeFakeRizin(directory, "fake-rizin");
    const subject = createConsole(
      { path: "/tmp/rz-ghidra-fake-target" },
      { ...process.env, REA_RIZIN_COMMAND: fake },
    );
    const opened = await subject.open();
    expect(opened.ok).toBe(true);
    consoles.push(subject);
    const echo = await subject.send("env");
    expect(echo.ok).toBe(true);
    if (echo.ok) expect(echo.value).toBe("ECHO:env\n");
  });

  it("fails startup with a typed error when the rizin binary is missing", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const subject = createConsole({
      path: "/tmp/rz-ghidra-fake-target",
      rizinCommand: join(directory, "no-such-rizin"),
    });
    const opened = await subject.open();
    expect(opened.ok).toBe(false);
    if (!opened.ok)
      expect(opened.error).toBeInstanceOf(AnalysisCapabilityUnavailableError);
  });

  it("closes gracefully through q and caches the idempotent result", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const subject = await startConsole(directory, "fake-rizin");
    const closed = await subject.close();
    expect(closed.ok).toBe(true);
    if (closed.ok) expect(closed.value).toEqual({ target_state: "closed" });
    expect(subject.observedExit()).toMatchObject({ code: 0, signal: null });
    const again = await subject.close();
    expect(again).toEqual({ ok: true, value: { target_state: "closed" } });
  });

  it("falls back to SIGKILL when rizin ignores q and shares one close", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const subject = await startConsole(directory, "fake-rizin", {
      ignoreQuit: true,
    });
    const [first, second] = await Promise.all([
      subject.close(),
      subject.close(),
    ]);
    // Concurrent close calls share one attempt and one result.
    expect(first).toBe(second);
    expect(first.ok).toBe(true);
    if (first.ok) expect(first.value).toEqual({ target_state: "closed" });
    expect(subject.observedExit()).toMatchObject({ signal: "SIGKILL" });
  });

  it("retains the last 64 KiB of rizin stderr", async () => {
    const directory = await createTestTempDirectory("rea-rz-ghidra-");
    const subject = await startConsole(directory, "fake-rizin");
    const result = await subject.send("stderr");
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value).toBe("stderr-done\n");
    // The stdout frame can land before the stderr stream drains; wait for the
    // final stderr marker so the ring is fully populated before asserting.
    const deadline = Date.now() + 2_000;
    while (!subject.recentStderr().includes("stderr-tail")) {
      if (Date.now() > deadline)
        throw new Error("stderr tail marker did not arrive");
      await sleep(10);
    }
    const recent = subject.recentStderr();
    expect(recent).toBe("a".repeat(64 * 1024 - 12) + "stderr-tail\n");
  });
});

it.skipIf(!realRizinAvailable)(
  "drives the real rizin-ghidra console against /bin/ls",
  async () => {
    const subject = createConsole({
      path: "/bin/ls",
      rizinCommand: REAL_RIZIN,
    });
    const opened = await subject.open();
    if (!opened.ok) throw opened.error;
    consoles.push(subject);
    const health = await subject.healthCheck();
    expect(health.ok).toBe(true);
    if (health.ok) {
      expect(health.value.length).toBeGreaterThan(0);
      expect(health.value).toContain("x86:LE:64:default");
    }
    const info = await subject.send("iIj");
    expect(info.ok).toBe(true);
    if (info.ok) {
      const parsed = JSON.parse(info.value) as { bintype?: string };
      expect(parsed.bintype).toBe("elf");
    }
    const closed = await subject.close();
    expect(closed.ok).toBe(true);
  },
);
