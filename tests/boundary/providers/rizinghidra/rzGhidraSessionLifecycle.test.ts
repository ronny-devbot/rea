import { expect, it as test } from "vitest";

import type { RzGhidraSessionClient } from "../../../../src/rizinghidra/RzGhidraSessionClient.js";
import { ProviderCleanupError } from "../../../../src/domain/providerCleanupError.js";
import { fakeRizinStdin } from "./fakeRizin.js";
import { interactiveCalls, run, session } from "./rzGhidraSessionFixture.js";

const it = test.skipIf(process.platform === "win32");

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const assertProcessGone = (pid: number | undefined): void => {
  if (pid === undefined) throw new Error("No fake rizin pid recorded");
  expect(() => process.kill(pid, 0)).toThrow();
};

it.each([false, true])(
  "close() drains an in-flight command before reporting itself closed (caller signal: %s)",
  async (withCallerSignal) => {
    const fixture = await session("rea-rz-ghidra-lc-drain-", { pdgj: "hang" });
    const client = fixture.open() as RzGhidraSessionClient;
    const caller = new AbortController();
    let request:
      | Promise<Awaited<ReturnType<RzGhidraSessionClient["execute"]>>>
      | undefined;
    try {
      request = client.execute(
        "procedure_pseudo_code",
        { procedure: "main" },
        withCallerSignal ? { signal: caller.signal } : {},
      );
      await expect
        .poll(async () => await fakeRizinStdin(fixture.rizin), {
          timeout: 5_000,
        })
        .toEqual(expect.arrayContaining(["pdgj"]));
      expect(await client.close()).toEqual({ ok: true, value: null });
      const consoles = await interactiveCalls(fixture.rizin);
      expect(consoles).toHaveLength(1);
      assertProcessGone(consoles[0]?.pid);
      const result = await request;
      expect(result).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisCancelledError" },
      });
      // A second execute after a successful close is refused.
      expect(await client.execute("list_procedures", {})).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisCapabilityUnavailableError",
          userMessage: "This rizin-ghidra session is closed.",
        },
      });
      // Double close is idempotent.
      expect(await client.close()).toEqual({ ok: true, value: null });
    } finally {
      caller.abort();
      await request;
      await client.close();
    }
  },
  30_000,
);

it("falls back to SIGKILL when rizin ignores q, then refuses further work", async () => {
  const fixture = await session("rea-rz-ghidra-lc-ignore-q-", { q: "ignore" });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect((await run(client, "list_procedures")).result).not.toHaveLength(0);
    const started = Date.now();
    expect(await client.close()).toEqual({ ok: true, value: null });
    // The graceful q grace window (3 s) elapsed before the kill.
    expect(Date.now() - started).toBeGreaterThanOrEqual(2_500);
    const consoles = await interactiveCalls(fixture.rizin);
    expect(consoles).toHaveLength(1);
    assertProcessGone(consoles[0]?.pid);
    expect(await client.execute("list_procedures", {})).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCapabilityUnavailableError" },
    });
  } finally {
    await client.close();
  }
}, 30_000);

it("reports unproven close cleanup and retries it on a later close", async () => {
  const fixture = await session("rea-rz-ghidra-lc-unproven-close-", {
    q: "ignore",
    quitHoldoutMs: 6_000,
  });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect((await run(client, "list_procedures")).result).not.toHaveLength(0);

    const first = await client.close();
    expect(first).toMatchObject({
      ok: false,
      error: {
        _tag: "ProviderAdapterError",
        cleanupIncomplete: true,
        diagnostics: {
          reason: expect.stringContaining("output streams did not settle"),
        },
      },
    });
    if (!first.ok) expect(first.error).toBeInstanceOf(ProviderCleanupError);
    // A retry while the holdout still owns the pipe fails the same way.
    expect((await client.close()).ok).toBe(false);

    // Wait for the grandchild holding the stdout pipe to exit.
    await expect
      .poll(
        async () =>
          (await fakeRizinStdin(fixture.rizin)).some((line) =>
            line.startsWith("__holdout__:"),
          ),
        { timeout: 15_000 },
      )
      .toBe(true);
    const holdout = (await fakeRizinStdin(fixture.rizin)).find((line) =>
      line.startsWith("__holdout__:"),
    );
    const until = Number(holdout?.slice("__holdout__:".length) ?? 0);
    while (Date.now() < until + 300) await sleep(50);

    expect(await client.close()).toEqual({ ok: true, value: null });
    expect(await client.close()).toEqual({ ok: true, value: null });
  } finally {
    await client.close();
  }
}, 45_000);

it("operationHealthSnapshot reports busy while a command is in flight and idle after", async () => {
  const fixture = await session("rea-rz-ghidra-lc-health-snapshot-", {
    slow: [{ command: "pdgj", ms: 600 }],
  });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(client.operationHealthSnapshot()).toMatchObject({ state: "idle" });
    const pending = client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    await expect
      .poll(async () => await fakeRizinStdin(fixture.rizin), { timeout: 5_000 })
      .toEqual(expect.arrayContaining(["pdgj"]));
    expect(client.operationHealthSnapshot()).toMatchObject({ state: "busy" });
    expect((await run(client, "list_procedures")).result).not.toHaveLength(0);
    expect(await pending).toMatchObject({ ok: true });
    await sleep(50);
    expect(client.operationHealthSnapshot()).toMatchObject({ state: "idle" });
  } finally {
    await client.close();
  }
}, 30_000);

it("a caller cancellation of one operation leaves the session usable via a respawned console", async () => {
  const fixture = await session("rea-rz-ghidra-lc-caller-cancel-", {
    slow: [{ command: "aflj", ms: 500 }],
  });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const caller = new AbortController();
    const cancelled = client.execute(
      "list_procedures",
      {},
      { signal: caller.signal },
    );
    await expect
      .poll(async () => await fakeRizinStdin(fixture.rizin), { timeout: 5_000 })
      .toEqual(expect.arrayContaining(["aflj"]));
    caller.abort();
    expect(await cancelled).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
    // The console is one-shot: the next operation respawns it and re-analyzes.
    const recovery = await run(client, "list_procedures");
    expect(recovery.result).not.toHaveLength(0);
    const consoles = await interactiveCalls(fixture.rizin);
    expect(consoles).toHaveLength(2);
    expect(consoles[0]?.pid).not.toBe(consoles[1]?.pid);
  } finally {
    await client.close();
  }
}, 30_000);
