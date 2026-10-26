import { createHash } from "node:crypto";
import {
  chmod,
  readFile,
  realpath,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { expect, it as test } from "vitest";

import type { ProcessCleanupResult } from "../../../../src/process/ProcessOwnership.js";
import { spawnOwnedProviderProcess } from "../../../../src/process/ProviderProcess.js";
import { readRzGhidraConfiguration } from "../../../../src/rizinghidra/RzGhidraConfiguration.js";
import {
  inspectRzGhidraInstallation,
  rzGhidraInstallationCancellation,
  rzGhidraChildEnvironment,
  type RzGhidraProcessLauncher,
} from "../../../../src/rizinghidra/RzGhidraInstallation.js";
import { RegularFileOperationCancelled } from "../../../../src/filesystem/RegularFile.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { fakeRizinCalls, writeFakeRizin } from "./fakeRizin.js";
import { inspectRzGhidraInstallationOwned } from "./rzGhidraResourceScope.js";

const it = test.skipIf(process.platform === "win32");

it("identifies a caller-selected rizin by version, digest and plugin", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-install-");
  const rizin = await writeFakeRizin(root);
  const link = join(root, "current-rizin");
  await symlink(rizin, link);

  const result = await inspectRzGhidraInstallationOwned({
    REA_RIZIN_COMMAND: link,
  });

  expect(result).toMatchObject({
    ok: true,
    value: {
      configuration: {
        command: link,
        analysisTimeoutMs: 600_000,
        frameTimeoutMs: 120_000,
      },
      executable: await realpath(rizin),
      version: "0.9.1",
      verified: true,
      // A `#!` launcher reports its interpreter; ownership checks must not expect the path.
      script: true,
      plugin: true,
      sha256: createHash("sha256")
        .update(await readFile(rizin))
        .digest("hex"),
    },
  });
  const calls = await fakeRizinCalls(rizin);
  expect(calls.map(({ argv }) => argv)).toEqual([
    ["-v"],
    ["-q", "-e", "scr.color=off", "-c", "pd?"],
  ]);
  // The probe runs with the private child environment and no inherited PATH.
  expect(
    calls.every(
      ({ home, noColor, path }) =>
        home === join(tmpdir(), "rea-rizin-ghidra") &&
        noColor === "1" &&
        path === null,
    ),
  ).toBe(true);
  const configuration = result.ok
    ? result.value.configuration
    : { command: "x", analysisTimeoutMs: 1, frameTimeoutMs: 1 };
  expect(rzGhidraChildEnvironment(configuration)).toEqual({
    HOME: join(tmpdir(), "rea-rizin-ghidra"),
    NO_COLOR: "1",
  });
});

it("accepts another release but reports it as unverified", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-unverified-");
  const rizin = await writeFakeRizin(root, {
    version: { stdout: "rizin 0.9.2 @ linux-x86-64\n" },
  });

  const result = await inspectRzGhidraInstallationOwned({
    REA_RIZIN_COMMAND: rizin,
  });
  expect(result).toMatchObject({
    ok: true,
    value: { version: "0.9.2", verified: false },
  });
});

it("refuses a version line it cannot recognize", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-garbled-");
  const rizin = await writeFakeRizin(root, {
    version: { stdout: "Rizin is a cool tool\n" },
  });

  await expect(
    inspectRzGhidraInstallationOwned({ REA_RIZIN_COMMAND: rizin }),
  ).resolves.toMatchObject({
    ok: false,
    error: {
      code: "version_unresolved",
      diagnostics: { stdout: "Rizin is a cool tool\n" },
    },
  });
});

it("reports a failed version probe with its exit status", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-probe-exit-");
  const rizin = await writeFakeRizin(root, { version: { exit: 3 } });

  await expect(
    inspectRzGhidraInstallationOwned({ REA_RIZIN_COMMAND: rizin }),
  ).resolves.toMatchObject({
    ok: false,
    error: {
      code: "version_unresolved",
      reason: expect.stringContaining("version probe failed"),
      diagnostics: { exit_code: 3, probe_failure_reason: "process" },
    },
  });
});

it("reports a plugin probe that lists no pdg decompiler", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-plugin-missing-");
  const rizin = await writeFakeRizin(root, { plugin: "missing" });

  await expect(
    inspectRzGhidraInstallationOwned({ REA_RIZIN_COMMAND: rizin }),
  ).resolves.toMatchObject({
    ok: false,
    error: {
      code: "plugin_missing",
      reason: expect.stringContaining("lists no pdg"),
      remediation: expect.stringContaining(
        "does not include the rz-ghidra plugin",
      ),
      diagnostics: { version: "0.9.1" },
    },
  });
});

it("reports a failed plugin probe with its exit status", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-plugin-exit-");
  const rizin = await writeFakeRizin(root, { plugin: "exit" });

  await expect(
    inspectRzGhidraInstallationOwned({ REA_RIZIN_COMMAND: rizin }),
  ).resolves.toMatchObject({
    ok: false,
    error: {
      code: "plugin_missing",
      diagnostics: { exit_code: 2, probe_failure_reason: "process" },
    },
  });
});

it("refuses a fingerprint that drifted between the pre-probe hash and the post-probe observation", async () => {
  const root = await createTestTempDirectory(
    "rea-rz-ghidra-mutated-during-probe-",
  );
  const rizin = await writeFakeRizin(root, {
    version: { append: "\n// mutated during the probe\n" },
  });
  const before = await readFile(rizin);

  const result = await inspectRzGhidraInstallationOwned({
    REA_RIZIN_COMMAND: rizin,
  });
  const after = await readFile(rizin);

  expect(createHash("sha256").update(after).digest("hex")).not.toBe(
    createHash("sha256").update(before).digest("hex"),
  );
  expect(result).toMatchObject({
    ok: false,
    error: {
      code: "fingerprint_mismatch",
      diagnostics: {
        installation_identity_changed: true,
        version: "0.9.1",
        before_sha256: createHash("sha256").update(before).digest("hex"),
        before_bytes: before.length,
        after_sha256: createHash("sha256").update(after).digest("hex"),
        after_bytes: after.length,
      },
    },
  });
});

it("reports a missing or non-executable command as executable_missing", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-missing-");
  const rizin = await writeFakeRizin(root);
  await chmod(rizin, 0o644);
  const directory = await createTestTempDirectory("rea-rz-ghidra-missing-dir-");

  for (const command of [rizin, join(root, "absent"), directory])
    await expect(
      inspectRzGhidraInstallationOwned({ REA_RIZIN_COMMAND: command }),
    ).resolves.toMatchObject({
      ok: false,
      error: { code: "executable_missing", diagnostics: { command } },
    });
});

it("distinguishes an unset command from an invalid one", async () => {
  await expect(inspectRzGhidraInstallationOwned({})).resolves.toMatchObject({
    ok: false,
    error: { code: "not_configured", diagnostics: { configured: false } },
  });
  await expect(
    inspectRzGhidraInstallationOwned({ REA_RIZIN_COMMAND: "bin/rizin" }),
  ).resolves.toMatchObject({
    ok: false,
    error: {
      code: "open_options_invalid",
      diagnostics: { configured: true, setting: "REA_RIZIN_COMMAND" },
    },
  });
});

it("declares Windows hosts unsupported before touching the command", async () => {
  await expect(
    inspectRzGhidraInstallationOwned(
      { REA_RIZIN_COMMAND: "/opt/rizin/rizin" },
      { platform: "win32" },
    ),
  ).resolves.toMatchObject({ ok: false, error: { code: "unsupported_host" } });
});

it("parses the timeout settings at the configuration boundary", () => {
  const environment = { REA_RIZIN_COMMAND: "/opt/rizin/rizin" };
  expect(readRzGhidraConfiguration(environment, "linux")).toMatchObject({
    ok: true,
    value: {
      command: "/opt/rizin/rizin",
      analysisTimeoutMs: 600_000,
      frameTimeoutMs: 120_000,
    },
  });
  expect(
    readRzGhidraConfiguration(
      {
        ...environment,
        REA_RIZIN_ANALYSIS_TIMEOUT_MS: "60000",
        REA_RIZIN_FRAME_TIMEOUT_MS: "5000",
      },
      "linux",
    ),
  ).toMatchObject({
    value: { analysisTimeoutMs: 60000, frameTimeoutMs: 5000 },
  });
  for (const [setting, value] of [
    ["REA_RIZIN_COMMAND", "relative/rizin"],
    ["REA_RIZIN_ANALYSIS_TIMEOUT_MS", "0"],
    ["REA_RIZIN_FRAME_TIMEOUT_MS", "-1"],
  ] as const)
    expect(
      readRzGhidraConfiguration(
        { REA_RIZIN_COMMAND: "/opt/rizin/rizin", [setting]: value },
        "linux",
      ),
    ).toMatchObject({
      ok: false,
      error: { code: "open_options_invalid", setting },
    });
  expect(readRzGhidraConfiguration(environment, "win32")).toMatchObject({
    ok: false,
    error: { code: "unsupported_host" },
  });
});

it("cancels a gated version probe in flight and joins the stopped process", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-cancel-probe-");
  const gate = join(root, "release-version");
  const rizin = await writeFakeRizin(root, {
    version: { stdout: "rizin 0.9.1 @ linux-x86-64\n", gate },
  });
  const controller = new AbortController();
  const reason = { request: "cancel mid-probe" };

  const pending = inspectRzGhidraInstallationOwned(
    { REA_RIZIN_COMMAND: rizin },
    { signal: controller.signal },
  ).then(
    (value) => ({ kind: "result" as const, value }),
    (cause: unknown) => ({ kind: "thrown" as const, cause }),
  );
  try {
    await expect
      .poll(async () => (await fakeRizinCalls(rizin)).length, {
        timeout: 10_000,
      })
      .toBe(1);
    const probe = (await fakeRizinCalls(rizin))[0];
    expect(probe?.argv).toEqual(["-v"]);
    controller.abort(reason);
    const outcome = await pending;
    expect(outcome.kind).toBe("thrown");
    const cause = outcome.kind === "thrown" ? outcome.cause : undefined;
    expect(cause).toBeInstanceOf(RegularFileOperationCancelled);
    expect(rzGhidraInstallationCancellation(cause)?.reason).toBe(reason);
    expect(() => process.kill(probe?.pid ?? 0, 0)).toThrowError(
      expect.objectContaining({ code: "ESRCH" }),
    );
  } finally {
    await writeFile(gate, "release");
    await pending;
  }
});

it("keeps a probe deadline ahead of the probe answer when the fake is gated", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-deadline-first-");
  const gate = join(root, "release-version");
  const rizin = await writeFakeRizin(root, {
    version: { stdout: "rizin 0.9.1 @ linux-x86-64\n", gate },
  });

  const result = await inspectRzGhidraInstallationOwned(
    { REA_RIZIN_COMMAND: rizin },
    { probeTimeoutMs: 500 },
  );
  await writeFile(gate, "release");

  expect(result).toMatchObject({
    ok: false,
    error: {
      code: "version_unresolved",
      diagnostics: { probe_failure_reason: "timeout", deadline_ms: 500 },
    },
  });
});

it("retains an unproven probe stop through the launcher seam", async () => {
  const root = await createTestTempDirectory(
    "rea-rz-ghidra-launcher-unproven-",
  );
  const rizin = await writeFakeRizin(root);
  let probeLaunches = 0;
  let cleanups = 0;
  const launcher: RzGhidraProcessLauncher = async (options) => {
    const spawned = await spawnOwnedProviderProcess(options);
    if (options.arguments[0] !== "-v") return spawned;
    probeLaunches += 1;
    return {
      ...spawned,
      cleanup: async (): Promise<ProcessCleanupResult> => {
        // The first stop is unproven; the fixture's scope close proves the retry.
        cleanups += 1;
        return cleanups === 1
          ? { cleaned: false, reason: "probe stop unproven" }
          : { cleaned: true, signaled: true };
      },
    };
  };

  const result = await inspectRzGhidraInstallationOwned(
    { REA_RIZIN_COMMAND: rizin },
    { processLauncher: launcher },
  );

  expect(probeLaunches).toBe(1);
  expect(cleanups).toBeGreaterThanOrEqual(1);
  expect(result).toMatchObject({
    ok: false,
    error: {
      code: "version_unresolved",
      diagnostics: {
        probe_failure_reason: "process",
        cleanup_incomplete: true,
      },
    },
  });
});
