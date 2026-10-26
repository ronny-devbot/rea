import { join } from "node:path";

import { expect, it as test, vi } from "vitest";

import type { DoctorHost } from "../../../../src/application/Doctor.js";
import { runDoctorOwned } from "../../../../src/application/Doctor.js";
import { AnalysisCancelledError } from "../../../../src/domain/analysisErrorCore.js";
import { OwnedFileHandle } from "../../../../src/filesystem/OwnedFileHandle.js";
import { createSystemDoctorHost } from "../../../../src/doctorRuntime.js";
import { STARTUP_OWNER_CLOSED } from "../../../../src/process/SharedStartupAttempt.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { fakeRizinCalls, writeFakeRizin } from "./fakeRizin.js";
import { inspectRzGhidraProviderOwned } from "./rzGhidraResourceScope.js";
import { supportsNodeVersion } from "../../../../src/domain/runtimeVersion.js";

const it = test.skipIf(process.platform === "win32");

it("reports an unconfigured rizin-ghidra as a missing optional engine", async () => {
  await expect(inspectRzGhidraProviderOwned({})).resolves.toMatchObject({
    id: "rizin-ghidra",
    configured: false,
    available: false,
    providerVersion: null,
    registrationEnvironment: {},
    checks: [
      {
        name: "installation",
        ok: false,
        code: "not_configured",
        classification: "missing_analysis_engine",
      },
    ],
  });
});

it("reports a configured but missing executable as config drift", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-doctor-missing-");
  await expect(
    inspectRzGhidraProviderOwned({ REA_RIZIN_COMMAND: join(root, "absent") }),
  ).resolves.toMatchObject({
    id: "rizin-ghidra",
    configured: true,
    available: false,
    providerVersion: null,
    checks: [
      {
        name: "installation",
        ok: false,
        code: "executable_missing",
        classification: "config_drift",
      },
    ],
  });
});

it("reports a missing plugin without failing the installation discovery", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-doctor-plugin-");
  const rizin = await writeFakeRizin(root, { plugin: "missing" });

  await expect(
    inspectRzGhidraProviderOwned({ REA_RIZIN_COMMAND: rizin }),
  ).resolves.toMatchObject({
    id: "rizin-ghidra",
    configured: true,
    available: false,
    providerVersion: null,
    checks: [{ name: "installation", ok: false, code: "plugin_missing" }],
  });
});

it("publishes the caller's explicit settings once the installation validates", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-doctor-settings-");
  const rizin = await writeFakeRizin(root);

  const inspection = await inspectRzGhidraProviderOwned({
    REA_RIZIN_COMMAND: rizin,
    REA_RIZIN_ANALYSIS_TIMEOUT_MS: "60000",
    REA_RIZIN_FRAME_TIMEOUT_MS: "5000",
    UNRELATED: "not published",
  });

  expect(inspection).toMatchObject({
    configured: true,
    available: true,
    providerVersion: "0.9.1",
    registrationEnvironment: {
      REA_RIZIN_COMMAND: rizin,
      REA_RIZIN_ANALYSIS_TIMEOUT_MS: "60000",
      REA_RIZIN_FRAME_TIMEOUT_MS: "5000",
    },
    checks: [
      {
        name: "installation",
        ok: true,
        details: { executable: rizin, script: true, bytes: expect.any(Number) },
      },
      {
        name: "version",
        ok: true,
        details: {
          version: "0.9.1",
          verified_release: true,
          verified_version: "0.9.1",
        },
      },
      { name: "rz-ghidra-plugin", ok: true, details: { pdg_listed: true } },
    ],
  });
  expect(Object.keys(inspection.registrationEnvironment)).toHaveLength(3);
});

it("flags an unverified release without failing the installation", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-doctor-version-");
  const rizin = await writeFakeRizin(root, {
    version: { stdout: "rizin 0.9.2 @ linux-x86-64\n" },
  });

  const inspection = await inspectRzGhidraProviderOwned({
    REA_RIZIN_COMMAND: rizin,
  });
  expect(inspection).toMatchObject({
    available: true,
    providerVersion: "0.9.2",
  });
  // toMatchObject compares arrays positionally, so pin the one check by name.
  const versionCheck = inspection.checks.find(
    (check) => check.name === "version",
  );
  expect(versionCheck).toMatchObject({
    ok: true,
    detail: expect.stringContaining("unverified"),
    details: {
      verified_release: false,
      verified_version: "0.9.1",
      version: "0.9.2",
    },
  });
  // Every other installation probe still succeeds.
  expect(inspection.checks.filter((check) => check.name !== "version")).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ name: "installation", ok: true }),
      expect.objectContaining({ name: "rz-ghidra-plugin", ok: true }),
    ]),
  );
});

const doctorEnvironment = (root: string, rizin: string): NodeJS.ProcessEnv => ({
  HOME: root,
  PATH: "",
  JAVA_HOME: join(root, "missing-jdk"),
  GHIDRA_INSTALL_DIR: join(root, "missing-ghidra"),
  HOPPER_LAUNCHER_PATH: join(root, "missing-hopper"),
  REA_RIZIN_COMMAND: rizin,
});

// Exercise the production composition, not just the provider's helper: both
// the caller signal and the host's own close signal must reach the probe.
it.each(["caller", "host"] as const)(
  "cancels the composed rizin-ghidra doctor probe on %s cancellation",
  async (source) => {
    const root = await createTestTempDirectory("rea-rz-ghidra-doctor-cancel-");
    const gate = join(root, "release-version");
    const rizin = await writeFakeRizin(root, {
      version: { stdout: "rizin 0.9.1 @ linux-x86-64\n", gate },
    });
    const controller = new AbortController();
    const reason = { request: "cancel rizin-ghidra doctor" };
    const host = createSystemDoctorHost(
      doctorEnvironment(root, rizin),
      controller.signal,
    );
    let settled = false;
    const inspection = host.providerInspections!().then(
      () => {
        settled = true;
        return undefined;
      },
      (cause: unknown) => {
        settled = true;
        return cause;
      },
    );
    let closing: ReturnType<NonNullable<DoctorHost["close"]>> | undefined;
    try {
      await expect
        .poll(async () => (await fakeRizinCalls(rizin)).length, {
          timeout: 10_000,
        })
        .toBe(1);
      const probe = (await fakeRizinCalls(rizin))[0];
      if (probe === undefined) throw new Error("Missing rizin version probe");
      expect(probe.argv).toEqual(["-v"]);
      if (source === "caller") controller.abort(reason);
      else closing = host.close!();
      await expect.poll(() => settled, { timeout: 5_000 }).toBe(true);
      const failure = await inspection;
      expect(failure).toBeInstanceOf(AnalysisCancelledError);
      if (!(failure instanceof AnalysisCancelledError))
        throw new Error("Expected rizin-ghidra inspection cancellation");
      expect(failure.operation).toBe("doctor");
      expect(failure.cause).toBe(
        source === "caller" ? reason : STARTUP_OWNER_CLOSED,
      );
      expect(() => process.kill(probe.pid, 0)).toThrowError(
        expect.objectContaining({ code: "ESRCH" }),
      );
      await closing;
      expect(await fakeRizinCalls(rizin)).toHaveLength(1);
    } finally {
      await import("node:fs/promises").then(({ writeFile }) =>
        writeFile(gate, "release"),
      );
      await inspection;
      await closing;
      await host.close!();
    }
  },
  30_000,
);

it("does not launch the composed rizin-ghidra probe for an already cancelled caller", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-doctor-preabort-");
  const rizin = await writeFakeRizin(root);
  const controller = new AbortController();
  controller.abort({ request: "cancel before inspection" });
  const host = createSystemDoctorHost(
    doctorEnvironment(root, rizin),
    controller.signal,
  );
  try {
    await expect(host.providerInspections!()).rejects.toBeDefined();
    expect(await fakeRizinCalls(rizin)).toEqual([]);
  } finally {
    await host.close!();
  }
});

it("projects a healthy rizin-ghidra installation through the doctor workflow", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-doctor-workflow-");
  const rizin = await writeFakeRizin(root);
  const host = createSystemDoctorHost(
    doctorEnvironment(root, rizin),
    new AbortController().signal,
  );
  try {
    const report = await runDoctorOwned(undefined, host, {
      providers: ["rizin-ghidra"],
      skill: false,
      clients: [],
    });
    expect(report.providerInspections).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: "rizin-ghidra",
          available: true,
          providerVersion: "0.9.1",
          checks: expect.arrayContaining([
            expect.objectContaining({ name: "installation", ok: true }),
          ]),
        }),
      ]),
    );
  } finally {
    await host.close!();
  }
});

it("reports a cleanup_incomplete installation when the executable file close fails", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-doctor-cleanup-");
  const rizin = await writeFakeRizin(root);
  const nativeClose = OwnedFileHandle.prototype.close;
  let failing = true;
  const closeSpy = vi
    .spyOn(OwnedFileHandle.prototype, "close")
    .mockImplementation(async function (this: OwnedFileHandle) {
      if (failing) {
        failing = false;
        throw new Error("injected rizin-ghidra file close failure");
      }
      return nativeClose.call(this);
    });
  try {
    const inspection = await inspectRzGhidraProviderOwned({
      REA_RIZIN_COMMAND: rizin,
    });
    expect(inspection).toMatchObject({
      id: "rizin-ghidra",
      configured: true,
      available: false,
      providerVersion: null,
      checks: [
        {
          name: "installation",
          ok: false,
          code: "cleanup_incomplete",
          classification: "config_drift",
          details: { cleanup_incomplete: true },
        },
      ],
    });
    closeSpy.mockRestore();
  } finally {
    closeSpy.mockRestore();
  }
});
