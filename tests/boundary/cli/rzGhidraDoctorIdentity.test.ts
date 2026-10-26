import { createHash } from "node:crypto";
import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { expect } from "vitest";

import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { supportsNodeVersion } from "../../../src/domain/runtimeVersion.js";
import { cliTest } from "../../support/cli/cliFixture.js";
import {
  writeFakeRizin,
  type FakeRizinBehavior,
} from "../providers/rizinghidra/fakeRizin.js";

const pinnedEnvironment = (home: string, root: string): NodeJS.ProcessEnv => ({
  HOME: home,
  USERPROFILE: home,
  JAVA_HOME: join(root, "missing-jdk"),
  HOPPER_LAUNCHER_PATH: join(root, "missing-hopper"),
  GHIDRA_INSTALL_DIR: join(root, "missing-ghidra"),
});

cliTest
  .skipIf(process.platform === "win32")
  .for(["stable", "replaced"] as const)(
  "doctor binds rizin version output to a %s executable identity",
  async (identity, { cli }) => {
    const root = await createTestTempDirectory(
      "rea-rz-ghidra-doctor-identity-",
    );
    const home = join(root, "home");
    await mkdir(home);
    const behavior: FakeRizinBehavior =
      identity === "replaced"
        ? {
            version: {
              stdout: "rizin 0.9.1 @ linux-x86-64\n",
              append: "\n// mutated during the probe\n",
            },
          }
        : {};
    const executable = await writeFakeRizin(root, behavior);
    const before = await readFile(executable);
    const beforeHash = createHash("sha256").update(before).digest("hex");

    const result = await cli.run({
      arguments: ["doctor", "--provider", "rizin-ghidra", "--json"],
      environment: {
        ...pinnedEnvironment(home, root),
        REA_RIZIN_COMMAND: executable,
        REA_LOG_LEVEL: "silent",
      },
      timeoutMs: 30_000,
    });
    const after = await readFile(executable);
    const afterHash = createHash("sha256").update(after).digest("hex");

    if (identity === "stable") {
      expect(afterHash).toBe(beforeHash);
      // An explicit-scope doctor also gates on the core node check; on a
      // Node outside the supported range the report is otherwise complete.
      expect(result.exitCode, result.stderr).toBe(
        supportsNodeVersion(process.versions.node) ? 0 : 1,
      );
      expect(result.json).toMatchObject({
        providerInspections: expect.arrayContaining([
          expect.objectContaining({
            id: "rizin-ghidra",
            configured: true,
            available: true,
            providerVersion: "0.9.1",
            registrationEnvironment: expect.objectContaining({
              REA_RIZIN_COMMAND: executable,
            }),
            checks: expect.arrayContaining([
              expect.objectContaining({ name: "installation", ok: true }),
              expect.objectContaining({
                name: "version",
                ok: true,
                // toMatchObject only partial-matches nested objects while they
                // stay wrapped in objectContaining.
                details: expect.objectContaining({
                  verified_release: true,
                  verified_version: "0.9.1",
                }),
              }),
              expect.objectContaining({ name: "rz-ghidra-plugin", ok: true }),
            ]),
          }),
        ]),
      });
    } else {
      expect(afterHash).not.toBe(beforeHash);
      expect(result.exitCode, result.stderr).toBe(1);
      expect(result.json).toMatchObject({
        providerInspections: expect.arrayContaining([
          expect.objectContaining({
            id: "rizin-ghidra",
            configured: true,
            available: false,
            providerVersion: null,
            checks: expect.arrayContaining([
              expect.objectContaining({
                name: "installation",
                ok: false,
                code: "fingerprint_mismatch",
                details: expect.objectContaining({
                  installation_identity_changed: true,
                  version: "0.9.1",
                  before_sha256: beforeHash,
                  before_bytes: before.length,
                  after_sha256: afterHash,
                  after_bytes: after.length,
                }),
              }),
            ]),
          }),
        ]),
      });
    }
  },
);

cliTest.skipIf(process.platform === "win32").for(["unconfigured"] as const)(
  "doctor reports an unconfigured rizin-ghidra provider through the CLI",
  async (_identity, { cli }) => {
    const root = await createTestTempDirectory(
      "rea-rz-ghidra-doctor-unconfigured-",
    );
    const home = join(root, "home");
    await mkdir(home);

    const result = await cli.run({
      arguments: ["doctor", "--provider", "rizin-ghidra", "--json"],
      environment: {
        ...pinnedEnvironment(home, root),
        REA_LOG_LEVEL: "silent",
      },
      timeoutMs: 30_000,
    });

    expect(result.exitCode, result.stderr).toBe(1);
    expect(result.json).toMatchObject({
      providerInspections: expect.arrayContaining([
        expect.objectContaining({
          id: "rizin-ghidra",
          configured: false,
          available: false,
          providerVersion: null,
          checks: expect.arrayContaining([
            expect.objectContaining({
              name: "installation",
              ok: false,
              code: "not_configured",
            }),
          ]),
        }),
      ]),
    });
  },
);
