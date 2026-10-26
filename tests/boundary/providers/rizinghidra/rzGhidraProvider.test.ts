import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { expect, it as test } from "vitest";

import { AnalysisProviderRegistry } from "../../../../src/application/binary/AnalysisProviderRegistry.js";
import { composeBinarySession } from "../../../../src/application/binary/BinarySessionComposition.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import { RzGhidraProvider } from "../../../../src/rizinghidra/RzGhidraProvider.js";
import { RIZIN_GHIDRA_PROVIDER_ID } from "../../../../src/rizinghidra/RzGhidraRelease.js";
import { RIZIN_GHIDRA_PROVIDER_IDENTITY } from "../../../../src/rizinghidra/RzGhidraProviderCapabilities.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  fakeRizinCalls,
  setFakeRizinBehavior,
  writeFakeRizin,
} from "./fakeRizin.js";
import { withRzGhidraResourceScope } from "./rzGhidraResourceScope.js";
import { session } from "./rzGhidraSessionFixture.js";

const it = test.skipIf(process.platform === "win32");

it("discovers configuration without probing and admits only verified targets", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-discovery-");
  const rizin = await writeFakeRizin(root);

  expect(new RzGhidraProvider({}).inspectAvailability()).toMatchObject({
    status: "unavailable",
    code: "not_configured",
    diagnostics: { configured: false, version_probed: false },
  });
  expect(
    new RzGhidraProvider({
      REA_RIZIN_COMMAND: join(root, "absent"),
    }).inspectAvailability(),
  ).toMatchObject({ status: "unavailable", code: "executable_missing" });
  expect(
    new RzGhidraProvider({
      REA_RIZIN_COMMAND: "bin/rizin",
    }).inspectAvailability(),
  ).toMatchObject({ status: "unavailable", code: "open_options_invalid" });
  expect(
    new RzGhidraProvider(
      { REA_RIZIN_COMMAND: rizin },
      { platform: "win32" },
    ).inspectAvailability(),
  ).toMatchObject({ status: "unavailable", code: "unsupported_host" });

  const configured = new RzGhidraProvider({ REA_RIZIN_COMMAND: rizin });
  expect(configured.inspectAvailability()).toMatchObject({
    status: "available",
    code: null,
    reason: null,
    diagnostics: { configured: true, command: rizin, version_probed: false },
  });
  // Discovery must not have launched the engine at all.
  expect(await fakeRizinCalls(rizin)).toEqual([]);
  expect(configured.identity()).toEqual(RIZIN_GHIDRA_PROVIDER_IDENTITY);
  const capabilities = configured.capabilities();
  expect(capabilities).toHaveLength(20);
  expect(
    capabilities.every(
      ({ available, reason, cachePolicy, effects }) =>
        available &&
        reason === null &&
        cachePolicy === "live" &&
        effects.launchesProcess,
    ),
  ).toBe(true);
  expect(
    capabilities
      .filter(({ effects }) => effects.mutatesArtifact)
      .map(({ operation }) => operation),
  ).toEqual(["set_address_name", "set_comment"]);

  const executable = (
    format: "elf" | "mach-o" | "pe" | "mach-o-universal" | "mach-o-universal-2",
    kind: "executable" | "archive" | "database",
  ) =>
    ({
      path: "/tmp/fixture",
      sha256: "a".repeat(64),
      kind,
      format,
      ...(kind === "executable"
        ? { architecture: "x86_64", availableArchitectures: ["x86_64"] }
        : {}),
    }) as unknown as BinaryTarget;
  expect(
    configured.inspectTargetSupport(executable("elf", "executable")).status,
  ).toBe("supported");
  expect(
    configured.inspectTargetSupport(executable("mach-o", "executable")).status,
  ).toBe("supported");
  // No architecture gate: Sleigh coverage is the engine's to report.
  expect(
    configured.inspectTargetSupport(executable("elf", "executable")).code,
  ).toBe(null);
  expect(
    configured.inspectTargetSupport(executable("pe", "executable")),
  ).toMatchObject({
    status: "unsupported",
    code: "target_format_unsupported",
    reason:
      "The rz-ghidra provider opens ELF and Mach-O images; pe is not admitted.",
  });
  expect(
    configured.inspectTargetSupport(
      executable("mach-o-universal", "executable"),
    ),
  ).toMatchObject({
    status: "unsupported",
    code: "target_format_unsupported",
    reason: expect.stringContaining("universal Mach-O slice"),
  });
  expect(
    configured.inspectTargetSupport(executable("elf", "archive")),
  ).toMatchObject({
    status: "unsupported",
    code: "target_kind_unsupported",
  });
});

it("commits the observed rizin release and digest to the analysis profile", async () => {
  const { rizin, profile } = await session("rea-rz-ghidra-profile-");

  expect(profile).toMatchObject({
    provider: { id: "rizin-ghidra", name: "rz-ghidra", version: "0.9.1" },
    parameters: {
      rz_version: "0.9.1",
      rz_sha256: createHash("sha256")
        .update(await readFile(rizin))
        .digest("hex"),
      verified_release: true,
      plugin: "rz-ghidra",
      cache_policy: "live",
    },
  });
});

it("reports an unverified rizin release in the profile without failing", async () => {
  const { profile } = await session("rea-rz-ghidra-unverified-profile-", {
    version: { stdout: "rizin 0.9.0 @ linux-x86-64\n" },
  });

  expect(profile).toMatchObject({
    provider: { version: "0.9.0" },
    parameters: { rz_version: "0.9.0", verified_release: false },
  });
});

it("refuses profile resolution without a durable resource scope", async () => {
  const { target, provider } = await session("rea-rz-ghidra-profile-noscope-");

  const result = await provider.resolveAnalysisProfile(target);
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisCapabilityUnavailableError",
      userMessage: expect.stringContaining("durable resource scope"),
    },
  });
});

it("returns a typed cancellation for an already aborted profile signal", async () => {
  const { target, provider } = await session("rea-rz-ghidra-profile-preabort-");
  const controller = new AbortController();
  const reason = { request: "cancel before probe" };
  controller.abort(reason);

  const result = await provider.resolveAnalysisProfile(target, {
    signal: controller.signal,
  });
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError", cause: reason },
  });
});

it("cancels a profile probe in flight and joins the stopped process", async () => {
  const { root, rizin, target, provider } = await session(
    "rea-rz-ghidra-profile-gate-",
  );
  const gate = join(root, "release-version");
  // The fixture already probed once; swap in a gated fake for a fresh spawn.
  await setFakeRizinBehavior(rizin, {
    version: { stdout: "rizin 0.9.1 @ linux-x86-64\n", gate },
  });
  const controller = new AbortController();
  const reason = { request: "cancel mid-probe" };

  const pending = withRzGhidraResourceScope((resourceScope) =>
    provider.resolveAnalysisProfile(target, {
      signal: controller.signal,
      resourceScope,
    }),
  ).then(
    (value) => ({ kind: "result" as const, value }),
    (cause: unknown) => ({ kind: "thrown" as const, cause }),
  );
  try {
    await expect
      .poll(async () => (await fakeRizinCalls(rizin)).length, {
        timeout: 10_000,
      })
      .toBeGreaterThanOrEqual(3); // profile probe + version probe of this attempt
    const probe = (await fakeRizinCalls(rizin)).at(-1);
    expect(probe?.argv).toEqual(["-v"]);
    controller.abort(reason);
    const outcome = await pending;
    expect(outcome.kind).toBe("result");
    if (outcome.kind === "result") {
      expect(outcome.value).toMatchObject({
        ok: false,
        error: {
          _tag: "AnalysisCancelledError",
          cause: reason,
          operation: "rizin-ghidra:profile",
        },
      });
    }
    expect(() => process.kill(probe?.pid ?? 0, 0)).toThrowError(
      expect.objectContaining({ code: "ESRCH" }),
    );
  } finally {
    await writeFile(gate, "release");
    await pending;
  }
});

it("keeps a healthy profile probe when the caller stays active", async () => {
  const { rizin, target, provider } = await session(
    "rea-rz-ghidra-profile-active-",
  );
  const controller = new AbortController();

  const result = await withRzGhidraResourceScope((resourceScope) =>
    provider.resolveAnalysisProfile(target, {
      signal: controller.signal,
      resourceScope,
    }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error("Profile unexpectedly failed");
  expect(result.value.profile).toMatchObject({
    provider: { id: "rizin-ghidra" },
  });
  // One version probe and one plugin probe per resolution.
  const calls = await fakeRizinCalls(rizin);
  expect(calls.filter(({ argv }) => argv[0] === "-v")).toHaveLength(2);
  expect(calls.filter(({ argv }) => argv[0] === "-q")).toHaveLength(2);
});

it("reports a missing plugin through profile resolution", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-profile-plugin-");
  const rizin = await writeFakeRizin(root, { plugin: "missing" });
  const target: BinaryTarget = {
    path: join(root, "program"),
    sha256: "a".repeat(64),
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
  };
  const provider = new RzGhidraProvider({ REA_RIZIN_COMMAND: rizin });

  const result = await provider.resolveAnalysisProfile(target, {
    resourceScope: {
      retain: () => {},
      run: <T>(operation: () => Promise<T>) => operation(),
    },
  });
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisCapabilityUnavailableError",
      userMessage: expect.stringContaining(
        "does not include the rz-ghidra plugin",
      ),
    },
  });
});

it("returns a stub client when unconfigured that stays closed on every operation", async () => {
  const root = await createTestTempDirectory("rea-rz-ghidra-stub-client-");
  const target: BinaryTarget = {
    path: join(root, "program"),
    sha256: "a".repeat(64),
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
  };
  const provider = new RzGhidraProvider({});
  const client = provider.createClient(target);

  for (const operation of [
    "health",
    "list_procedures",
    "procedure_pseudo_code",
  ] as const) {
    const result = await client.execute(operation, {});
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        userMessage: expect.stringContaining("Set REA_RIZIN_COMMAND"),
      },
    });
  }
  expect(await client.close()).toEqual({ ok: true, value: null });
});

it("registers in the provider registry and previews a target through a composed session", async () => {
  const { rizin, target, provider } = await session("rea-rz-ghidra-registry-");

  const registry = new AnalysisProviderRegistry([provider], "rizin-ghidra");
  const binary = composeBinarySession(registry);
  try {
    const preview = await binary.previewTarget(target, {
      providerId: RIZIN_GHIDRA_PROVIDER_ID,
    });
    expect(preview.ok).toBe(true);
    if (!preview.ok) throw new Error("Preview unexpectedly failed");
    expect(preview.value.route.profile).toMatchObject({
      provider: { id: "rizin-ghidra", version: "0.9.1" },
      parameters: { rz_version: "0.9.1", verified_release: true },
    });
    expect(await fakeRizinCalls(rizin)).not.toHaveLength(0);
  } finally {
    await binary.close();
  }
});
