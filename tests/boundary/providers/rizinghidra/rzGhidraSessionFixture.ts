import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { AnalysisClient } from "../../../../src/application/AnalysisProvider.js";
import type { AnalysisProfileCommitment } from "../../../../src/domain/analysisProfile.js";
import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import type { JsonValue } from "../../../../src/domain/jsonValue.js";
import type { RzGhidraProcessLauncher } from "../../../../src/rizinghidra/RzGhidraInstallation.js";
import { RzGhidraProvider } from "../../../../src/rizinghidra/RzGhidraProvider.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { withRzGhidraResourceScope } from "./rzGhidraResourceScope.js";
import {
  fakeRizinCalls,
  fakeRizinStdin,
  writeFakeRizin,
  type FakeRizinBehavior,
} from "./fakeRizin.js";

export interface RzGhidraSessionFixture {
  readonly root: string;
  readonly rizin: string;
  readonly target: BinaryTarget;
  readonly provider: RzGhidraProvider;
  readonly profile: AnalysisProfileCommitment;
  open(): AnalysisClient;
}

/**
 * One rz-ghidra session over the fake rizin: temp dir, configured
 * REA_RIZIN_COMMAND, a target file, resolved profile and a client factory.
 */
export const session = async (
  prefix: string,
  behavior: FakeRizinBehavior = {},
  environment: Readonly<Record<string, string>> = {},
  launcher?: RzGhidraProcessLauncher,
): Promise<RzGhidraSessionFixture> => {
  const root = await createTestTempDirectory(prefix);
  const rizin = await writeFakeRizin(root, behavior);
  const targetPath = join(root, "program");
  const bytes = "program bytes";
  await writeFile(targetPath, bytes);
  const target: BinaryTarget = {
    path: targetPath,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
  };
  const provider = new RzGhidraProvider(
    { REA_RIZIN_COMMAND: rizin, ...environment },
    {
      platform: process.platform,
      ...(launcher === undefined ? {} : { launcher }),
    },
  );
  const profile = await withRzGhidraResourceScope((resourceScope) =>
    provider.resolveAnalysisProfile(target, { resourceScope }),
  );
  if (!profile.ok || profile.value.profile === null)
    throw new Error("profile did not resolve");
  const resolved = profile.value.profile;
  return {
    root,
    rizin,
    target,
    provider,
    profile: resolved,
    open: () => provider.createClient(target, resolved),
  };
};

export const run = async (
  client: AnalysisClient,
  operation: Parameters<AnalysisClient["execute"]>[0],
  parameters: Readonly<Record<string, JsonValue>> = {},
  signal?: AbortSignal,
) => {
  const result = await client.execute(
    operation,
    parameters,
    signal === undefined ? {} : { signal },
  );
  if (!result.ok) throw result.error;
  return result.value;
};

/** Interactive console processes the fake spawned, oldest first. */
export const interactiveCalls = async (rizin: string) =>
  (await fakeRizinCalls(rizin)).filter(({ argv }) => argv[0] === "-N");

export { fakeRizinCalls, fakeRizinStdin };
