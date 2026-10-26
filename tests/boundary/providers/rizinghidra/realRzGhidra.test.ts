import { accessSync, constants, existsSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { expect, test } from "vitest";

import type { BinaryTarget } from "../../../../src/domain/binaryTargetTypes.js";
import { RzGhidraProvider } from "../../../../src/rizinghidra/RzGhidraProvider.js";
import { run } from "./rzGhidraSessionFixture.js";
import { withRzGhidraResourceScope } from "./rzGhidraResourceScope.js";

/** Same gating idiom as the console test: presence of the known rizin build. */
const REAL_RIZIN =
  process.env.REA_RIZIN_COMMAND ??
  join(homedir(), "reverse", "install", "bin", "rizin");
let realRizinAvailable = false;
try {
  if (existsSync(REAL_RIZIN) && statSync(REAL_RIZIN).isFile())
    accessSync(REAL_RIZIN, constants.X_OK);
  realRizinAvailable = true;
} catch {
  realRizinAvailable = false;
}
const it = test.skipIf(process.platform === "win32" || !realRizinAvailable);

it("analyzes a real ELF with the real rizin-ghidra engine", async () => {
  const targetPath = "/bin/ls";
  const bytes = await readFile(targetPath);
  const target: BinaryTarget = {
    path: targetPath,
    sha256: createHash("sha256").update(bytes).digest("hex"),
    kind: "executable",
    format: "elf",
    architecture: "x86_64",
    availableArchitectures: ["x86_64"],
  };
  const provider = new RzGhidraProvider({ REA_RIZIN_COMMAND: REAL_RIZIN });
  const profile = await withRzGhidraResourceScope((resourceScope) =>
    provider.resolveAnalysisProfile(target, { resourceScope }),
  );
  if (!profile.ok) throw profile.error;
  if (profile.value.profile === null)
    throw new Error("profile did not resolve");
  const client = provider.createClient(target, profile.value.profile);
  try {
    expect((await run(client, "health")).result).toMatchObject({ ready: true });

    const procedures = (await run(client, "list_procedures")).result as {
      address: string;
      value: string;
    }[];
    expect(procedures.length).toBeGreaterThan(0);

    // Find a function the embedded Ghidra decompiler can rebuild; a few
    // entries may legitimately fail on stripped binaries.
    let pseudo = "";
    for (const procedure of procedures.slice(0, 8)) {
      const attempt = await client.execute("procedure_pseudo_code", {
        procedure: procedure.value,
      });
      if (
        attempt.ok &&
        typeof attempt.value.result === "string" &&
        attempt.value.result.length > 0
      ) {
        pseudo = attempt.value.result;
        break;
      }
    }
    expect(pseudo.length).toBeGreaterThan(0);

    const xrefs = await run(client, "xrefs", {
      address: procedures[0]?.address ?? "0x0",
    });
    expect(Array.isArray(xrefs.result)).toBe(true);
  } finally {
    const closed = await client.close();
    if (!closed.ok) throw closed.error;
    expect(closed.value).toBe(null);
  }
}, 180_000);
