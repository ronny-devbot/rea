#!/usr/bin/env node
// Real rizin-ghidra provider lane. Requires a caller-supplied rizin
// (REA_RIZIN_COMMAND, an absolute path to a build carrying the rz-ghidra
// plugin) and a host C compiler; REA installs neither. The default run
// builds a source-owned fixture, verifies the public MCP workflow -
// procedure inventory, one function's pseudocode, xrefs to that function -
// and asserts that closing the session leaves no retained process.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { inspectRzGhidraInstallation } from "../dist/rizinghidra/RzGhidraInstallation.js";
import { ArtifactResourceScope } from "../dist/artifacts/ArtifactResourceScope.js";
import { AnalysisCleanupLease } from "../dist/artifacts/AnalysisCleanupLease.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import {
  assertVerifierCleanupComplete,
  completeVerifierRun,
  createVerifierRun,
} from "./lib/verifier-run.mjs";

const exec = promisify(execFile);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const rizin = process.env.REA_RIZIN_COMMAND;
assert.ok(
  rizin !== undefined && isAbsolute(rizin),
  "rizin-ghidra lane prerequisite missing: REA_RIZIN_COMMAND must name a caller-supplied rizin build carrying the rz-ghidra plugin by absolute path (bring your own)",
);
const run = createVerifierRun();
const inspectionResources = new ArtifactResourceScope();
const resourceScope = {
  retain: (owner, resource) =>
    inspectionResources.retain({
      kind: "lease",
      resource,
      lease: AnalysisCleanupLease.forCloseOwner(owner, resource),
    }),
  run: (operation) => inspectionResources.run(operation),
};

// main calls rea_square, so xrefs to the helper must report main as a source.
const FIXTURE_SOURCE = String.raw`
#include <stdio.h>
__attribute__((noinline)) int rea_square(int x) {
  return x * x;
}
int main(void) {
  printf("%d\n", rea_square(7));
  return 0;
}
`;

const workspace = await mkdtemp(join(tmpdir(), "rea-rzghidra-lane-"));
const failures = [];
const results = [];
// A server is retained only when cleanup failures exceed the one tolerated
// prior verification failure; the workspace follows the same rule.
let serverRetained = false;
let inspectionResourcesClean = true;
const mcpStderr = [];
try {
  const installation = await inspectRzGhidraInstallation(
    { REA_RIZIN_COMMAND: rizin },
    { resourceScope },
  );
  assert.ok(
    installation.ok,
    installation.ok ? undefined : installation.error.reason,
  );
  results.push({
    installation: `${rizin} reports rizin ${installation.value.version}${installation.value.verified ? ", the release REA verified" : ", an unverified release"}`,
  });

  const source = join(workspace, "fixture.c");
  await writeFile(source, FIXTURE_SOURCE);
  const binary = join(workspace, "rea-rzghidra-fixture");
  await exec(process.env.REA_CC ?? "cc", ["-O2", "-o", binary, source]);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [entrypoint, "--mcp"],
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      HOME: process.env.HOME ?? workspace,
      REA_LOG_LEVEL: "silent",
      REA_PROCESS_RUN_ID: run.run_id,
      REA_RIZIN_COMMAND: rizin,
    },
    stderr: "pipe",
  });
  transport.stderr?.on("data", (chunk) => mcpStderr.push(chunk));
  const client = new Client({ name: "rea-real-rzghidra", version: "1" });
  const call = async (name, arguments_ = {}) =>
    requireMcpOperationResult(
      // The full frame budget: a slow whole-image `aa` pass is normal.
      await client.callTool(
        { name, arguments: arguments_ },
        { timeout: 1_800_000 },
      ),
      name,
    );
  let priorFailure;
  try {
    await client.connect(transport);
    await call("open_binary", { path: binary, provider_id: "rizin-ghidra" });
    const procedures = await call("list_procedures");
    assert.ok(
      Array.isArray(procedures) && procedures.length > 0,
      `list_procedures returned no procedures for ${binary}`,
    );
    // Global ELF symbols arrive prefixed (sym.rea_square); the entry point
    // is not, so accept either the bare or the namespaced form.
    const square = procedures.find((entry) =>
      /(^|\.)rea_square$/.test(entry.value),
    );
    assert.ok(
      square !== undefined,
      "rea_square is missing from the procedure list",
    );
    const pseudocode = await call("procedure_pseudo_code", {
      procedure: square.address,
    });
    assert.ok(
      typeof pseudocode === "string" && pseudocode.length > 0,
      `procedure_pseudo_code returned no code for rea_square at ${square.address}`,
    );
    const references = await call("xrefs", { address: square.address });
    assert.ok(
      Array.isArray(references) && references.length > 0,
      `xrefs returned no references to rea_square at ${square.address}`,
    );
    results.push({
      procedures: procedures.length,
      rea_square: square.address,
      pseudocode_bytes: pseudocode.length,
      xrefs_to_rea_square: references,
    });
  } catch (cause) {
    priorFailure = cause;
  } finally {
    // Attempt each cleanup independently. Disposing a transport is not proof
    // that close_binary released the rizin console.
    const closeFailures = priorFailure === undefined ? [] : [priorFailure];
    for (const cleanup of [
      () => call("close_binary"),
      () => client.close(),
      () => transport.close(),
    ])
      try {
        await cleanup();
      } catch (cause) {
        closeFailures.push(cause);
      }
    // A prior verification error must survive successful cleanup. Only
    // additional failures retain this server's process.
    if (closeFailures.length > (priorFailure === undefined ? 0 : 1)) {
      serverRetained = true;
      failures.push(
        new AggregateError(
          closeFailures,
          "MCP server cleanup was not confirmed",
        ),
      );
    }
    if (priorFailure !== undefined) failures.push(priorFailure);
  }
} catch (cause) {
  failures.push(cause);
}
try {
  await inspectionResources.close();
} catch (cause) {
  inspectionResourcesClean = false;
  failures.push(cause);
}
const lifecycle = await completeVerifierRun(run);
let cleanupComplete = !serverRetained && inspectionResourcesClean;
try {
  assertVerifierCleanupComplete(lifecycle.process_lineage);
} catch (cause) {
  cleanupComplete = false;
  failures.push(cause);
}
if (cleanupComplete && failures.length === 0)
  try {
    await rm(workspace, { recursive: true, force: true });
  } catch (cause) {
    cleanupComplete = false;
    failures.push(cause);
  }
const report = {
  lane: "rizin-ghidra",
  status: failures.length === 0 ? "passed" : "failed",
  platform: `${process.platform}/${process.arch}`,
  verifier_run: lifecycle,
  results,
  cleanup: cleanupComplete ? "complete" : "incomplete",
  ...(cleanupComplete ? {} : { retained_workspace: workspace }),
  ...(failures.length === 0
    ? {}
    : {
        failures: failures.map((cause) =>
          cause instanceof Error ? cause.message : String(cause),
        ),
        mcp_stderr: Buffer.concat(mcpStderr).toString("utf8").slice(-4096),
      }),
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (failures.length > 0)
  throw new AggregateError(
    failures,
    "rizin-ghidra verification failed; see the report for cleanup evidence",
  );
