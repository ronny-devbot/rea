import {
  assertRegularFileActive,
  RegularFileOperationCancelled,
} from "../filesystem/RegularFile.js";
import { constants, realpathSync, accessSync, statSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { jsonValueSchema, type JsonValue } from "../domain/jsonValue.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { bindArtifactFileCleanup } from "../artifacts/ArtifactFileOperation.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import {
  AnalysisCleanupLease,
  AnalysisCleanupLeaseGroup,
} from "../artifacts/AnalysisCleanupLease.js";
import {
  hashStableFile,
  observeStableFile,
  stableFileHashCause,
} from "../filesystem/StableFileHash.js";
import type { RetainedResourceScope } from "../application/AnalysisProvider.js";
import {
  RegularFileCancelled,
  RegularFileCleanupFailure,
  regularFileCancellation,
} from "../filesystem/OwnedRegularFile.js";
import {
  OwnedCommandFailure,
  runOwnedCommand,
} from "../process/OwnedCommand.js";
import { retainOwnedCommandCleanup } from "../providers/OwnedCommandCleanup.js";
import type {
  OwnedProviderProcessSpawnOptions,
  ProviderProcessSnapshot,
  SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import {
  readRzGhidraConfiguration,
  type RzGhidraConfiguration,
  type RzGhidraConfigurationFailure,
} from "./RzGhidraConfiguration.js";
import {
  RIZIN_COMMAND_REMEDIATION,
  RIZIN_GHIDRA_PROVIDER_ID,
  RIZIN_GHIDRA_VERIFIED_VERSION,
  RIZIN_VERSION_PROBE_REMEDIATION,
  RZ_GHIDRA_PLUGIN_REMEDIATION,
} from "./RzGhidraRelease.js";
import { RIZIN_GHIDRA_DIAGNOSTIC_BYTES } from "./RzGhidraLimits.js";

/** `rizin -v` exits before loading plugins or an input; `pd?` answers in milliseconds. */
const PROBE_TIMEOUT_MS = 10_000;

/** Verified rizin 0.9.1 banner: `rizin 0.9.1 @ linux-x86-64` on the first line. */
const VERSION_LINE = /^rizin (\d+\.\d+\.\d+) @ /u;

/** One-shot probes; both run read-only and print plain text to stdout. */
const PROBE_COMMANDS = {
  version: { arguments: ["-v"], label: "-v" },
  // rizin has no plugin-list command in 0.9.1; `pd?` help lists `pdg` only
  // when the rz-ghidra plugin is compiled in.
  plugin: {
    arguments: ["-q", "-e", "scr.color=off", "-c", "pd?"],
    label: "-c pd?",
  },
} as const;

type ProbeName = keyof typeof PROBE_COMMANDS;

const probeOutput = (snapshot: ProviderProcessSnapshot | null) => ({
  stdout: snapshot?.stdout.text ?? "",
  stderr: snapshot?.stderr.text ?? "",
  exitCode: snapshot?.exitCode ?? null,
  signal: snapshot?.signal ?? null,
  stdoutBytes: snapshot?.stdout.bytes ?? 0,
  stdoutObservedBytes: snapshot?.stdout.observedBytes ?? 0,
  stderrBytes: snapshot?.stderr.bytes ?? 0,
  stderrObservedBytes: snapshot?.stderr.observedBytes ?? 0,
  stdoutInvalidUtf8: snapshot?.stdout.invalidUtf8 === true,
  stderrInvalidUtf8: snapshot?.stderr.invalidUtf8 === true,
  diagnosticTruncated: snapshot?.diagnosticTruncated === true,
  outputIncomplete: snapshot?.outputIncomplete === true,
  truncated:
    snapshot?.diagnosticTruncated === true ||
    snapshot?.outputIncomplete === true ||
    (snapshot !== null &&
      snapshot.stdout.bytes < snapshot.stdout.observedBytes),
});

const probeOutputDiagnostics = (output: ReturnType<typeof probeOutput>) => ({
  stdout: output.stdout,
  stderr: output.stderr,
  exit_code: output.exitCode,
  signal: output.signal,
  stdout_bytes: output.stdoutBytes,
  stdout_observed_bytes: output.stdoutObservedBytes,
  stderr_bytes: output.stderrBytes,
  stderr_observed_bytes: output.stderrObservedBytes,
  ...(output.stdoutInvalidUtf8 ? { stdout_invalid_utf8: true } : {}),
  ...(output.stderrInvalidUtf8 ? { stderr_invalid_utf8: true } : {}),
  diagnostic_truncated: output.diagnosticTruncated,
  output_incomplete: output.outputIncomplete,
  output_truncated: output.truncated,
});

/** One observed rizin executable, identified by its bytes as well as its version and plugin. */
export interface RzGhidraInstallation {
  readonly configuration: RzGhidraConfiguration;
  /** Canonical path of the probed executable. */
  readonly executable: string;
  readonly version: string;
  /** Whether this release is the one REA verified. */
  readonly verified: boolean;
  readonly sha256: string;
  readonly bytes: number;
  /**
   * Whether the executable is a `#!` script, such as a package-manager shim.
   * Its process then reports the interpreter as its command, so ownership
   * checks cannot match the configured path by argv prefix.
   */
  readonly script: boolean;
  /** The probed build lists the `pdg` (rz-ghidra) decompiler. */
  readonly plugin: true;
}

/** Why the selected rizin installation cannot be used. */
export interface RzGhidraReadinessFailure {
  readonly code:
    | RzGhidraConfigurationFailure["code"]
    | "executable_missing"
    | "version_unresolved"
    | "plugin_missing"
    | "fingerprint_mismatch";
  readonly reason: string;
  readonly diagnostics: Readonly<Record<string, JsonValue>>;
  readonly remediation?: string;
}

export interface RzGhidraInstallationOptions {
  readonly platform?: NodeJS.Platform;
  readonly signal?: AbortSignal;
  /** Probe deadline; tests shorten it. */
  readonly probeTimeoutMs?: number;
  readonly resourceScope: RetainedResourceScope;
  /** Test seam for the owned command launcher; production uses the verified default. */
  readonly processLauncher?: RzGhidraProcessLauncher | undefined;
}

/** Cancellation facts normalized by the installation inspection that observed them. */
interface RzGhidraInstallationCancellation {
  readonly reason: unknown;
  readonly diagnostics?: Readonly<Record<string, JsonValue>>;
}

// Annotations follow the exact failure's lifetime. Descriptor ownership stays
// with the supplied resource scope, independently of this weak metadata.
const installationFailureDiagnostics = new WeakMap<
  Error,
  Readonly<Record<string, JsonValue>>
>();

export const rzGhidraInstallationFailureDiagnostics = (
  cause: unknown,
): Readonly<Record<string, JsonValue>> | undefined =>
  cause instanceof Error
    ? installationFailureDiagnostics.get(cause)
    : undefined;

/** Test seam for the owned command launcher; production uses the verified default. */
export type RzGhidraProcessLauncher = (
  options: OwnedProviderProcessSpawnOptions,
) => Promise<SpawnedOwnedProviderProcess>;

/** Consumers project the owner's facts without reinterpreting generic file outcomes. */
export const rzGhidraInstallationCancellation = (
  cause: unknown,
): RzGhidraInstallationCancellation | undefined => {
  const cancellation = regularFileCancellation(cause);
  if (cancellation === undefined) return undefined;
  const diagnostics = rzGhidraInstallationFailureDiagnostics(cause);
  return {
    reason: cancellation.reason,
    ...(diagnostics === undefined ? {} : { diagnostics }),
  };
};

/** One installation inspection's retained owners and originating errors. */
export interface RzGhidraResourceScope {
  readonly owner: RetainedResourceScope;
  readonly cleanupResources: readonly string[] | undefined;
  readonly hasPending: boolean;
  installationCancellationError(
    cause: unknown,
    operation: string,
  ): AnalysisCancelledError | undefined;
  bindFailure(failure: RegularFileCleanupFailure, error: AnalysisError): void;
  bindRetainedFailure(error: AnalysisError): void;
}

/** Adapt retained resource owners into leases and bind errors to exact owners. */
export const createRzGhidraResourceScope = (
  parent: RetainedResourceScope,
): RzGhidraResourceScope => {
  const leases = new Map<
    Parameters<RetainedResourceScope["retain"]>[0],
    { readonly lease: AnalysisCleanupLease }
  >();
  const pendingLeases = () =>
    [...leases.values()]
      .map(({ lease }) => lease)
      .filter((lease) => !lease.released);
  const bindPendingFailure = (error: AnalysisError) => {
    const retained = pendingLeases();
    if (retained.length > 0) new AnalysisCleanupLeaseGroup(error, retained);
  };
  const cleanupResources = (
    pending = pendingLeases(),
  ): readonly string[] | undefined => {
    if (pending.some((lease) => lease.cleanupResources === undefined))
      return undefined;
    return [
      ...new Set(pending.flatMap((lease) => lease.cleanupResources ?? [])),
    ];
  };
  return {
    get hasPending() {
      return pendingLeases().length > 0;
    },
    get cleanupResources() {
      return cleanupResources();
    },
    installationCancellationError: (cause, operation) => {
      const cancellation = rzGhidraInstallationCancellation(cause);
      if (cancellation === undefined) return undefined;
      const pending = pendingLeases();
      const error = new AnalysisCancelledError(operation, {
        cause: cancellation.reason,
        diagnostics: cancellation.diagnostics,
        ...(pending.length === 0
          ? {}
          : {
              cleanup: {
                reason: "rizin-ghidra probe process cleanup is unconfirmed.",
                resources: cleanupResources(pending) ?? [],
              },
            }),
      });
      bindPendingFailure(error);
      return error;
    },
    owner: {
      retain: (owner, resource) => {
        const lease = AnalysisCleanupLease.forCloseOwner(owner, resource);
        leases.set(owner, { lease });
        parent.retain(
          {
            close: () => lease.release(),
            get cleanupResources() {
              return lease.cleanupResources;
            },
          },
          resource,
        );
      },
      run: (operation) => parent.run(operation),
    },
    bindFailure: (failure, error) => {
      if (leases.has(failure.owner)) bindPendingFailure(error);
    },
    bindRetainedFailure: bindPendingFailure,
  };
};

/**
 * Environment for every rizin child. Rizin runs with `-N` (no rc file) and
 * opens the target read-only, so it writes nothing; the private HOME under
 * the system temporary directory is cheap insurance that no rc, cache or
 * config is ever read from or written to the user's own home.
 */
export const rzGhidraChildEnvironment = (
  configuration: RzGhidraConfiguration,
): NodeJS.ProcessEnv => {
  void configuration;
  const home = join(tmpdir(), "rea-rizin-ghidra");
  return {
    HOME: home,
    NO_COLOR: "1",
  };
};

const failure = (
  code: RzGhidraReadinessFailure["code"],
  reason: string,
  diagnostics: Readonly<Record<string, JsonValue>>,
  remediation?: string,
): Result<never, RzGhidraReadinessFailure> =>
  err({
    code,
    reason,
    diagnostics,
    ...(remediation === undefined ? {} : { remediation }),
  });

const message = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

/** Preserve the exact retryable resources when an inspection admission retries them. */
export const rzGhidraRetainedResourceCleanupError = (
  cause: unknown,
  operation: string,
): AnalysisError | undefined => {
  if (
    !(cause instanceof ArtifactReaderFailure) ||
    cause.cleanupLeases === undefined ||
    cause.cleanupLeases.length === 0
  )
    return undefined;
  const cleanup = new ProviderCleanupError(
    RIZIN_GHIDRA_PROVIDER_ID,
    cause.cleanup?.resources ?? [],
    { reason: message(cause) },
    { cause, operation },
  );
  bindArtifactFileCleanup(cause, cleanup);
  return cleanup;
};

/** Mutable bookkeeping for one inspection's file observations, re-recorded as phases complete. */
interface InstallationFileObservation {
  phase: "fingerprint" | "identity";
  completedHash?: { readonly sha256: string; readonly bytes: number };
  script?: boolean;
  beforeProbeFingerprint?: {
    readonly sha256: string;
    readonly bytes: number;
  };
  versionProbe?: {
    readonly deadlineMs: number;
    readonly output: ReturnType<typeof probeOutput>;
  };
  pluginProbe?: {
    readonly deadlineMs: number;
    readonly output: ReturnType<typeof probeOutput>;
  };
}

/** Keep completed file facts attached when cancellation or close failure interrupts inspection. */
const recordPartialInstallationFileOperation = (
  cause: unknown,
  facts: {
    readonly command: string;
    readonly executable: string;
    readonly version?: string;
    readonly observed: InstallationFileObservation;
  },
): boolean => {
  const cancellation = regularFileCancellation(cause);
  if (
    !(cause instanceof Error) ||
    (!(cause instanceof RegularFileCleanupFailure) &&
      cancellation === undefined)
  )
    return false;

  const outcome =
    cause instanceof RegularFileCancelled ||
    cause instanceof RegularFileCleanupFailure
      ? cause.outcome
      : undefined;
  const completed = outcome?.kind === "completed" ? outcome.value : undefined;
  const completedRecord =
    completed !== null &&
    typeof completed === "object" &&
    !Array.isArray(completed)
      ? (completed as Record<string, unknown>)
      : undefined;
  const completedFingerprint =
    facts.observed.phase === "fingerprint"
      ? completed
      : completedRecord === undefined
        ? undefined
        : {
            sha256: completedRecord["sha256"],
            bytes: completedRecord["bytes"],
          };
  const completedHash =
    facts.observed.completedHash ??
    (outcome?.kind === "completed" && completedFingerprint !== undefined
      ? jsonValueSchema.parse(completedFingerprint)
      : undefined);
  const completedScript =
    facts.observed.script ??
    (facts.observed.phase === "identity" &&
    Buffer.isBuffer(completedRecord?.["prefix"])
      ? completedRecord["prefix"].toString("latin1") === "#!"
      : undefined);
  installationFailureDiagnostics.set(cause, {
    rizin_ghidra_installation: {
      status: "partial",
      command: facts.command,
      executable: facts.executable,
      ...(facts.version === undefined
        ? {}
        : {
            version: facts.version,
            verified: facts.version === RIZIN_GHIDRA_VERIFIED_VERSION,
          }),
      ...(completedHash === undefined ? {} : { completed_hash: completedHash }),
      ...(completedScript === undefined ? {} : { script: completedScript }),
      ...(facts.observed.beforeProbeFingerprint === undefined
        ? {}
        : {
            before_probe_sha256: facts.observed.beforeProbeFingerprint.sha256,
            before_probe_bytes: facts.observed.beforeProbeFingerprint.bytes,
          }),
    },
    ...(facts.observed.versionProbe === undefined
      ? {}
      : {
          rizin_version_probe: {
            status: "completed",
            deadline_ms: facts.observed.versionProbe.deadlineMs,
            ...probeOutputDiagnostics(facts.observed.versionProbe.output),
          },
        }),
    ...(facts.observed.pluginProbe === undefined
      ? {}
      : {
          rizin_plugin_probe: {
            status: "completed",
            deadline_ms: facts.observed.pluginProbe.deadlineMs,
            ...probeOutputDiagnostics(facts.observed.pluginProbe.output),
          },
        }),
  });
  return true;
};

/** Resolve, fingerprint, version-probe and plugin-probe the configured executable. */
export const inspectRzGhidraInstallation = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  options: RzGhidraInstallationOptions,
): Promise<Result<RzGhidraInstallation, RzGhidraReadinessFailure>> => {
  const configuration = readRzGhidraConfiguration(
    environment,
    options.platform,
  );
  if (!configuration.ok)
    return err({
      code: configuration.error.code,
      reason: configuration.error.reason,
      remediation: configuration.error.remediation,
      diagnostics: {
        configured: configuration.error.code !== "not_configured",
        ...(configuration.error.setting === null
          ? {}
          : { setting: configuration.error.setting }),
      },
    });
  const { command } = configuration.value;
  assertRegularFileActive(options.signal);

  let executable: string;
  try {
    executable = realpathSync(command);
    accessSync(executable, constants.X_OK);
    if (!statSync(executable).isFile())
      return failure(
        "executable_missing",
        `REA_RIZIN_COMMAND is not a regular file: ${command}. ${RIZIN_COMMAND_REMEDIATION}`,
        { command },
        RIZIN_COMMAND_REMEDIATION,
      );
  } catch (cause: unknown) {
    return failure(
      "executable_missing",
      `Cannot execute REA_RIZIN_COMMAND ${command}: ${message(cause)}. ${RIZIN_COMMAND_REMEDIATION}`,
      { command },
      RIZIN_COMMAND_REMEDIATION,
    );
  }

  assertRegularFileActive(options.signal);

  let beforeProbeFingerprint: {
    readonly sha256: string;
    readonly bytes: number;
  };
  const beforeProbeObservation: InstallationFileObservation = {
    phase: "fingerprint",
  };
  try {
    beforeProbeFingerprint = await options.resourceScope.run(() =>
      hashStableFile(executable, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        retainFailedClose: (owner) =>
          options.resourceScope.retain(owner, executable),
      }),
    );
  } catch (cause: unknown) {
    if (cause instanceof ArtifactReaderFailure) throw cause;
    if (
      recordPartialInstallationFileOperation(cause, {
        command,
        executable,
        observed: beforeProbeObservation,
      })
    )
      throw cause;
    return failure(
      "executable_missing",
      `Cannot fingerprint ${executable}: ${message(stableFileHashCause(cause))}`,
      { command, executable },
      RIZIN_COMMAND_REMEDIATION,
    );
  }

  const deadline = options.probeTimeoutMs ?? PROBE_TIMEOUT_MS;
  const observed: InstallationFileObservation = {
    phase: "fingerprint",
    beforeProbeFingerprint,
  };

  const runProbe = async (
    name: ProbeName,
  ): Promise<Result<ProviderProcessSnapshot, RzGhidraReadinessFailure>> => {
    const probe = PROBE_COMMANDS[name];
    const remediation =
      name === "version"
        ? RIZIN_VERSION_PROBE_REMEDIATION
        : RZ_GHIDRA_PLUGIN_REMEDIATION;
    try {
      return ok(
        await options.resourceScope.run(() =>
          runOwnedCommand(
            {
              command: executable,
              arguments: probe.arguments,
              runId: `rea-rzghidra-${name}-${randomUUID()}`,
              // The configured command may be an interpreter-driven shim.
              expectedCommand: null,
              hostEnvironment: rzGhidraChildEnvironment(configuration.value),
            },
            {
              timeoutMs: deadline,
              diagnosticBytes: RIZIN_GHIDRA_DIAGNOSTIC_BYTES,
            },
            {
              ...(options.signal === undefined
                ? {}
                : { signal: options.signal }),
              ...(options.processLauncher === undefined
                ? {}
                : { launcher: options.processLauncher }),
            },
          ),
        ),
      );
    } catch (cause: unknown) {
      if (cause instanceof ArtifactReaderFailure) throw cause;
      const retainedCleanup = retainOwnedCommandCleanup(
        cause,
        options.resourceScope,
        RIZIN_GHIDRA_PROVIDER_ID,
        "rizin-ghidra:installation",
      );
      const cleanupIncomplete = retainedCleanup.length > 0;
      if (cause instanceof OwnedCommandFailure) {
        const output = probeOutput(cause.snapshot);
        if (cause.reason === "cancelled") {
          const cancellation = new RegularFileOperationCancelled(
            cause.cancellation?.reason,
          );
          installationFailureDiagnostics.set(cancellation, {
            rizin_ghidra_installation: {
              status: "partial",
              command,
              executable,
            },
            [name === "version" ? "rizin_version_probe" : "rizin_plugin_probe"]:
              {
                status: "partial",
                command,
                executable,
                deadline_ms: deadline,
                ...probeOutputDiagnostics(output),
                probe_failure_reason: cause.reason,
                cleanup_incomplete: cleanupIncomplete,
              },
          });
          throw cancellation;
        }
        return failure(
          name === "version" ? "version_unresolved" : "plugin_missing",
          `${executable} ${probe.label} failed: ${output.stderr.trim() || cause.message}. ${remediation}`,
          {
            command,
            executable,
            probe_failure_reason: cause.reason,
            cleanup_incomplete: cleanupIncomplete,
            deadline_ms: deadline,
            ...probeOutputDiagnostics(output),
          },
          remediation,
        );
      }
      return failure(
        name === "version" ? "version_unresolved" : "plugin_missing",
        `${executable} ${probe.label} failed: ${message(cause)}. ${remediation}`,
        {
          command,
          executable,
          exit_code: null,
          signal: null,
          cleanup_incomplete: cleanupIncomplete,
          deadline_ms: deadline,
        },
        remediation,
      );
    }
  };

  const versionProbe = await runProbe("version");
  if (!versionProbe.ok) return versionProbe;
  observed.versionProbe = {
    deadlineMs: deadline,
    output: probeOutput(versionProbe.value),
  };
  const versionOutput = observed.versionProbe.output;
  if (versionOutput.truncated)
    return failure(
      "version_unresolved",
      `${executable} -v output was incomplete. ${RIZIN_VERSION_PROBE_REMEDIATION}`,
      {
        command,
        executable,
        deadline_ms: deadline,
        output_truncated: true,
        stdout: versionOutput.stdout.slice(0, 256),
      },
      RIZIN_VERSION_PROBE_REMEDIATION,
    );
  const version = VERSION_LINE.exec(
    versionOutput.stdout.split(/\r?\n/u)[0] ?? "",
  )?.[1];
  if (version === undefined)
    return failure(
      "version_unresolved",
      `${executable} -v printed no recognizable rizin version. ${RIZIN_VERSION_PROBE_REMEDIATION}`,
      { command, executable, stdout: versionOutput.stdout.slice(0, 256) },
      RIZIN_VERSION_PROBE_REMEDIATION,
    );

  const pluginProbe = await runProbe("plugin");
  if (!pluginProbe.ok) return pluginProbe;
  observed.pluginProbe = {
    deadlineMs: deadline,
    output: probeOutput(pluginProbe.value),
  };
  const pluginOutput = observed.pluginProbe.output;
  if (pluginOutput.truncated)
    return failure(
      "plugin_missing",
      `${executable} -c pd? output was incomplete, so the rz-ghidra plugin cannot be confirmed. ${RZ_GHIDRA_PLUGIN_REMEDIATION}`,
      {
        command,
        executable,
        version,
        deadline_ms: deadline,
        output_truncated: true,
      },
      RZ_GHIDRA_PLUGIN_REMEDIATION,
    );
  const pluginPresent = pluginOutput.stdout
    .split(/\r?\n/u)
    .some((line) => line.includes("pdg"));
  if (!pluginPresent)
    return failure(
      "plugin_missing",
      `${executable} reports rizin ${version} but its pd? help lists no pdg (rz-ghidra) decompiler. ${RZ_GHIDRA_PLUGIN_REMEDIATION}`,
      {
        command,
        executable,
        version,
        verified: version === RIZIN_GHIDRA_VERIFIED_VERSION,
        deadline_ms: deadline,
        ...probeOutputDiagnostics(pluginOutput),
      },
      RZ_GHIDRA_PLUGIN_REMEDIATION,
    );

  let fingerprint: { readonly sha256: string; readonly bytes: number };
  let script: boolean;
  try {
    ({ fingerprint, script } = await options.resourceScope.run(async () => {
      observed.phase = "identity";
      const observation = await observeStableFile(executable, {
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        retainFailedClose: (owner) =>
          options.resourceScope.retain(owner, executable),
      });
      const fingerprint = {
        sha256: observation.sha256,
        bytes: observation.bytes,
      };
      const script =
        observation.prefix.length === 2 &&
        observation.prefix.toString("latin1") === "#!";
      observed.completedHash = fingerprint;
      observed.script = script;
      assertRegularFileActive(options.signal);
      return { fingerprint, script };
    }));
  } catch (cause: unknown) {
    if (cause instanceof ArtifactReaderFailure) throw cause;
    if (
      recordPartialInstallationFileOperation(cause, {
        command,
        executable,
        version,
        observed,
      })
    )
      throw cause;
    return failure(
      "executable_missing",
      `Cannot observe ${executable} after its probes: ${message(stableFileHashCause(cause))}`,
      {
        command,
        executable,
        version,
        verified: version === RIZIN_GHIDRA_VERIFIED_VERSION,
        identity_observation_phase: "post_probe",
        identity_observation_failure: message(stableFileHashCause(cause)),
        before_probe_sha256: beforeProbeFingerprint.sha256,
        before_probe_bytes: beforeProbeFingerprint.bytes,
        deadline_ms: deadline,
      },
      RIZIN_COMMAND_REMEDIATION,
    );
  }

  if (
    beforeProbeFingerprint.sha256 !== fingerprint.sha256 ||
    beforeProbeFingerprint.bytes !== fingerprint.bytes
  )
    return failure(
      "fingerprint_mismatch",
      `${executable} changed during the rizin probes, so its version and plugin were observed on different bytes. ${RIZIN_COMMAND_REMEDIATION}`,
      {
        command,
        executable,
        version,
        verified: version === RIZIN_GHIDRA_VERIFIED_VERSION,
        installation_identity_changed: true,
        before_sha256: beforeProbeFingerprint.sha256,
        before_bytes: beforeProbeFingerprint.bytes,
        after_sha256: fingerprint.sha256,
        after_bytes: fingerprint.bytes,
        deadline_ms: deadline,
      },
      RIZIN_COMMAND_REMEDIATION,
    );

  return ok({
    configuration: configuration.value,
    executable,
    version,
    verified: version === RIZIN_GHIDRA_VERIFIED_VERSION,
    ...fingerprint,
    script,
    plugin: true,
  });
};
