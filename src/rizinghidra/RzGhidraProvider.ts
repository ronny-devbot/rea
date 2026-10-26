import { accessSync, constants, statSync } from "node:fs";

import type {
  AnalysisClient,
  AnalysisProfileResolutionOptions,
  AnalysisProviderCandidate,
  ProviderAvailability,
  ProviderTargetSupport,
} from "../application/AnalysisProvider.js";
import {
  resolveRegexMatchingDeadline,
  type RegexMatchingDeadline,
} from "../config/regexMatchingDeadline.js";
import {
  resolveRegexWorkerHeapRequest,
  type RegexWorkerHeapRequest,
} from "../config/regexWorkerHeapRequest.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import {
  createAnalysisProfile,
  type AnalysisProfileCommitment,
} from "../domain/analysisProfile.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { err, ok } from "../domain/result.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { RegularFileCleanupFailure } from "../filesystem/OwnedRegularFile.js";
import { readRzGhidraConfiguration } from "./RzGhidraConfiguration.js";
import {
  createRzGhidraResourceScope,
  inspectRzGhidraInstallation,
  rzGhidraRetainedResourceCleanupError,
  type RzGhidraProcessLauncher,
} from "./RzGhidraInstallation.js";
import {
  RIZIN_GHIDRA_PROVIDER_IDENTITY,
  rzGhidraCapabilities,
} from "./RzGhidraProviderCapabilities.js";
import { RIZIN_COMMAND_REMEDIATION } from "./RzGhidraRelease.js";
import { RzGhidraSessionClient } from "./RzGhidraSessionClient.js";
import { rzGhidraUnavailable } from "./RzGhidraUnavailable.js";

/**
 * Bring-your-own rz-ghidra candidate. The executable must be a rizin build
 * carrying the rz-ghidra plugin (Ghidra decompiler embedded; no Ghidra
 * installation). Discovery reads configuration and executable metadata only;
 * the version and plugin probes run when a target is opened.
 *
 * No architecture gate: the embedded Sleigh set covers more architectures
 * than REA has verified, so an undecompilable function surfaces as a
 * per-function error rather than a selection failure.
 */
export class RzGhidraProvider implements AnalysisProviderCandidate {
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #deadline: RegexMatchingDeadline;
  readonly #heapRequest: RegexWorkerHeapRequest;
  readonly #platform: NodeJS.Platform;
  readonly #launcher: RzGhidraProcessLauncher | undefined;
  readonly #probeTimeoutMs: number | undefined;

  constructor(
    environment: Readonly<NodeJS.ProcessEnv>,
    options: {
      readonly platform?: NodeJS.Platform;
      readonly launcher?: RzGhidraProcessLauncher;
      /** Test seam for bounded installation-probe lifecycle cases. */
      readonly probeTimeoutMs?: number;
      /**
       * Deadline already resolved at startup. Omitted means resolve the
       * selected environment; an invalid setting is refused.
       */
      readonly regexMatchingDeadline?: RegexMatchingDeadline;
      /**
       * Heap request already resolved at startup. Omitted means resolve the
       * selected environment; an invalid setting is refused.
       */
      readonly regexWorkerHeapRequest?: RegexWorkerHeapRequest;
    } = {},
  ) {
    this.#platform = options.platform ?? process.platform;
    this.#environment = snapshotEnvironment(environment, this.#platform);
    this.#deadline =
      options.regexMatchingDeadline ??
      resolveRegexMatchingDeadline(this.#environment);
    this.#heapRequest =
      options.regexWorkerHeapRequest ??
      resolveRegexWorkerHeapRequest(this.#environment);
    this.#launcher = options.launcher;
    this.#probeTimeoutMs = options.probeTimeoutMs;
  }

  identity() {
    return RIZIN_GHIDRA_PROVIDER_IDENTITY;
  }

  capabilities() {
    const availability = this.inspectAvailability();
    return rzGhidraCapabilities(
      availability.status === "available"
        ? { available: true }
        : {
            available: false,
            reason: availability.reason,
            code: availability.code,
          },
      this.#deadline,
      this.#heapRequest,
    );
  }

  inspectAvailability(): ProviderAvailability {
    const configuration = readRzGhidraConfiguration(
      this.#environment,
      this.#platform,
    );
    if (!configuration.ok)
      return {
        status: "unavailable",
        code: configuration.error.code,
        reason: configuration.error.reason,
        diagnostics: {
          configured: configuration.error.code !== "not_configured",
          version_probed: false,
        },
      };
    const { command } = configuration.value;
    try {
      accessSync(command, constants.X_OK);
      if (!statSync(command).isFile()) throw new Error("not a regular file");
    } catch (cause: unknown) {
      return {
        status: "unavailable",
        code: "executable_missing",
        reason: `Cannot execute REA_RIZIN_COMMAND ${command}: ${cause instanceof Error ? cause.message : String(cause)}. ${RIZIN_COMMAND_REMEDIATION}`,
        diagnostics: { configured: true, command, version_probed: false },
      };
    }
    return {
      status: "available",
      code: null,
      reason: null,
      diagnostics: { configured: true, command, version_probed: false },
    };
  }

  inspectTargetSupport(target: BinaryTarget): ProviderTargetSupport {
    const diagnostics = {
      target_kind: target.kind,
      target_format: target.format,
    };
    if (target.kind !== "executable")
      return {
        status: "unsupported",
        code: "target_kind_unsupported",
        reason:
          "rz-ghidra decompiles executable images, not databases or archives.",
        diagnostics,
      };
    if (target.format !== "elf" && target.format !== "mach-o")
      return {
        status: "unsupported",
        code: "target_format_unsupported",
        reason:
          target.format === "mach-o-universal"
            ? "The rz-ghidra provider has no verified universal Mach-O slice selection yet; open a thin slice or use another provider."
            : `The rz-ghidra provider opens ELF and Mach-O images; ${target.format} is not admitted.`,
        diagnostics,
      };
    return { status: "supported", code: null, reason: null, diagnostics };
  }

  async resolveAnalysisProfile(
    _target: BinaryTarget,
    options?: AnalysisProfileResolutionOptions,
  ) {
    if (options?.signal?.aborted === true)
      return err(
        new AnalysisCancelledError("rizin-ghidra:profile", {
          cause: options.signal.reason,
        }),
      );
    let installation: Awaited<ReturnType<typeof inspectRzGhidraInstallation>>;
    const resourceScope = options?.resourceScope;
    if (resourceScope === undefined)
      return err(
        rzGhidraUnavailable(
          "rizin-ghidra:profile",
          "rz-ghidra profile inspection requires a durable resource scope",
        ),
      );
    const rzResources = createRzGhidraResourceScope(resourceScope);
    try {
      installation = await inspectRzGhidraInstallation(this.#environment, {
        platform: this.#platform,
        ...(options?.signal === undefined ? {} : { signal: options.signal }),
        resourceScope: rzResources.owner,
        ...(this.#launcher === undefined
          ? {}
          : { processLauncher: this.#launcher }),
        ...(this.#probeTimeoutMs === undefined
          ? {}
          : { probeTimeoutMs: this.#probeTimeoutMs }),
      });
    } catch (cause: unknown) {
      const retainedCleanup = rzGhidraRetainedResourceCleanupError(
        cause,
        "rizin-ghidra:profile",
      );
      if (retainedCleanup !== undefined) return err(retainedCleanup);
      const cancellation = rzResources.installationCancellationError(
        cause,
        "rizin-ghidra:profile",
      );
      if (cancellation !== undefined) return err(cancellation);
      if (cause instanceof RegularFileCleanupFailure) {
        const error = rzGhidraUnavailable(
          "rizin-ghidra:profile",
          "Probe cleanup failed and its resources are retained for a later retry.",
        );
        rzResources.bindFailure(cause, error);
        return err(error);
      }
      throw cause;
    }
    if (!installation.ok) {
      const error = rzGhidraUnavailable(
        "open_binary",
        installation.error.reason,
        {
          diagnostics: installation.error.diagnostics,
          ...(!rzResources.hasPending
            ? {}
            : {
                cleanup: {
                  reason:
                    "rz-ghidra version-probe process cleanup is unconfirmed.",
                  resources: rzResources.cleanupResources ?? [],
                },
              }),
        },
      );
      rzResources.bindRetainedFailure(error);
      return err(error);
    }
    const { value } = installation;
    return ok({
      profile: createAnalysisProfile(
        { ...RIZIN_GHIDRA_PROVIDER_IDENTITY, version: value.version },
        {
          rz_version: value.version,
          rz_sha256: value.sha256,
          verified_release: value.verified,
          plugin: "rz-ghidra",
          cache_policy: "live",
        },
      ),
    });
  }

  createClient(
    target: BinaryTarget,
    profile?: AnalysisProfileCommitment,
  ): AnalysisClient {
    const configuration = readRzGhidraConfiguration(
      this.#environment,
      this.#platform,
    );
    if (!configuration.ok)
      return {
        execute: async (operation) =>
          err(rzGhidraUnavailable(operation, configuration.error.reason)),
        close: async () => ok(null),
      };
    return new RzGhidraSessionClient(target, profile, {
      environment: this.#environment,
      analysisTimeoutMs: configuration.value.analysisTimeoutMs,
      frameTimeoutMs: configuration.value.frameTimeoutMs,
      deadline: this.#deadline,
      heapRequest: this.#heapRequest,
      ...(this.#launcher === undefined ? {} : { launcher: this.#launcher }),
    });
  }
}
