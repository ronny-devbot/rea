import { isAbsolute } from "node:path";

import { providerStartupTimeoutSchema } from "../config/providerStartupTimeout.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  RIZIN_COMMAND_REMEDIATION,
  RIZIN_UNSUPPORTED_HOST_REMEDIATION,
} from "./RzGhidraRelease.js";

/**
 * A whole-image `aa` pass on a large stripped binary runs for minutes; ten
 * minutes admits images an order of magnitude larger without an unbounded run.
 * Larger images need a raised deadline.
 */
const DEFAULT_ANALYSIS_TIMEOUT_MS = 600_000;

/** One command frame normally answers in milliseconds; 120 s matches the debug manager's frame deadline. */
const DEFAULT_FRAME_TIMEOUT_MS = 120_000;

/** Caller-selected rizin installation and REA-owned deadlines. */
export interface RzGhidraConfiguration {
  /** Caller-selected executable path, preserved exactly as configured. */
  readonly command: string;
  /** Deadline for the one whole-image `aa` pass. */
  readonly analysisTimeoutMs: number;
  /** Deadline for one command frame on the console. */
  readonly frameTimeoutMs: number;
}

/** One configured deadline and the setting that owns it. */
export interface RzGhidraDeadline {
  readonly setting:
    | "REA_RIZIN_ANALYSIS_TIMEOUT_MS"
    | "REA_RIZIN_FRAME_TIMEOUT_MS";
  readonly ms: number;
}

/** The one whole-image `aa` pass. */
export const rzGhidraAnalysisDeadline = (
  configuration: RzGhidraConfiguration,
): RzGhidraDeadline => ({
  setting: "REA_RIZIN_ANALYSIS_TIMEOUT_MS",
  ms: configuration.analysisTimeoutMs,
});

/** Every other command frame on the console. */
export const rzGhidraFrameDeadline = (
  configuration: RzGhidraConfiguration,
): RzGhidraDeadline => ({
  setting: "REA_RIZIN_FRAME_TIMEOUT_MS",
  ms: configuration.frameTimeoutMs,
});

/** Why the configured environment cannot select a rizin installation. */
export interface RzGhidraConfigurationFailure {
  readonly code: "not_configured" | "open_options_invalid" | "unsupported_host";
  readonly reason: string;
  readonly setting: string | null;
  readonly remediation: string;
}

const failure = (
  code: RzGhidraConfigurationFailure["code"],
  reason: string,
  setting: string | null = null,
): Result<never, RzGhidraConfigurationFailure> =>
  err({
    code,
    reason,
    setting,
    remediation:
      code === "unsupported_host"
        ? RIZIN_UNSUPPORTED_HOST_REMEDIATION
        : setting === null || setting === "REA_RIZIN_COMMAND"
          ? RIZIN_COMMAND_REMEDIATION
          : `Correct ${setting} to meet the reported constraint, or unset it to use its default. Restart REA after changing the environment.`,
  });

/** Parse the rizin-ghidra settings without touching the filesystem or the executable. */
export const readRzGhidraConfiguration = (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
): Result<RzGhidraConfiguration, RzGhidraConfigurationFailure> => {
  const command = environment.REA_RIZIN_COMMAND;
  if (command === undefined || command.length === 0)
    return failure("not_configured", RIZIN_COMMAND_REMEDIATION);
  if (!isAbsolute(command))
    return failure(
      "open_options_invalid",
      `REA_RIZIN_COMMAND must be an absolute path; received ${command}. ${RIZIN_COMMAND_REMEDIATION}`,
      "REA_RIZIN_COMMAND",
    );
  if (platform !== "darwin" && platform !== "linux")
    return failure("unsupported_host", RIZIN_UNSUPPORTED_HOST_REMEDIATION);

  const rawAnalysisTimeout = environment.REA_RIZIN_ANALYSIS_TIMEOUT_MS;
  const analysisTimeout =
    rawAnalysisTimeout === undefined
      ? undefined
      : providerStartupTimeoutSchema.safeParse(rawAnalysisTimeout);
  if (analysisTimeout !== undefined && !analysisTimeout.success)
    return failure(
      "open_options_invalid",
      `REA_RIZIN_ANALYSIS_TIMEOUT_MS must be a decimal millisecond count from 1 to 2147483647; received ${String(rawAnalysisTimeout)}.`,
      "REA_RIZIN_ANALYSIS_TIMEOUT_MS",
    );

  const rawFrameTimeout = environment.REA_RIZIN_FRAME_TIMEOUT_MS;
  const frameTimeout =
    rawFrameTimeout === undefined
      ? undefined
      : providerStartupTimeoutSchema.safeParse(rawFrameTimeout);
  if (frameTimeout !== undefined && !frameTimeout.success)
    return failure(
      "open_options_invalid",
      `REA_RIZIN_FRAME_TIMEOUT_MS must be a decimal millisecond count from 1 to 2147483647; received ${String(rawFrameTimeout)}.`,
      "REA_RIZIN_FRAME_TIMEOUT_MS",
    );

  return ok({
    command,
    analysisTimeoutMs: analysisTimeout?.data ?? DEFAULT_ANALYSIS_TIMEOUT_MS,
    frameTimeoutMs: frameTimeout?.data ?? DEFAULT_FRAME_TIMEOUT_MS,
  });
};
