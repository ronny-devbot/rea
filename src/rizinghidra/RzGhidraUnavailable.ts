import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import type { AnalysisErrorOptions } from "../domain/analysisErrorBase.js";
import { RIZIN_GHIDRA_PROVIDER_ID } from "./RzGhidraRelease.js";

/**
 * A rizin-ghidra capability gap whose reason is what the caller needs to read. Without
 * a user message the projection shows only "choose another analysis or
 * target", which hides facts such as "no code at this address".
 */
export const rzGhidraUnavailable = (
  operation: string,
  reason: string,
  options: AnalysisErrorOptions = {},
): AnalysisCapabilityUnavailableError =>
  new AnalysisCapabilityUnavailableError(
    RIZIN_GHIDRA_PROVIDER_ID,
    operation,
    reason,
    {
      ...options,
      userMessage: reason,
    },
  );
