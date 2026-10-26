import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { analysisClientFailureForOperation } from "../providers/AnalysisClientFailure.js";
import { RIZIN_GHIDRA_PROVIDER_ID } from "./RzGhidraRelease.js";

/** Keep one producer failure immutable while each waiter receives its context. */
export const rzGhidraQueryFailureForCaller = (
  source: AnalysisError,
  operation: string,
): AnalysisError => {
  if (
    !("operation" in source) ||
    typeof source.operation !== "string" ||
    source.operation === operation
  )
    return source;
  return analysisClientFailureForOperation(
    source,
    RIZIN_GHIDRA_PROVIDER_ID,
    operation,
    {
      producer_operation: source.operation,
    },
  );
};
