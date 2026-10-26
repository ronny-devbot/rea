import type {
  AnalysisOperation,
  CapabilityDescriptor,
} from "../application/AnalysisProvider.js";
import type { ProviderRejectionCode } from "../contracts/providerSelection.js";
import { RIZIN_GHIDRA_PROVIDER_ID } from "./RzGhidraRelease.js";
import {
  DEFAULT_REGEX_MATCHING_DEADLINE,
  type RegexMatchingDeadline,
} from "../config/regexMatchingDeadline.js";
import {
  DEFAULT_REGEX_WORKER_HEAP_REQUEST,
  type RegexWorkerHeapRequest,
} from "../config/regexWorkerHeapRequest.js";
import { launchRegexMatchingLimitation } from "../process/RegexMatcher.js";
import { RIZIN_GHIDRA_TEXT_BYTES } from "./RzGhidraLimits.js";

/** Static identity; the observed rizin release is reported in each analysis profile. */
export const RIZIN_GHIDRA_PROVIDER_IDENTITY = Object.freeze({
  id: RIZIN_GHIDRA_PROVIDER_ID,
  name: "rz-ghidra",
  version: null,
});

/** Analyst outcomes the rz-ghidra console can answer. */
export const RIZIN_GHIDRA_OPERATIONS = Object.freeze([
  "list_documents",
  "list_procedures",
  "search_procedures",
  "list_strings",
  "search_strings",
  "list_segments",
  "list_names",
  "procedure_address",
  "address_name",
  "procedure_info",
  "procedure_pseudo_code",
  "procedure_assembly",
  "read_function_instructions",
  "read_bytes",
  "xrefs",
  "procedure_callers",
  "procedure_callees",
  "set_address_name",
  "set_comment",
  "comment",
] as const satisfies readonly Exclude<AnalysisOperation, "health">[]);
export type RzGhidraOperation = (typeof RIZIN_GHIDRA_OPERATIONS)[number];

/** Whether an operation is one rz-ghidra answers. */
export const isRzGhidraOperation = (
  operation: AnalysisOperation,
): operation is RzGhidraOperation =>
  (RIZIN_GHIDRA_OPERATIONS as readonly string[]).includes(operation);

/** How to read every rz-ghidra answer. */
export const RZ_PROVENANCE =
  "Rizin static analysis with the embedded Ghidra decompiler: addresses and bytes are its observations, function entries and extents its derivations, and pseudocode its reconstruction, never original source.";

/** Entries come from rizin's own discovery. */
export const RZ_FUNCTION_LIMITATION =
  "rz-ghidra reports the functions rizin's analysis (`aa`) discovered; undetected or merged entries remain unknown, and entry extents are upper bounds.";

/** Pseudocode and disassembly are exact engine text, not comparable across providers. */
export const RZ_PSEUDOCODE_LIMITATION =
  "Pseudocode and disassembly are exact rz-ghidra/Rizin text, not comparable as equal or different with another provider's text.";
const RZ_TEXT_CAPACITY_LIMITATION = `Each decompiled or disassembled text admits at most ${String(RIZIN_GHIDRA_TEXT_BYTES)} bytes before allocation; larger output is refused, never truncated.`;

export const RZ_STRING_LIMITATION =
  "Rizin scans mapped sections for printable runs; encodings beyond its string finder (ASCII, wide) can remain undiscovered. An empty result is not proof of absence.";

export const RZ_XREF_LIMITATION =
  "Rizin reports static code/data references it resolves; unresolved computed calls and references outside its resolved set remain unknown; an empty result is not proof of absence.";

export const RZ_NAME_LIMITATION =
  "Names are the symbols, flags and function names rizin recorded; null means rizin assigned no name at this address, not that no symbol exists.";

export const RZ_MUTATION_LIMITATION =
  "Edits persist only in this session's rizin process and are visible to later reads in the same session; they never modify the file on disk.";

/** The limitations that apply to one operation's answer, and only those. */
export const rzGhidraLimitations = (
  operation: RzGhidraOperation,
  deadline: RegexMatchingDeadline = DEFAULT_REGEX_MATCHING_DEADLINE,
  heapRequest: RegexWorkerHeapRequest = DEFAULT_REGEX_WORKER_HEAP_REQUEST,
): readonly string[] => {
  switch (operation) {
    case "list_documents":
      return [RZ_PROVENANCE];
    case "list_strings":
      return [RZ_PROVENANCE, RZ_STRING_LIMITATION];
    case "search_strings":
      return [
        RZ_PROVENANCE,
        RZ_STRING_LIMITATION,
        launchRegexMatchingLimitation(deadline, heapRequest),
      ];
    case "list_segments":
    case "read_bytes":
    case "comment":
      return [RZ_PROVENANCE];
    case "list_names":
      return [RZ_PROVENANCE, RZ_NAME_LIMITATION];
    case "address_name":
      return [RZ_PROVENANCE, RZ_NAME_LIMITATION];
    case "list_procedures":
    case "procedure_address":
    case "procedure_info":
      return [RZ_PROVENANCE, RZ_FUNCTION_LIMITATION];
    case "search_procedures":
      return [
        RZ_PROVENANCE,
        RZ_FUNCTION_LIMITATION,
        launchRegexMatchingLimitation(deadline, heapRequest),
      ];
    case "xrefs":
      return [RZ_PROVENANCE, RZ_FUNCTION_LIMITATION, RZ_XREF_LIMITATION];
    case "procedure_callers":
    case "procedure_callees":
      return [RZ_PROVENANCE, RZ_FUNCTION_LIMITATION, RZ_XREF_LIMITATION];
    case "procedure_pseudo_code":
    case "procedure_assembly":
    case "read_function_instructions":
      return [
        RZ_PROVENANCE,
        RZ_PSEUDOCODE_LIMITATION,
        RZ_TEXT_CAPACITY_LIMITATION,
      ];
    case "set_address_name":
    case "set_comment":
      return [RZ_PROVENANCE, RZ_MUTATION_LIMITATION];
  }
};

/** Advertise rz-ghidra's static, process-launching operations truthfully. */
export const rzGhidraCapabilities = (
  availability:
    | { readonly available: true }
    | {
        readonly available: false;
        readonly reason: string;
        readonly code: ProviderRejectionCode;
      },
  deadline: RegexMatchingDeadline = DEFAULT_REGEX_MATCHING_DEADLINE,
  heapRequest: RegexWorkerHeapRequest = DEFAULT_REGEX_WORKER_HEAP_REQUEST,
): readonly CapabilityDescriptor[] =>
  RIZIN_GHIDRA_OPERATIONS.map((operation) => ({
    provider: RIZIN_GHIDRA_PROVIDER_IDENTITY,
    operation,
    ...(availability.available
      ? ({ available: true, reason: null } as const)
      : ({
          available: false,
          reason: availability.reason,
          availabilityCode: availability.code,
        } as const)),
    // `aa` and session edits mutate the live in-process analysis; replaying a
    // recorded answer would ignore renames and comments made later in the session.
    cachePolicy: "live",
    effects: {
      mutatesArtifact:
        operation === "set_address_name" || operation === "set_comment",
      launchesProcess: true,
      mayShowUi: false,
      mayAccessNetwork: false,
      mayWriteFilesystem: false,
      changesPermissions: false,
      requiresRoot: false,
    },
    limitations: rzGhidraLimitations(operation, deadline, heapRequest),
  }));
