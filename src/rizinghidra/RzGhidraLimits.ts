/** One complete rizin frame: a whole-image `aflj`, `izj` or `pDj` answer. */
export const RIZIN_GHIDRA_FRAME_BYTES = 128 * 1024 * 1024;

/** Pseudocode or disassembly text for one function; those of a large image stay far below this. */
export const RIZIN_GHIDRA_TEXT_BYTES = 16 * 1024 * 1024;

/** Rizin stderr and diagnostic frames; matches the debug manager's diagnostic cap. */
export const RIZIN_GHIDRA_DIAGNOSTIC_BYTES = 64 * 1024;
