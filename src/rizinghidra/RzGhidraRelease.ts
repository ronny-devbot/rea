/** Rizin release whose CLI and rz-ghidra plugin layout REA verified; others report as unverified. */
export const RIZIN_GHIDRA_VERIFIED_VERSION = "0.9.1";

/** Stable provider ID shared by readiness, doctor and Evidence. */
export const RIZIN_GHIDRA_PROVIDER_ID = "rizin-ghidra";

/** Display name used in tool output and documentation. */
export const RZ_GHIDRA_PROVIDER_NAME = "rz-ghidra";

/** Remediation when `REA_RIZIN_COMMAND` is missing or not an absolute path. */
export const RIZIN_COMMAND_REMEDIATION = `Set REA_RIZIN_COMMAND to the absolute path of a caller-supplied rizin executable (verified with ${RIZIN_GHIDRA_VERIFIED_VERSION}) whose build includes the rz-ghidra plugin with its Sleigh language files. REA does not download, install or update rizin.`;

/** Remediation when the selected rizin build lacks the rz-ghidra plugin. */
export const RZ_GHIDRA_PLUGIN_REMEDIATION =
  "The selected rizin build does not include the rz-ghidra plugin (the Ghidra decompiler with its Sleigh language files). Install a rizin build that bundles the plugin, or point REA_RIZIN_COMMAND at one.";

/** Remediation when the host cannot supervise a rizin process group. */
export const RIZIN_UNSUPPORTED_HOST_REMEDIATION =
  "Use Linux or macOS for the rizin-ghidra provider. Windows process-group ownership for rizin is not supported.";

/** Remediation when `rizin -v` cannot establish the installed release. */
export const RIZIN_VERSION_PROBE_REMEDIATION =
  "Run the selected executable with -v: it must exit promptly and print `rizin <major>.<minor>.<patch> @ <platform>` on its first line.";
