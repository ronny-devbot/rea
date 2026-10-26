# rz-ghidra provider

[rz-ghidra](https://github.com/rizinorg/rz-ghidra) is a rizin build carrying the rz-ghidra plugin: the Ghidra decompiler embedded as a C++ library, plus the Sleigh disassembler. REA drives the rizin console directly, so no Ghidra installation, JDK or database is needed. REA uses a rizin build you supply. It does not download, install, update or bundle it. REA verified this provider with rizin 0.9.1; it accepts other releases and reports them as unverified in `rea doctor` and in each analysis profile.

rz-ghidra is static: rizin opens the selected image read-only and never executes it.

## Prerequisites

- A rizin build that includes the rz-ghidra plugin, for example a source build of [rizinorg/rz-ghidra](https://github.com/rizinorg/rz-ghidra). A plain distro rizin without the plugin will not read as available: the readiness probe is a one-shot `pd?` help lookup, and `pdg` is listed only when the plugin is compiled in.
- The Sleigh language files installed alongside that build. No one-shot probe can confirm them; a missing Sleigh set surfaces as per-function decompile failures at runtime, not as a readiness failure.

## Configure

```bash
export REA_RIZIN_COMMAND=/absolute/path/to/rizin
rea doctor --provider rizin-ghidra --json
```

| Setting                         | Default         | Meaning                                                                                                                                                                                                                                               |
| ------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `REA_RIZIN_COMMAND`             | none (required) | Absolute path of a caller-supplied rizin executable whose build includes the rz-ghidra plugin with its Sleigh language files. The same variable also configures the separate one-shot `execute_rizin_command` tool, so it must name the plugin build. |
| `REA_RIZIN_ANALYSIS_TIMEOUT_MS` | 600000 (10 min) | Deadline for the one whole-image `aa` analysis pass.                                                                                                                                                                                                  |
| `REA_RIZIN_FRAME_TIMEOUT_MS`    | 120000 (120 s)  | Deadline for one command frame on the rizin console.                                                                                                                                                                                                  |

Both timeout settings are decimal millisecond counts from 1 to 2147483647. Unset uses the default; an invalid value is a configuration error, not a fallback. Settings are read from the environment that starts REA, so a change needs a restart.

`REA_RIZIN_COMMAND` must be an absolute path; a relative name is refused with the correction. The doctor reports the executable and its SHA-256, the rizin version from `rizin -v`, and the one-shot `pd?` plugin probe.

Select it explicitly with `--provider rizin-ghidra`, MCP's `open_binary.provider_id: "rizin-ghidra"`, or `REA_ANALYSIS_PROVIDER=rizin-ghidra`. With rz-ghidra and another provider configured for the same target, `auto` reports `ambiguous` instead of choosing one.

The provider runs on Linux and macOS. Windows process-group ownership for rizin is not supported.

## Usage

```bash
rea decompile /absolute/path/to/program main --provider rizin-ghidra --json
rea function /absolute/path/to/program main --provider rizin-ghidra --json
rea xrefs /absolute/path/to/program 0x401000 --provider rizin-ghidra --json
```

Over MCP:

```json
{"name":"open_binary","arguments":{"path":"/absolute/path/to/program","provider_id":"rizin-ghidra"}}
{"name":"procedure_pseudo_code","arguments":{"procedure":"main"}}
{"name":"search_strings","arguments":{"pattern":"license"}}
{"name":"close_binary","arguments":{}}
```

The first analysis request in a session runs one whole-image `aa` pass under `REA_RIZIN_ANALYSIS_TIMEOUT_MS`; every later operation is a single console frame under `REA_RIZIN_FRAME_TIMEOUT_MS`. `close_binary`, or the end of a CLI command, ends the rizin process.

## What rz-ghidra answers

| Operation                                                                     | Source                                                                                                   |
| ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `procedure_pseudo_code`                                                       | The Ghidra decompiler embedded in rizin (`pdg`)                                                          |
| `procedure_assembly`, `read_function_instructions`                            | The Sleigh disassembler                                                                                  |
| `list_procedures`, `search_procedures`, `procedure_address`, `procedure_info` | The function table the `aa` pass builds                                                                  |
| `list_strings`, `search_strings`                                              | Rizin's string finder over the mapped sections; an empty result is not proof of absence                  |
| `list_segments`                                                               | Rizin's load layout                                                                                      |
| `list_names`, `address_name`                                                  | The symbols, flags and function names rizin recorded; `null` means rizin assigned no name at the address |
| `list_documents`                                                              | The session's selected target                                                                            |
| `read_bytes`                                                                  | Raw bytes of the image                                                                                   |
| `xrefs`, `procedure_callers`, `procedure_callees`                             | Static code/data references rizin resolves; an empty result is not proof of absence                      |
| `set_address_name`, `set_comment`, `comment`                                  | Session-scoped renames and comments (see Scope)                                                          |

Pseudocode and disassembly text for one function admits at most 16 MiB before allocation; larger output is refused, never truncated.

## Check readiness

```bash
rea doctor --provider rizin-ghidra --json
```

The report covers the installation (the executable and its SHA-256), the rizin version, and the rz-ghidra plugin probe. It does not create or modify anything; rizin opens targets read-only, so there is no cache to check. Follow the reported remediation: an unverified release, a missing plugin, or an unsupported host each name the exact correction.

## Scope

- Static analysis of ELF and thin Mach-O images. Universal Mach-O is refused with guidance to open a thin slice; other formats are not admitted.
- Function discovery and decompiler quality depend on rizin's own `aa` pass: undetected or merged entries remain unknown, entry extents are upper bounds, and encodings beyond rizin's string finder can remain undiscovered.
- There is no architecture gate: the embedded Sleigh set covers more architectures than REA has verified, so an undecompilable function surfaces as a per-function error rather than a selection failure.
- `set_address_name` and `set_comment` persist only in this session's rizin process; later reads in the same session see them, and they never modify the file on disk.
- Pseudocode is rizin's reconstruction, never original source. Pseudocode and disassembly are exact rz-ghidra/Rizin text, not comparable as equal or different with another provider's text.
