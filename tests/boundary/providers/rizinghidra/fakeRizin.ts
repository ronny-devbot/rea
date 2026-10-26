import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

/** One rizin `aflj` function row; addresses are exact decimal tokens or 0x strings. */
export interface FakeRizinFunction {
  readonly offset: number | string;
  readonly name: string;
  readonly size: number;
  readonly nbbs?: number;
  readonly signature?: string | null;
  readonly callrefs?: readonly {
    readonly from: number | string;
    readonly to: number | string;
    readonly type: string;
  }[];
}

export interface FakeRizinSection {
  readonly name: string;
  readonly vaddr: number | string;
  readonly paddr?: number | string;
  readonly size?: number;
  readonly vsize?: number;
  readonly perm?: string;
  readonly type?: string;
}

export interface FakeRizinStringRow {
  readonly vaddr: number | string;
  readonly string: string;
  readonly paddr?: number | string;
  readonly size?: number;
  readonly length?: number;
  readonly section?: string;
  readonly type?: string;
}

export interface FakeRizinRef {
  readonly from: number | string;
  readonly to: number | string;
  readonly type: string;
}

/** Scripted behavior of the fake `rizin` executable for one test. */
export interface FakeRizinBehavior {
  /** `rizin -v` probe; defaults to the verified 0.9.1 banner. */
  readonly version?: {
    readonly stdout?: string;
    readonly exit?: number;
    /** Block until this file exists, then answer (mid-probe cancellation tests). */
    readonly gate?: string;
    /** Append inert bytes to the fake itself after answering (fingerprint drift). */
    readonly append?: string;
  };
  /** One-shot `pd?` plugin probe. */
  readonly plugin?: "ok" | "missing" | "exit";
  /** Never emit the init NUL (startup-timeout tests). */
  readonly noInitNul?: boolean;
  readonly initDelayMs?: number;
  /** Emit the init NUL, then exit before any command is admitted. */
  readonly exitOnInit?: boolean;
  /** `q` in interactive mode; default exits 0. */
  readonly q?: "exit" | "ignore";
  /**
   * When `q` is ignored, spawn a grandchild that holds the stdout pipe open
   * for this long, so close's output-settle step reports an unproven stop.
   */
  readonly quitHoldoutMs?: number;
  /** Per-command reply delays (serial queue and cancellation tests). */
  readonly slow?: readonly { readonly command: string; readonly ms: number }[];
  /** Delay before every command reply. */
  readonly frameDelayMs?: number;
  readonly aa?: "ok" | "hang";
  readonly aflj?: "ok" | "hang" | "not-json";
  readonly iSj?: "ok" | "hang";
  readonly izj?: "ok" | "hang";
  /** `pdgj` replies; `error` answers the Ghidra decompiler error line. */
  readonly pdgj?: "ok" | "error" | "hang" | "empty";
  /** Extra bytes in the `pdgj` code string (text-capacity tests). */
  readonly pdgjPadding?: number;
  readonly pDj?: "ok" | "hang";
  /** Extra esil bytes per `pDj` row. */
  readonly pdjPadding?: number;
  readonly pxj?: "ok" | "hang";
  readonly xrefs?: "ok" | "hang";
  readonly xrefsFrom?: "ok" | "hang";
  readonly xrefRows?: readonly FakeRizinRef[];
  readonly xrefsFromRows?: readonly FakeRizinRef[];
  /** The named interactive command exits with this code without answering. */
  readonly crash?: { readonly command: string; readonly code?: number };
  readonly functions?: readonly FakeRizinFunction[];
  readonly sections?: readonly FakeRizinSection[];
  readonly strings?: readonly FakeRizinStringRow[];
  readonly flags?: readonly {
    readonly offset: number | string;
    readonly name: string;
    readonly size?: number;
  }[];
  readonly symbols?: readonly {
    readonly vaddr: number | string;
    readonly name: string;
    readonly size?: number;
    readonly type?: string;
  }[];
  readonly imageInfo?: Record<string, unknown>;
  readonly main?: {
    readonly vaddr: number | string;
    readonly paddr?: number | string;
  };
  /** `pdgs` Sleigh language list; empty means the plugin is not loaded. */
  readonly sleigh?: readonly string[];
}

/**
 * The fake reads its behavior from `<script>.json` and appends every
 * invocation (argv, env) to `<script>.calls` and every interactive stdin
 * line to `<script>.stdin`. REA gives rizin children no PATH, so the
 * shebang names this Node binary directly. Interactive mode speaks the
 * verified `-0` protocol: one init NUL, then one NUL-terminated frame per
 * command line.
 */
const SCRIPT = String.raw`
const fs = require("node:fs");
const { spawn } = require("node:child_process");
const behavior = JSON.parse(fs.readFileSync(__filename + ".json", "utf8"));
fs.appendFileSync(__filename + ".calls", JSON.stringify({ pid: process.pid, at: Date.now(), argv: process.argv.slice(2), home: process.env.HOME, noColor: process.env.NO_COLOR, path: process.env.PATH ?? null }) + "\n");
const args = process.argv.slice(2);

const DEFAULT_VERSION = "rizin 0.9.1 @ linux-x86-64\ncommit: c3a90e9226d977f58f4e9c75f78fa6b07afe13c7\n";
const DEFAULT_SLEIGH = ["x86:LE:64:default", "arm:LE:32:code"];
const DEFAULT_FUNCTIONS = [
  { offset: 4096, name: "main", size: 16, nbbs: 2, signature: "int main(void)", callrefs: [{ from: 4100, to: 4224, type: "CALL" }] },
  { offset: 4224, name: "helper", size: 16, nbbs: 1, signature: "int helper(void)", callrefs: [] },
  { offset: "18446744073709543424", name: "big", size: 8, nbbs: 1, signature: null, callrefs: [] }
];
const DEFAULT_SECTIONS = [
  { name: ".text", vaddr: 4096, paddr: 4096, size: 256, vsize: 256, perm: "-r-x", type: "PROGBITS" },
  { name: ".rodata", vaddr: 8192, paddr: 8192, size: 256, vsize: 256, perm: "-r--", type: "PROGBITS" },
  { name: "NULL", vaddr: "18446744073709551615", paddr: "18446744073709551615", size: 0, vsize: 0, perm: "----", type: "NULL" }
];
const DEFAULT_STRINGS = [
  { vaddr: 8192, string: "REA fixture prompt", section: ".rodata", type: "ascii" },
  { vaddr: 8224, string: "SecondMarker", section: ".rodata", type: "ascii" }
];
const DEFAULT_FLAGS = [{ offset: 8192, name: "dat_rodata", size: 1 }];
const DEFAULT_SYMBOLS = [
  { vaddr: 12288, name: "global_table", size: 16, type: "SYMTAB" },
  { vaddr: 0, name: "main", size: 0, type: "SYMTAB" }
];
const DEFAULT_XREF_ROWS = [
  { from: 4100, to: 4224, type: "CALL" },
  { from: 8200, to: 4096, type: "DATA" }
];
const DEFAULT_XREFS_FROM_ROWS = [{ from: 4100, to: 4224, type: "CALL" }];

if (args[0] === "-v") {
  const version = behavior.version ?? { stdout: DEFAULT_VERSION };
  if ("exit" in version) {
    process.stderr.write("version probe failed\n");
    process.exit(version.exit);
  }
  const finish = () => {
    if (version.append) fs.appendFileSync(__filename, version.append);
    process.stdout.write(version.stdout ?? DEFAULT_VERSION);
    process.exit(0);
  };
  if (version.gate) {
    const waiting = setInterval(() => {
      if (!fs.existsSync(version.gate)) return;
      clearInterval(waiting);
      finish();
    }, 10);
  } else finish();
} else if (args[0] === "-q") {
  // One-shot plugin probe: rizin -q -e scr.color=off -c pd?
  if (behavior.plugin === "exit") {
    process.stderr.write("pd? probe failed\n");
    process.exit(2);
  }
  const missing = behavior.plugin === "missing";
  const lines = ["Command help:"];
  if (!missing) lines.push("  | pdg <[addr]> [n]       # Native Ghidra decompiler and Sleigh Disassembler plugin");
  lines.push("  | pd [s] [fmt] [q] [n]   # Disassemble N bytes");
  process.stdout.write(lines.join("\n") + "\n");
  process.exit(0);
} else {
  if (args[0] !== "-N" || args[1] !== "-0" || args[2] === undefined) {
    process.stderr.write("unexpected rizin argv: " + args.join(" ") + "\n");
    process.exit(99);
  }

  // Live model: renames, flags and comments mutate in-process like rizin.
  const functions = (behavior.functions ?? DEFAULT_FUNCTIONS).map((fn) => ({ ...fn }));
  const flags = (behavior.flags ?? DEFAULT_FLAGS).map((flag) => ({ ...flag }));
  const comments = new Map();
  let seek = "0x0";
  // Exact u64 normalization: decimal numbers/strings and 0x-hex all round-trip.
  const norm = (value) => "0x" + BigInt(value).toString(16);
  const out = (text) => process.stdout.write(text + "\0");
  const refRow = (row) => '{"from":' + String(row.from) + ',"to":' + String(row.to) + ',"type":' + JSON.stringify(row.type) + "}";
  const functionRow = (fn) =>
    '{"offset":' + String(fn.offset) +
    ',"name":' + JSON.stringify(fn.name) +
    ',"size":' + String(fn.size) +
    ',"real size":' + String(fn.size) +
    ',"nbbs":' + String(fn.nbbs ?? 1) +
    ',"signature":' + JSON.stringify(fn.signature ?? null) +
    ',"callrefs":[' + (fn.callrefs ?? []).map(refRow).join(",") + "]}" + "";
  const handle = async (line) => {
    fs.appendFileSync(__filename + ".stdin", JSON.stringify(line) + "\n");
    if (behavior.crash && line === behavior.crash.command) process.exit(behavior.crash.code ?? 9);
    const [cmd, ...rest] = line.split(" ");
    const arg = rest.join(" ");
    const slow = (behavior.slow ?? []).find((entry) => entry.command === cmd);
    const delayMs = slow ? slow.ms : (behavior.frameDelayMs ?? 0);
    if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
    const seekBig = () => BigInt("0x" + seek.replace(/^0x/i, ""));
    switch (cmd) {
      case "q":
        if (behavior.q === "ignore") {
          if (behavior.quitHoldoutMs) {
            const until = Date.now() + behavior.quitHoldoutMs;
            fs.appendFileSync(__filename + ".stdin", JSON.stringify("__holdout__:" + until) + "\n");
            const holdout = spawn(process.execPath, ["-e", "setTimeout(() => {}, " + behavior.quitHoldoutMs + ")"], { stdio: ["ignore", "inherit", "ignore"] });
            holdout.unref();
          }
          return;
        }
        out("");
        process.exit(0);
        return;
      case "s":
        if (arg.length > 0) seek = norm(arg);
        out("");
        return;
      case "aa":
        if (behavior.aa === "hang") return;
        out("");
        return;
      case "aflj":
        if (behavior.aflj === "hang") return;
        if (behavior.aflj === "not-json") { out("not a JSON list"); return; }
        out("[" + functions.map(functionRow).join(",") + "]");
        return;
      case "izj":
        if (behavior.izj === "hang") return;
        out("[" + (behavior.strings ?? DEFAULT_STRINGS).map((row) =>
          '{"vaddr":' + String(row.vaddr) + ',"paddr":' + String(row.paddr ?? row.vaddr) +
          ',"size":' + String(row.size ?? 0) + ',"length":' + String(row.length ?? [...row.string].length) +
          ',"section":' + JSON.stringify(row.section ?? null) + ',"type":' + JSON.stringify(row.type ?? "ascii") +
          ',"string":' + JSON.stringify(row.string) + "}") + "]");
        return;
      case "iIj":
        out(JSON.stringify(behavior.imageInfo ?? { arch: "x86", bintype: "elf", bits: 64, endian: "little", baddr: 4194304, binsz: 0, machine: "EM_X86_64", os: "linux" }));
        return;
      case "iSj":
        if (behavior.iSj === "hang") return;
        out("[" + (behavior.sections ?? DEFAULT_SECTIONS).map((row) =>
          '{"name":' + JSON.stringify(row.name) + ',"size":' + String(row.size ?? 0) + ',"vsize":' + String(row.vsize ?? row.size ?? 0) +
          ',"perm":' + JSON.stringify(row.perm ?? "-r--") + ',"type":' + JSON.stringify(row.type ?? "PROGBITS") +
          ',"paddr":' + String(row.paddr ?? row.vaddr) + ',"vaddr":' + String(row.vaddr) + "}") + "]");
        return;
      case "iMj": {
        const main = behavior.main ?? { vaddr: 4096, paddr: 4096 };
        out('{"vaddr":' + String(main.vaddr) + ',"paddr":' + String(main.paddr ?? main.vaddr) + "}");
        return;
      }
      case "flj":
        out("[" + flags.map((row) => '{"offset":' + String(row.offset) + ',"name":' + JSON.stringify(row.name) + ',"size":' + String(row.size ?? 1) + "}") + "]");
        return;
      case "isj":
        out("[" + (behavior.symbols ?? DEFAULT_SYMBOLS).map((row) =>
          '{"vaddr":' + String(row.vaddr) + ',"name":' + JSON.stringify(row.name) + ',"size":' + String(row.size ?? 0) + ',"type":' + JSON.stringify(row.type ?? "SYMTAB") + "}") + "]");
        return;
      case "CClj":
        out("[" + [...comments.entries()].map(([offset, text]) => '{"offset":' + String(offset) + ',"type":"CODE","name":' + JSON.stringify(text) + "}") + "]");
        return;
      case "CC.":
        out(comments.get(seekBig().toString(10)) ?? "");
        return;
      case "CC":
        if (arg.length > 0) comments.set(seekBig().toString(10), arg);
        out("");
        return;
      case "CC-*":
        comments.delete(seekBig().toString(10));
        out("");
        return;
      case "afn": {
        const target = functions.find((fn) => norm(fn.offset) === seek);
        if (target !== undefined && arg.length > 0) target.name = arg;
        out("");
        return;
      }
      case "f":
        if (arg.length > 0) flags.push({ offset: seekBig().toString(10), name: arg.split(" ")[0], size: 1 });
        out("");
        return;
      case "pdgs":
        out((behavior.sleigh ?? DEFAULT_SLEIGH).join("\n"));
        return;
      case "pdgj": {
        if (behavior.pdgj === "hang") return;
        if (behavior.pdgj === "empty") { out(""); return; }
        const target = functions.find((fn) => norm(fn.offset) === seek);
        if (behavior.pdgj === "error" || target === undefined) {
          out("Ghidra Decompiler Error: No function at this offset");
          return;
        }
        const code = "int " + target.name + "(void)\n{\n  return 0;\n}" + "x".repeat(behavior.pdgjPadding ?? 0);
        out(JSON.stringify({ code: code, annotations: [] }));
        return;
      }
      case "pDj": {
        if (behavior.pDj === "hang") return;
        const bytes = Math.max(1, parseInt(arg, 10) || 1);
        const count = Math.max(1, Math.ceil(bytes / 8));
        const base = seekBig();
        const rows = [];
        for (let i = 0; i < count; i++) {
          const offset = base + BigInt(i * 8);
          const disasm = "mov r" + (i % 8) + "q, r" + ((i + 1) % 8) + "q";
          rows.push('{"offset":' + String(offset) + ',"disasm":' + JSON.stringify(disasm) +
            ',"esil":' + JSON.stringify("mov r" + (i % 8) + ", 0x0;" + "x".repeat(behavior.pdjPadding ?? 0)) +
            ',"bytes":"9090909090909090","type":"mov","family":"data"}');
        }
        out("[" + rows.join(",") + "]");
        return;
      }
      case "pxj": {
        if (behavior.pxj === "hang") return;
        const bytes = Math.max(0, parseInt(arg, 10) || 0);
        const base = seekBig();
        out(JSON.stringify(Array.from({ length: bytes }, (_, i) => Number((base + BigInt(i)) % 256n))));
        return;
      }
      case "axtj":
        if (behavior.xrefs === "hang") return;
        out("[" + (behavior.xrefRows ?? DEFAULT_XREF_ROWS).map(refRow).join(",") + "]");
        return;
      case "axfj":
        if (behavior.xrefsFrom === "hang") return;
        out("[" + (behavior.xrefsFromRows ?? DEFAULT_XREFS_FROM_ROWS).map(refRow).join(",") + "]");
        return;
      default:
        out("ERROR: unknown command\n");
    }
  };
  let queue = Promise.resolve();
  if (!behavior.noInitNul) {
    setTimeout(() => {
      out(""); // init frame
      if (behavior.exitOnInit) process.exit(0);
    }, behavior.initDelayMs ?? 30);
  } else {
    setInterval(() => {}, 1000); // stay alive until the startup deadline kills us
  }
  let buffered = "";
  process.stdin.on("data", (chunk) => {
    buffered += chunk.toString("utf8");
    let index;
    while ((index = buffered.indexOf("\n")) >= 0) {
      const line = buffered.slice(0, index);
      buffered = buffered.slice(index + 1);
      if (line.length > 0) queue = queue.then(() => handle(line));
    }
  });
  process.stdin.on("end", () => process.exit(0));
  process.stdin.resume();
}
`;

/** Write a fake `rizin` into a directory and return its path. */
export const writeFakeRizin = async (
  directory: string,
  behavior: FakeRizinBehavior = {},
): Promise<string> => {
  const path = join(directory, "rizin");
  await writeFile(path, `#!${process.execPath}\n${SCRIPT}`, { mode: 0o755 });
  await writeFile(`${path}.json`, JSON.stringify(behavior));
  return path;
};

/** Replace the scripted behavior of an existing fake (new spawns re-read it). */
export const setFakeRizinBehavior = (
  path: string,
  behavior: FakeRizinBehavior,
): Promise<void> => writeFile(`${path}.json`, JSON.stringify(behavior));

/** Invocations the fake recorded, oldest first. */
export const fakeRizinCalls = async (
  path: string,
): Promise<
  readonly {
    readonly pid: number;
    readonly at: number;
    readonly argv: readonly string[];
    readonly home: string;
    readonly noColor: string;
    readonly path: string | null;
  }[]
> => {
  const text = await readFile(`${path}.calls`, "utf8").catch(() => "");
  return text
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as never);
};

/** Interactive command lines the fake read from stdin, oldest first. */
export const fakeRizinStdin = async (
  path: string,
): Promise<readonly string[]> => {
  const text = await readFile(`${path}.stdin`, "utf8").catch(() => "");
  return text
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => JSON.parse(line) as string);
};
