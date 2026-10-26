import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";

import { expect, it as test } from "vitest";

import { RzGhidraSessionClient } from "../../../../src/rizinghidra/RzGhidraSessionClient.js";
import { fakeRizinStdin, setFakeRizinBehavior } from "./fakeRizin.js";
import { interactiveCalls, run, session } from "./rzGhidraSessionFixture.js";

const it = test.skipIf(process.platform === "win32");

const withClient = async <T>(
  prefix: string,
  behavior: Parameters<typeof session>[1],
  work: (client: RzGhidraSessionClient) => Promise<T>,
): Promise<T> => {
  const fixture = await session(prefix, behavior);
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    return await work(client);
  } finally {
    await client.close();
  }
};

it("health reports the installation identity without starting the console", async () => {
  const fixture = await session("rea-rz-ghidra-op-health-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const health = await run(client, "health");
    expect(health.result).toEqual({
      ready: true,
      rizin: {
        version: "0.9.1",
        verified: true,
        sha256: createHash("sha256")
          .update(await readFile(fixture.rizin))
          .digest("hex"),
        plugin: "rz-ghidra",
      },
    });
    expect(health.provider).toEqual({
      id: "rizin-ghidra",
      name: "rz-ghidra",
      version: "0.9.1",
    });
    expect(health.cachePolicy).toBe("live");
    expect(health.locations).toEqual([
      { kind: "artifact-path", path: fixture.target.path },
    ]);
    // health never spawns the console process.
    expect(await interactiveCalls(fixture.rizin)).toHaveLength(0);
  } finally {
    await client.close();
  }
});

it("list_documents answers the selected target without starting analysis", async () => {
  const fixture = await session("rea-rz-ghidra-op-documents-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const documents = await run(client, "list_documents");
    expect(documents.result).toEqual([fixture.target.path]);
    expect(await interactiveCalls(fixture.rizin)).toHaveLength(0);
    expect(await fakeRizinStdin(fixture.rizin)).toEqual([]);
  } finally {
    await client.close();
  }
});

it("list_segments returns sections with the NULL pseudo-section excluded", async () => {
  const fixture = await session("rea-rz-ghidra-op-segments-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const segments = await run(client, "list_segments");
    expect(segments.result).toEqual([
      {
        name: ".text",
        start: "0x1000",
        end: "0x1100",
        readable: true,
        writable: false,
        executable: true,
        image_base: "0x1000",
      },
      {
        name: ".rodata",
        start: "0x2000",
        end: "0x2100",
        readable: true,
        writable: false,
        executable: false,
        image_base: "0x1000",
      },
    ]);
    // list_segments is bin info: no whole-image `aa` pass on the console.
    expect(await fakeRizinStdin(fixture.rizin)).not.toContain("aa");
  } finally {
    await client.close();
  }
});

it("runs one rizin console per session and answers list_procedures from aflj", async () => {
  const fixture = await session("rea-rz-ghidra-op-procedures-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const procedures = await run(client, "list_procedures");
    expect(procedures.result).toEqual([
      { address: "0x1000", value: "main" },
      { address: "0x1080", value: "helper" },
      { address: "0xffffffffffffe000", value: "big" },
    ]);
    const stdin = await fakeRizinStdin(fixture.rizin);
    expect(stdin).toContain("aa");
    expect(stdin).toContain("aflj");
    expect(stdin[0]).toBe("pdgs"); // console plugin proof before any command
    // One console process serves the whole session.
    expect(await interactiveCalls(fixture.rizin)).toHaveLength(1);
  } finally {
    await client.close();
  }
});

it("search_procedures matches literals and regular expressions against function names", async () => {
  const fixture = await session("rea-rz-ghidra-op-search-procedures-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (await run(client, "search_procedures", { pattern: "ain" })).result,
    ).toEqual([{ address: "0x1000", value: "main" }]);
    expect(
      (await run(client, "search_procedures", { pattern: "^h", mode: "regex" }))
        .result,
    ).toEqual([{ address: "0x1080", value: "helper" }]);
    expect(
      (
        await run(client, "search_procedures", {
          pattern: "ain",
          case_sensitive: false,
        })
      ).result,
    ).toEqual([{ address: "0x1000", value: "main" }]);
    expect(
      await client.execute("search_procedures", { pattern: "" }),
    ).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  } finally {
    await client.close();
  }
});

it("list_strings returns the scanned strings with section and type", async () => {
  const fixture = await session("rea-rz-ghidra-op-strings-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect((await run(client, "list_strings")).result).toEqual([
      {
        address: "0x2000",
        value: "REA fixture prompt",
        length: 18,
        section: ".rodata",
        type: "ascii",
      },
      {
        address: "0x2020",
        value: "SecondMarker",
        length: 12,
        section: ".rodata",
        type: "ascii",
      },
    ]);
    expect(await fakeRizinStdin(fixture.rizin)).toContain("izj");
  } finally {
    await client.close();
  }
});

it("search_strings matches literals and regular expressions against string values", async () => {
  const fixture = await session("rea-rz-ghidra-op-search-strings-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (await run(client, "search_strings", { pattern: "Second" })).result,
    ).toEqual([
      {
        address: "0x2020",
        value: "SecondMarker",
        length: 12,
        section: ".rodata",
        type: "ascii",
      },
    ]);
    expect(
      (
        await run(client, "search_strings", {
          pattern: "Marker$",
          mode: "regex",
        })
      ).result,
    ).toEqual([
      {
        address: "0x2020",
        value: "SecondMarker",
        length: 12,
        section: ".rodata",
        type: "ascii",
      },
    ]);
  } finally {
    await client.close();
  }
});

it("list_names unions function names, symbols and flags, ordered by address", async () => {
  const fixture = await session("rea-rz-ghidra-op-names-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect((await run(client, "list_names")).result).toEqual([
      { address: "0x1000", value: "main" },
      { address: "0x1080", value: "helper" },
      { address: "0x2000", value: "dat_rodata" },
      { address: "0x3000", value: "global_table" },
      { address: "0xffffffffffffe000", value: "big" },
    ]);
  } finally {
    await client.close();
  }
});

it("procedure_address resolves names and explicit addresses", async () => {
  const fixture = await session("rea-rz-ghidra-op-procedure-address-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (await run(client, "procedure_address", { procedure: "main" })).result,
    ).toBe("0x1000");
    expect(
      (await run(client, "procedure_address", { procedure: "0x1080" })).result,
    ).toBe("0x1080");
    // A >2^53 address round-trips as a 0x string, never as a mangled number.
    expect(
      (
        await run(client, "procedure_address", {
          procedure: "0xffffffffffffe000",
        })
      ).result,
    ).toBe("0xffffffffffffe000");
    for (const procedure of ["missing", "0x1044"])
      expect(
        await client.execute("procedure_address", { procedure }),
      ).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError" },
      });
  } finally {
    await client.close();
  }
});

it("address_name resolves function entries, flags and symbols, and null when unnamed", async () => {
  const fixture = await session("rea-rz-ghidra-op-address-name-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (await run(client, "address_name", { address: "0x1000" })).result,
    ).toBe("main");
    expect(
      (await run(client, "address_name", { address: "0x2000" })).result,
    ).toBe("dat_rodata");
    expect(
      (await run(client, "address_name", { address: "0x3000" })).result,
    ).toBe("global_table");
    const unnamed = await run(client, "address_name", { address: "0x9999" });
    expect(unnamed.result).toBeNull();
    expect(unnamed.limitations.at(-1)).toContain("not that no symbol exists");
    expect(
      await client.execute("address_name", { address: "not-hex" }),
    ).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  } finally {
    await client.close();
  }
});

it("procedure_info reports the aflj row for the resolved function", async () => {
  const fixture = await session("rea-rz-ghidra-op-procedure-info-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (await run(client, "procedure_info", { procedure: "main" })).result,
    ).toEqual({
      address: "0x1000",
      name: "main",
      size: 16,
      blocks: 2,
      signature: "int main(void)",
    });
  } finally {
    await client.close();
  }
});

it("procedure_pseudo_code returns the decompiler code string for a function", async () => {
  const fixture = await session("rea-rz-ghidra-op-pseudocode-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (await run(client, "procedure_pseudo_code", { procedure: "main" }))
        .result,
    ).toBe("int main(void)\n{\n  return 0;\n}");
    const stdin = await fakeRizinStdin(fixture.rizin);
    expect(stdin).toContain("s 0x1000");
    expect(stdin).toContain("pdgj");
  } finally {
    await client.close();
  }
});

it("procedure_pseudo_code maps a decompiler failure to a typed unavailable", async () => {
  const fixture = await session("rea-rz-ghidra-op-pseudocode-error-", {
    pdgj: "error",
  });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const result = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        userMessage: expect.stringContaining(
          "Ghidra Decompiler Error: No function at this offset",
        ),
      },
    });
  } finally {
    await client.close();
  }
});

it("procedure_pseudo_code reports an empty pdgj frame as unavailable", async () => {
  const fixture = await session("rea-rz-ghidra-op-pseudocode-empty-", {
    pdgj: "empty",
  });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const result = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        userMessage: expect.stringContaining("returned no pseudocode"),
      },
    });
  } finally {
    await client.close();
  }
});

it("rejects pseudocode above the text capacity instead of truncating it", async () => {
  const fixture = await session("rea-rz-ghidra-op-pseudocode-oversize-", {
    pdgjPadding: 17 * 1024 * 1024,
  });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const result = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCapabilityUnavailableError" },
    });
  } finally {
    await client.close();
  }
}, 30_000);

it("procedure_assembly joins the disassembly lines of the function body", async () => {
  const fixture = await session("rea-rz-ghidra-op-assembly-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (await run(client, "procedure_assembly", { procedure: "main" })).result,
    ).toBe("mov r0q, r1q\nmov r1q, r2q");
    const stdin = await fakeRizinStdin(fixture.rizin);
    expect(stdin).toContain("pDj 16");
  } finally {
    await client.close();
  }
});

it("read_function_instructions returns structured rows without the esil noise", async () => {
  const fixture = await session("rea-rz-ghidra-op-instructions-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (await run(client, "read_function_instructions", { procedure: "main" }))
        .result,
    ).toEqual([
      {
        address: "0x1000",
        disasm: "mov r0q, r1q",
        bytes: "9090909090909090",
        type: "mov",
      },
      {
        address: "0x1008",
        disasm: "mov r1q, r2q",
        bytes: "9090909090909090",
        type: "mov",
      },
    ]);
  } finally {
    await client.close();
  }
});

it("read_bytes returns the hex payload for the addressed range", async () => {
  const fixture = await session("rea-rz-ghidra-op-read-bytes-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (await run(client, "read_bytes", { address: "0x2000", length: 8 }))
        .result,
    ).toBe("0001020304050607");
    expect(await fakeRizinStdin(fixture.rizin)).toContain("pxj 8");
    for (const parameters of [
      { address: "0x2000", length: 0 },
      { address: "not-hex", length: 4 },
      { address: "0x2000", length: "4" },
    ])
      expect(await client.execute("read_bytes", parameters)).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError" },
      });
  } finally {
    await client.close();
  }
});

it("xrefs lists the resolved reference sources to the addressed location", async () => {
  const fixture = await session("rea-rz-ghidra-op-xrefs-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const toHelper = await run(client, "xrefs", { address: "0x1080" });
    expect(toHelper.result).toEqual(["0x1004"]);
    expect(toHelper.referencesTruncated).toBe(false);
    const toMain = await run(client, "xrefs", { address: "0x1000" });
    expect(toMain.result).toEqual(["0x2008"]);
  } finally {
    await client.close();
  }
});

it("procedure_callers and procedure_callees derive call edges from the aflj callrefs", async () => {
  const fixture = await session("rea-rz-ghidra-op-call-relations-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const callers = await run(client, "procedure_callers", {
      procedure: "helper",
    });
    expect(callers.result).toEqual(["0x1000"]);
    expect(callers.relationshipCoverage).toEqual({
      status: "partial",
      limitations: [expect.stringContaining("static code/data references")],
      limited_directions: ["callers"],
    });
    const callees = await run(client, "procedure_callees", {
      procedure: "main",
    });
    expect(callees.result).toEqual(["0x1080"]);
    expect(callees.relationshipCoverage).toMatchObject({
      limited_directions: ["callees"],
    });
    expect(
      (await run(client, "procedure_callees", { procedure: "helper" })).result,
    ).toEqual([]);
  } finally {
    await client.close();
  }
});

it("set_address_name renames a function and the change is visible to later reads", async () => {
  const fixture = await session("rea-rz-ghidra-op-set-name-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (
        await run(client, "set_address_name", {
          address: "0x1000",
          name: "renamed_main",
        })
      ).result,
    ).toBe("renamed_main");
    const stdin = await fakeRizinStdin(fixture.rizin);
    expect(stdin).toContain("afn renamed_main");
    // The rename invalidates the cached function table for later resolves.
    expect((await run(client, "list_procedures")).result).toEqual([
      { address: "0x1000", value: "renamed_main" },
      { address: "0x1080", value: "helper" },
      { address: "0xffffffffffffe000", value: "big" },
    ]);
    expect(
      (await run(client, "procedure_address", { procedure: "renamed_main" }))
        .result,
    ).toBe("0x1000");
  } finally {
    await client.close();
  }
});

it("set_address_name plants a flag at a non-function address", async () => {
  const fixture = await session("rea-rz-ghidra-op-set-name-flag-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (
        await run(client, "set_address_name", {
          address: "0x2000",
          name: "data_alias",
        })
      ).result,
    ).toBe("data_alias");
    const stdin = await fakeRizinStdin(fixture.rizin);
    expect(stdin).toContain("f data_alias");
    expect(stdin).not.toContain("afn data_alias");
    expect(
      (await run(client, "address_name", { address: "0x2000" })).result,
    ).toBe("data_alias");
    for (const parameters of [
      { address: "0x2000", name: "" },
      { address: "0x2000", name: "bad\nname" },
    ])
      expect(
        await client.execute("set_address_name", parameters),
      ).toMatchObject({
        ok: false,
        error: { _tag: "AnalysisInputError" },
      });
  } finally {
    await client.close();
  }
});

it("set_comment stores a comment and the comment operation reads it back", async () => {
  const fixture = await session("rea-rz-ghidra-op-set-comment-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    expect(
      (
        await run(client, "set_comment", {
          address: "0x1000",
          comment: "hello there",
        })
      ).result,
    ).toBe("hello there");
    const stdin = await fakeRizinStdin(fixture.rizin);
    expect(stdin).toContain("CC hello there");
    expect((await run(client, "comment", { address: "0x1000" })).result).toBe(
      "hello there",
    );
    expect(
      (await run(client, "comment", { address: "0x1080" })).result,
    ).toBeNull();
    // An empty comment clears the stored text.
    expect(
      (await run(client, "set_comment", { address: "0x1000", comment: "" }))
        .result,
    ).toBe("");
    expect(
      (await run(client, "comment", { address: "0x1000" })).result,
    ).toBeNull();
    const afterClear = await fakeRizinStdin(fixture.rizin);
    expect(afterClear).toContain("CC-*");
    expect(
      await client.execute("set_comment", { address: "0x1000", comment: 42 }),
    ).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisInputError" },
    });
  } finally {
    await client.close();
  }
});

it("refuses a document other than the session target", async () => {
  const fixture = await session("rea-rz-ghidra-op-document-mismatch-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const result = await client.execute("list_procedures", {
      document: "/other/program",
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisInputError",
        userMessage: expect.stringContaining("analyzes one program"),
      },
    });
    // The matching document parameter is admitted.
    expect(
      (await run(client, "list_procedures", { document: fixture.target.path }))
        .result,
    ).toHaveLength(3);
  } finally {
    await client.close();
  }
});

it("refuses operations rz-ghidra does not declare", async () => {
  const fixture = await session("rea-rz-ghidra-op-foreign-");
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const result = await client.execute("analyze_function", {
      procedure: "main",
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisCapabilityUnavailableError",
        userMessage: expect.stringContaining("needs another provider"),
      },
    });
    expect(await interactiveCalls(fixture.rizin)).toHaveLength(0);
  } finally {
    await client.close();
  }
});

it("keeps answering after a caller cancellation breaks the one-shot console", async () => {
  const fixture = await session("rea-rz-ghidra-op-caller-cancel-", {
    slow: [{ command: "aflj", ms: 400 }],
  });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const caller = new AbortController();
    const cancelled = client.execute(
      "list_procedures",
      {},
      { signal: caller.signal },
    );
    const stdin = () => fakeRizinStdin(fixture.rizin);
    await expect
      .poll(stdin, { timeout: 5_000 })
      .toEqual(expect.arrayContaining(["aflj"]));
    caller.abort();
    expect(await cancelled).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
    // The broken frame interval drops the console; the next request respawns
    // and re-analyzes on a fresh process.
    const respawned = await run(client, "list_procedures");
    expect(respawned.result).toEqual([
      { address: "0x1000", value: "main" },
      { address: "0x1080", value: "helper" },
      { address: "0xffffffffffffe000", value: "big" },
    ]);
    const consoles = await interactiveCalls(fixture.rizin);
    expect(consoles).toHaveLength(2);
    expect(consoles[0]?.pid).not.toBe(consoles[1]?.pid);
  } finally {
    await client.close();
  }
});

it("recovers from a console that exits on init by respawning on the next request", async () => {
  const fixture = await session("rea-rz-ghidra-op-exit-on-init-", {
    exitOnInit: true,
  });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const failed = await client.execute("list_procedures", {});
    expect(failed).toMatchObject({ ok: false });
    await setFakeRizinBehavior(fixture.rizin, {});
    expect((await run(client, "list_procedures")).result).toHaveLength(3);
    const consoles = await interactiveCalls(fixture.rizin);
    expect(consoles).toHaveLength(2);
  } finally {
    await client.close();
  }
});

it("reports a rizin crash mid-session as a typed provider failure and respawns", async () => {
  const fixture = await session("rea-rz-ghidra-op-crash-", {
    crash: { command: "aflj", code: 9 },
  });
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const failed = await client.execute("list_procedures", {});
    expect(failed).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCapabilityUnavailableError" },
    });
    await setFakeRizinBehavior(fixture.rizin, {});
    expect((await run(client, "list_procedures")).result).toHaveLength(3);
  } finally {
    await client.close();
  }
});

it("surfaces a hung console command as a frame timeout naming the owning setting", async () => {
  const fixture = await session(
    "rea-rz-ghidra-op-hang-",
    { pdgj: "hang" },
    { REA_RIZIN_FRAME_TIMEOUT_MS: "300" },
  );
  const client = fixture.open() as RzGhidraSessionClient;
  try {
    const result = await client.execute("procedure_pseudo_code", {
      procedure: "main",
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        _tag: "AnalysisTimeoutError",
        userMessage: expect.stringContaining("REA_RIZIN_FRAME_TIMEOUT_MS"),
      },
    });
  } finally {
    await client.close();
  }
});
