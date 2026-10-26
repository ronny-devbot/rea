import { randomUUID } from "node:crypto";
import type { Logger } from "pino";

import {
  AnalysisCancelledError,
  AnalysisCapabilityUnavailableError,
  AnalysisInputError,
  AnalysisProtocolError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import type { AnalysisErrorOptions } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
  type SpawnedOwnedProviderProcess,
} from "../process/ProviderProcess.js";
import { ABORTED, waitForAbortable } from "../process/AbortablePromise.js";
import { RIZIN_GHIDRA_PROVIDER_IDENTITY } from "./RzGhidraProviderCapabilities.js";

/** Identity of the first-class rizin-ghidra provider (single source: capabilities module). */
const RZ_GHIDRA_PROVIDER_IDENTITY = RIZIN_GHIDRA_PROVIDER_IDENTITY;

const PROVIDER_ID = RZ_GHIDRA_PROVIDER_IDENTITY.id;
const OPEN_OPERATION = "open_rz_ghidra_console";
const SEND_OPERATION = "send_rz_ghidra_command";
const CLOSE_OPERATION = "close_rz_ghidra_console";
const HEALTH_OPERATION = "health_check_rz_ghidra_console";

const DEFAULT_COMMAND_TIMEOUT_MS = 120_000;
const STARTUP_TIMEOUT_MS = 30_000;
const HEALTH_CHECK_TIMEOUT_MS = 10_000;
const CLOSE_GRACE_MS = 3_000;
const CLOSE_KILL_GRACE_MS = 1_000;
const DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024;
const MAX_STDERR_BYTES = 64 * 1024;
const MAX_LATE_OUTPUT_BYTES = 64 * 1024;

/** Every typed failure surfaced from the rz-ghidra console. */
export type RzGhidraConsoleError =
  | AnalysisInputError
  | AnalysisProtocolError
  | AnalysisTimeoutError
  | AnalysisCancelledError
  | AnalysisCapabilityUnavailableError;

/** Outcome of one console shutdown. */
export interface RzGhidraConsoleCloseResult {
  readonly target_state: "closed";
}

export interface RzGhidraConsoleConfig {
  /** Absolute path of the binary to analyze. */
  readonly path: string;
  /** Rizin binary from REA config; falls back to REA_RIZIN_COMMAND, then PATH. */
  readonly rizinCommand?: string;
  /** Per-command deadline in ms; default 120000. */
  readonly defaultTimeoutMs?: number;
  /**
   * Hard transport cap for one NUL frame in bytes; default 16 MiB. Callers
   * whose result budget is larger (e.g. the provider's frame budget) pass it
   * explicitly, otherwise the transport refuses frames the caller would accept.
   */
  readonly maxFrameBytes?: number;
  /** @internal Test seam; production callers should use the 30 s default. */
  readonly startupTimeoutMs?: number;
}

type ConsoleState = "starting" | "ready" | "broken" | "closing" | "closed";

interface FrameWaiter {
  readonly resolve: (frame: string) => void;
  readonly reject: (cause: Error) => void;
}

interface ConsoleExitObservation {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
}

type ConsoleStopResult =
  | { readonly status: "stopped" | "killed" | "already-exited" }
  | { readonly status: "incomplete"; readonly reason: string };

/** Translate only this transport's typed cancellation, preserving opaque/null caller reasons. */
const rzGhidraCancellation = (
  operation: string,
  signal?: AbortSignal,
  cause?: unknown,
  options: AnalysisErrorOptions = {},
): AnalysisCancelledError =>
  new AnalysisCancelledError(operation, {
    ...options,
    cause: signal?.aborted
      ? signal.reason
      : cause instanceof AnalysisCancelledError
        ? cause.cause
        : cause,
  });

const waitForTurn = (
  previous: Promise<void>,
  signal?: AbortSignal,
): Promise<void> => {
  if (signal === undefined) return previous;
  return waitForAbortable(previous, signal).then((outcome) => {
    if (outcome === ABORTED) throw rzGhidraCancellation(SEND_OPERATION, signal);
  });
};

/**
 * Drives one persistent rizin console (`rizin -N -0 <target>`) speaking the
 * NUL-framed `-0` protocol: rizin emits one init NUL at startup and exactly
 * one NUL-terminated frame on stdout per command line read from stdin;
 * terminal junk goes to stderr.
 *
 * Commands run strictly serially and the console is one-shot: a missed
 * deadline or cancellation breaks it, and callers open a new console to
 * continue.
 */
export class RzGhidraConsole {
  readonly #id = randomUUID();
  readonly #path: string;
  readonly #command: string;
  readonly #logger: Logger;
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #defaultTimeoutMs: number;
  readonly #startupTimeoutMs: number;
  readonly #maxFrameBytes: number;

  #state: ConsoleState = "starting";
  #brokenError: RzGhidraConsoleError | undefined;
  #child: SpawnedOwnedProviderProcess | undefined;
  #supervisor: ProviderProcessSupervisor | undefined;
  #exit: ConsoleExitObservation | undefined;
  #initReceived = false;
  #initResolve: (() => void) | undefined;
  #initReject: ((cause: Error) => void) | undefined;
  #frames: string[] = [];
  #frameWaiters: FrameWaiter[] = [];
  #frameChunks: Buffer[] = [];
  #frameBytes = 0;
  #stderrChunks: Buffer[] = [];
  #stderrBytes = 0;
  #stderrTruncated = false;
  #tail: Promise<void> = Promise.resolve();
  #closePromise:
    | Promise<Result<RzGhidraConsoleCloseResult, RzGhidraConsoleError>>
    | undefined;
  #stopAttempt: Promise<ConsoleStopResult> | undefined;

  constructor(
    config: RzGhidraConsoleConfig,
    logger: Logger,
    environment: Readonly<NodeJS.ProcessEnv> = process.env,
  ) {
    this.#path = config.path;
    this.#logger = logger;
    this.#environment = { ...environment };
    // Mirror the REA_GDB_COMMAND / REA_RIZIN_COMMAND resolution: the
    // configured value, then the environment variable, then PATH by bare name.
    this.#command =
      config.rizinCommand ?? this.#environment.REA_RIZIN_COMMAND ?? "rizin";
    this.#defaultTimeoutMs =
      config.defaultTimeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;
    this.#startupTimeoutMs = config.startupTimeoutMs ?? STARTUP_TIMEOUT_MS;
    this.#maxFrameBytes = config.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES;
  }

  /** Observed rizin exit, or undefined while the process is alive. */
  observedExit(): ConsoleExitObservation | undefined {
    return this.#exit === undefined ? undefined : { ...this.#exit };
  }

  /**
   * Bounded tail (last 64 KiB) of rizin stderr for diagnostics. Terminal
   * junk such as `aa` progress output lands here, never on stdout.
   */
  recentStderr(): string {
    return Buffer.concat(this.#stderrChunks, this.#stderrBytes).toString(
      "utf8",
    );
  }

  /** Spawn rizin and wait for its init NUL before admitting commands. */
  async open(
    signal?: AbortSignal,
  ): Promise<Result<null, RzGhidraConsoleError>> {
    if (this.#state !== "starting")
      return err(
        new AnalysisProtocolError(
          `Invalid analysis output for ${OPEN_OPERATION}: console is already started`,
        ),
      );
    if (signal?.aborted)
      return err(rzGhidraCancellation(OPEN_OPERATION, signal));
    let launched: SpawnedOwnedProviderProcess;
    try {
      launched = await spawnOwnedProviderProcess({
        command: this.#command,
        arguments: ["-N", "-0", this.#path],
        hostEnvironment: this.#environment,
        runId: this.#id,
        stdin: "pipe",
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause) {
      if (signal?.aborted)
        return err(rzGhidraCancellation(OPEN_OPERATION, signal, cause));
      this.#state = "closed";
      return err(
        new AnalysisCapabilityUnavailableError(
          PROVIDER_ID,
          OPEN_OPERATION,
          cause instanceof Error ? cause.message : "Unable to start rizin",
          { cause },
        ),
      );
    }
    this.#child = launched;
    this.#supervisor = new ProviderProcessSupervisor(
      { process: launched.process, ownsProcessLifetime: false },
      { captureStdout: false, maxDiagnosticBytes: 0 },
    );
    launched.process.stdout?.on("data", (chunk: Buffer | string) =>
      this.#onStdout(Buffer.from(chunk)),
    );
    launched.process.stderr?.on("data", (chunk: Buffer | string) =>
      this.#onStderr(Buffer.from(chunk)),
    );
    launched.process.stdin?.on("error", (cause: Error) =>
      this.#failProtocol(`rizin stdin stream failed: ${cause.message}`),
    );
    launched.process.stdin?.once("close", () => {
      if (
        this.#state !== "closed" &&
        this.#state !== "broken" &&
        this.#state !== "closing"
      )
        this.#failProtocol("rizin stdin stream closed unexpectedly.");
    });
    launched.process.once(
      "exit",
      (code: number | null, signal: NodeJS.Signals | null) =>
        this.#onExit(code, signal),
    );
    try {
      await this.#waitForInit(signal);
      // Let process and stream lifecycle notifications queued alongside the
      // initial frame run before publishing the console as ready.
      await new Promise<void>((resolve) => setImmediate(resolve));
      if (signal?.aborted) throw rzGhidraCancellation(OPEN_OPERATION, signal);
      if (this.#exit !== undefined) throw new Error(this.#exitMessage());
      if (this.#state !== "starting")
        throw new Error(
          this.#brokenError?.message ??
            "rizin console protocol failed during startup",
        );
      this.#state = "ready";
      this.#logger.debug(
        { id: this.#id, pid: launched.process.pid },
        "rz-ghidra console ready",
      );
      return ok(null);
    } catch (cause) {
      const primary =
        cause instanceof AnalysisTimeoutError ||
        cause instanceof AnalysisCancelledError
          ? cause
          : new AnalysisCapabilityUnavailableError(
              PROVIDER_ID,
              OPEN_OPERATION,
              this.#exit !== undefined
                ? this.#exitMessage()
                : cause instanceof Error
                  ? cause.message
                  : "Unable to start rizin",
              {
                cause,
                capturedOutput: {
                  stdout: "",
                  stderr: this.recentStderr(),
                  truncated: this.#stderrTruncated,
                },
              },
            );
      const stopped = await this.#stopProcess();
      this.#state = "closed";
      this.#logger.warn(
        { id: this.#id, error: primary.message },
        "rz-ghidra console startup failed",
      );
      if (stopped.status !== "incomplete") return err(primary);
      return err(
        new AnalysisCapabilityUnavailableError(
          PROVIDER_ID,
          OPEN_OPERATION,
          `The owned rizin process could not be confirmed stopped: ${stopped.reason}`,
          {
            cause: primary,
            cleanup: { reason: stopped.reason, resources: [this.#id] },
          },
        ),
      );
    }
  }

  /**
   * Run one command and return its raw NUL-delimited response (no trailing
   * NUL). Commands run strictly serially in call order: a command sent while
   * another is in flight is queued until the first completes.
   */
  async send(
    command: string,
    options: {
      readonly signal?: AbortSignal;
      readonly timeoutMs?: number;
    } = {},
  ): Promise<Result<string, RzGhidraConsoleError>> {
    const signal = options.signal;
    const timeoutMs = options.timeoutMs ?? this.#defaultTimeoutMs;
    if (command.length === 0 || /[\n\u0000]/u.test(command))
      return err(
        new AnalysisInputError(SEND_OPERATION, {
          userMessage:
            "A rizin command must be non-empty and must not contain newline or NUL bytes.",
        }),
      );
    if (this.#state !== "ready") {
      if (this.#state === "broken" && this.#brokenError !== undefined)
        return err(this.#brokenError);
      return err(
        new AnalysisInputError(SEND_OPERATION, {
          userMessage: `The rz-ghidra console is not ready (state: ${this.#state}).`,
        }),
      );
    }
    if (signal?.aborted)
      return err(rzGhidraCancellation(SEND_OPERATION, signal));
    const previous = this.#tail;
    let release!: () => void;
    this.#tail = new Promise<void>((resolve) => {
      release = resolve;
    });
    let acquired = false;
    try {
      await waitForTurn(previous, signal);
      acquired = true;
      if (signal?.aborted) throw rzGhidraCancellation(SEND_OPERATION, signal);
      if (this.#state !== "ready")
        throw this.#state === "broken" && this.#brokenError !== undefined
          ? this.#brokenError
          : new AnalysisInputError(SEND_OPERATION);
      // One frame per command line: unsolicited frames mean the NUL stream is
      // already misaligned and no response can be attributed safely.
      if (this.#frames.length > 0 || this.#frameBytes > 0)
        throw this.#failProtocol(
          "Unsolicited rizin frames arrived before a command; command output can no longer be safely correlated.",
        );
      const stdin = this.#child?.process.stdin;
      if (
        stdin === null ||
        stdin === undefined ||
        stdin.destroyed ||
        !stdin.writable
      )
        throw new Error("rizin stdin is closed.");
      try {
        stdin.write(`${command}\n`, "utf8", (cause?: Error | null) => {
          if (cause !== undefined && cause !== null)
            this.#failProtocol(`rizin stdin write failed: ${cause.message}`);
        });
      } catch (cause) {
        throw this.#failProtocol(
          `rizin stdin write failed: ${cause instanceof Error ? cause.message : "unknown error"}`,
        );
      }
      const frame = await this.#waitForFrame(timeoutMs, signal);
      if (signal?.aborted) throw rzGhidraCancellation(SEND_OPERATION, signal);
      return ok(frame);
    } catch (cause) {
      const partial = this.#takeBufferedFrame();
      const captured = {
        stdout: partial,
        stderr: this.recentStderr(),
        truncated: this.#stderrTruncated,
      };
      if (signal?.aborted || cause instanceof AnalysisCancelledError) {
        // No re-sync: rizin may still be emitting the cancelled command's
        // frame, and a late frame would be consumed as the next command's
        // response, silently corrupting it. The session is one-shot from a
        // broken interval onward.
        const error = rzGhidraCancellation(SEND_OPERATION, signal, cause, {
          capturedOutput: captured,
        });
        this.#markBroken(error);
        return err(error);
      }
      if (cause instanceof AnalysisTimeoutError) {
        // No re-sync, same reason as cancellation: the late frame of the
        // timed-out command would corrupt the next response.
        const error = new AnalysisTimeoutError(SEND_OPERATION, timeoutMs, {
          cause,
          capturedOutput: captured,
        });
        this.#markBroken(error);
        return err(error);
      }
      if (cause instanceof AnalysisError) {
        // State recheck, unsolicited-frame and stdin-failure paths already
        // produced and attributed a member of this transport's error union.
        const error = cause as RzGhidraConsoleError;
        this.#markBroken(error);
        return err(error);
      }
      const error = new AnalysisCapabilityUnavailableError(
        PROVIDER_ID,
        SEND_OPERATION,
        this.#exit !== undefined
          ? `rizin exited before completing the command (${this.#exitMessage()})`
          : cause instanceof Error
            ? cause.message
            : String(cause),
        { cause, capturedOutput: captured },
      );
      this.#markBroken(error);
      return err(error);
    } finally {
      if (acquired) release();
      else void previous.then(() => release());
    }
  }

  /**
   * Prove the rz-ghidra plugin is loaded: `pdgs` lists the Sleigh languages
   * the embedded Ghidra decompiler contributes, so non-empty output proves
   * the plugin. Returns the parsed language list (arch:endian:bits:variant).
   */
  async healthCheck(): Promise<Result<string[], RzGhidraConsoleError>> {
    const result = await this.send("pdgs", {
      timeoutMs: HEALTH_CHECK_TIMEOUT_MS,
    });
    if (!result.ok) return result;
    const languages = result.value
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0);
    if (languages.length === 0)
      return err(
        new AnalysisCapabilityUnavailableError(
          PROVIDER_ID,
          HEALTH_OPERATION,
          "pdgs returned no Sleigh languages; the rz-ghidra plugin is not loaded",
        ),
      );
    return ok(languages);
  }

  /**
   * Shut the console down: ask rizin to quit (`q`), wait up to 3 s for a
   * graceful exit, then SIGKILL and reap. Idempotent: concurrent calls share
   * one attempt, a completed close is cached, and a failed (retained) close
   * may be retried.
   */
  close(): Promise<Result<RzGhidraConsoleCloseResult, RzGhidraConsoleError>> {
    this.#closePromise ??= this.#close().then((result) => {
      if (!result.ok) this.#closePromise = undefined;
      return result;
    });
    return this.#closePromise;
  }

  async #close(): Promise<
    Result<RzGhidraConsoleCloseResult, RzGhidraConsoleError>
  > {
    if (this.#state === "closed") return ok({ target_state: "closed" });
    this.#state = "closing";
    const stopped = await this.#stopProcess();
    if (stopped.status === "incomplete") {
      // Retained failure: the console stays broken so close() can retry.
      this.#state = "broken";
      return err(
        new AnalysisCapabilityUnavailableError(
          PROVIDER_ID,
          CLOSE_OPERATION,
          `The owned rizin process could not be confirmed stopped: ${stopped.reason}`,
          {
            cleanup: { reason: stopped.reason, resources: [this.#id] },
          },
        ),
      );
    }
    this.#state = "closed";
    this.#logger.debug(
      {
        id: this.#id,
        status: stopped.status,
        exit: this.observedExit() ?? null,
      },
      "rz-ghidra console closed",
    );
    return ok({ target_state: "closed" });
  }

  /** Shared stop attempt; an incomplete result clears it so cleanup can retry. */
  #stopProcess(): Promise<ConsoleStopResult> {
    this.#stopAttempt ??= this.#doStop().then((result) => {
      if (result.status === "incomplete") this.#stopAttempt = undefined;
      return result;
    });
    return this.#stopAttempt;
  }

  async #doStop(): Promise<ConsoleStopResult> {
    const child = this.#child;
    const supervisor = this.#supervisor;
    if (child === undefined || supervisor === undefined)
      return { status: "already-exited" };
    if (this.#exit === undefined) {
      const stdin = child.process.stdin;
      if (
        stdin !== null &&
        stdin !== undefined &&
        !stdin.destroyed &&
        stdin.writable
      ) {
        try {
          stdin.write("q\n");
        } catch {
          // A dead pipe falls through to the SIGKILL fallback below.
        }
      }
    }
    const exited =
      this.#exit !== undefined ||
      (await supervisor.waitForExit(CLOSE_GRACE_MS));
    const result: ConsoleStopResult = exited
      ? { status: "stopped" }
      : await (async () => {
          try {
            child.process.kill("SIGKILL");
          } catch {
            // kill() on an already-gone process reports nothing useful.
          }
          return (await supervisor.waitForExit(CLOSE_KILL_GRACE_MS))
            ? { status: "killed" as const }
            : {
                status: "incomplete" as const,
                reason: "the owned rizin process did not exit after SIGKILL",
              };
        })();
    if (result.status !== "incomplete") {
      // Exit proves process lifetime only. Settle the inherited pipes before
      // detaching capture, like owned-debugger cleanup.
      try {
        supervisor.limitAdditionalOutputBytes(MAX_LATE_OUTPUT_BYTES);
        if (!(await supervisor.waitForOutputClose(1_000)))
          return {
            status: "incomplete",
            reason:
              "the owned rizin process exited but its output streams did not settle within 1000 ms",
          };
      } catch (cause) {
        return {
          status: "incomplete",
          reason: `the owned rizin process output streams could not be settled: ${cause instanceof Error ? cause.message : String(cause)}`,
        };
      }
      supervisor.unrefOutputStreams();
      supervisor.dispose();
    }
    return result;
  }

  #onStdout(chunk: Buffer): void {
    let offset = 0;
    while (offset < chunk.length) {
      const boundary = chunk.indexOf(0, offset);
      const end = boundary < 0 ? chunk.length : boundary;
      const piece = chunk.subarray(offset, end);
      if (this.#frameBytes + piece.length > this.#maxFrameBytes) {
        this.#failProtocol(
          `rizin emitted a NUL frame exceeding the ${String(this.#maxFrameBytes)} byte protocol limit`,
        );
        return;
      }
      if (piece.length > 0) {
        this.#frameChunks.push(Buffer.from(piece));
        this.#frameBytes += piece.length;
      }
      if (boundary < 0) return;
      this.#deliverFrame(this.#takeBufferedFrame());
      offset = boundary + 1;
    }
  }

  #onStderr(chunk: Buffer): void {
    if (chunk.length === 0) return;
    this.#stderrChunks.push(chunk);
    this.#stderrBytes += chunk.length;
    while (this.#stderrBytes > MAX_STDERR_BYTES) {
      const head = this.#stderrChunks[0];
      if (head === undefined) return;
      const excess = this.#stderrBytes - MAX_STDERR_BYTES;
      if (head.length <= excess) {
        this.#stderrChunks.shift();
        this.#stderrBytes -= head.length;
      } else {
        this.#stderrChunks[0] = head.subarray(excess);
        this.#stderrBytes -= excess;
        this.#stderrTruncated = true;
      }
    }
  }

  /** The first NUL after spawn is the init delimiter; later frames are command responses. */
  #deliverFrame(frame: string): void {
    if (!this.#initReceived) {
      if (this.#state === "closed" || this.#state === "broken") return;
      this.#initReceived = true;
      const resolve = this.#initResolve;
      this.#initResolve = undefined;
      this.#initReject = undefined;
      resolve?.();
      return;
    }
    if (this.#state === "closed" || this.#state === "broken") return; // Late frames from a broken interval are never re-attributed.
    const waiter = this.#frameWaiters.shift();
    if (waiter !== undefined) {
      waiter.resolve(frame);
      return;
    }
    this.#frames.push(frame);
  }

  #onExit(code: number | null, signal: NodeJS.Signals | null): void {
    if (this.#exit !== undefined) return;
    this.#exit = { code, signal };
    this.#initReject?.(new Error(this.#exitMessage()));
    this.#initReject = undefined;
    this.#initResolve = undefined;
    for (const waiter of this.#frameWaiters)
      waiter.reject(new Error(this.#exitMessage()));
    this.#frameWaiters = [];
    if (this.#state === "ready")
      this.#markBroken(
        new AnalysisCapabilityUnavailableError(
          PROVIDER_ID,
          SEND_OPERATION,
          `rizin exited before completing the command (${this.#exitMessage()})`,
        ),
      );
  }

  #exitMessage(): string {
    const { code, signal } = this.#exit ?? { code: null, signal: null };
    return `code ${String(code)}, signal ${String(signal)}`;
  }

  #waitForInit(signal: AbortSignal | undefined): Promise<void> {
    if (this.#initReceived) return Promise.resolve();
    if (this.#exit !== undefined)
      return Promise.reject(new Error(this.#exitMessage()));
    return new Promise((resolve, reject) => {
      const cleanup = (): void => {
        this.#initResolve = undefined;
        this.#initReject = undefined;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
      };
      const onAbort = (): void => {
        cleanup();
        reject(rzGhidraCancellation(OPEN_OPERATION, signal));
      };
      const timer = setTimeout(() => {
        cleanup();
        reject(
          new AnalysisTimeoutError(OPEN_OPERATION, this.#startupTimeoutMs),
        );
      }, this.#startupTimeoutMs);
      this.#initResolve = (): void => {
        cleanup();
        resolve();
      };
      this.#initReject = (cause: Error): void => {
        cleanup();
        reject(cause);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) onAbort();
    });
  }

  #waitForFrame(timeoutMs: number, signal?: AbortSignal): Promise<string> {
    if (signal?.aborted)
      return Promise.reject(rzGhidraCancellation(SEND_OPERATION, signal));
    const queued = this.#frames.shift();
    if (queued !== undefined) return Promise.resolve(queued);
    if (this.#exit !== undefined)
      return Promise.reject(new Error(this.#exitMessage()));
    return new Promise((resolve, reject) => {
      // Settlement removes all three trigger paths before resolving or rejecting.
      const cleanup = (): void => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        const index = this.#frameWaiters.indexOf(waiter);
        if (index >= 0) this.#frameWaiters.splice(index, 1);
      };
      const onAbort = (): void => {
        cleanup();
        reject(rzGhidraCancellation(SEND_OPERATION, signal));
      };
      const timer = setTimeout(() => {
        cleanup();
        reject(new AnalysisTimeoutError(SEND_OPERATION, timeoutMs));
      }, timeoutMs);
      const waiter: FrameWaiter = {
        resolve: (frame: string): void => {
          cleanup();
          resolve(frame);
        },
        reject: (cause: Error): void => {
          cleanup();
          reject(cause);
        },
      };
      this.#frameWaiters.push(waiter);
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) onAbort();
    });
  }

  #takeBufferedFrame(): string {
    const bytes = Buffer.concat(this.#frameChunks, this.#frameBytes);
    this.#frameChunks = [];
    this.#frameBytes = 0;
    return bytes.toString("utf8");
  }

  #failProtocol(message: string): RzGhidraConsoleError {
    const partial = this.#takeBufferedFrame();
    const error = new AnalysisCapabilityUnavailableError(
      PROVIDER_ID,
      SEND_OPERATION,
      message,
      {
        capturedOutput: {
          stdout: partial,
          stderr: this.recentStderr(),
          truncated: this.#stderrTruncated,
        },
      },
    );
    this.#initReject?.(new Error(message));
    this.#initReject = undefined;
    this.#initResolve = undefined;
    for (const waiter of this.#frameWaiters) waiter.reject(new Error(message));
    this.#frameWaiters = [];
    this.#frames.length = 0;
    this.#markBroken(error);
    return error;
  }

  #markBroken(error: RzGhidraConsoleError): void {
    if (this.#state === "broken" || this.#state === "closed") return;
    this.#state = "broken";
    this.#brokenError = error;
    // Discard the in-flight partial frame: a late frame from the broken
    // interval would corrupt the next response, so the session is one-shot.
    this.#frameChunks = [];
    this.#frameBytes = 0;
    this.#logger.warn(
      { id: this.#id, error: error.message },
      "rz-ghidra console broken",
    );
  }
}
