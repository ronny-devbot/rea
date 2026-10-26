import { AnalysisCleanupLease } from "../artifacts/AnalysisCleanupLease.js";
import { ArtifactReaderFailure } from "../artifacts/ArtifactReader.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import {
  createAnalysisExecution,
  type AnalysisClient,
  type AnalysisExecution,
  type AnalysisOperation,
  type ExecutionOptions,
  type RetainedResourceScope,
} from "../application/AnalysisProvider.js";
import type { RegexMatchingDeadline } from "../config/regexMatchingDeadline.js";
import type { RegexWorkerHeapRequest } from "../config/regexWorkerHeapRequest.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import {
  AnalysisCapabilityUnavailableError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisTimeoutError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisProfileCommitment } from "../domain/analysisProfile.js";
import {
  analysisSearchPredicate,
  analysisSearchQuerySchema,
} from "../domain/analysisSearch.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import type { EvidenceLocation } from "../domain/evidence.js";
import { analysisInputErrorFromIssues } from "../domain/inputIssueProjection.js";
import type { JsonValue } from "../domain/jsonValue.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import type { RelationshipCoverage } from "../domain/relationshipCoverage.js";
import { err, ok, type Result } from "../domain/result.js";
import type { ProviderOperationHealth } from "../domain/providerOperationHealth.js";
import { RegularFileCleanupFailure } from "../filesystem/OwnedRegularFile.js";
import { silentLogger } from "../logger.js";
import { matchRegexValues } from "../process/RegexMatcher.js";
import { SharedStartupAttempt } from "../process/SharedStartupAttempt.js";
import {
  rzGhidraAnalysisDeadline,
  rzGhidraFrameDeadline,
  type RzGhidraDeadline,
} from "./RzGhidraConfiguration.js";
import { normalizeRzGhidraAddress } from "./RzGhidraAddress.js";
import { RzGhidraConsole } from "./RzGhidraConsole.js";
import { parseRzGhidraJson } from "./RzGhidraJson.js";
import {
  RIZIN_GHIDRA_DIAGNOSTIC_BYTES,
  RIZIN_GHIDRA_FRAME_BYTES,
  RIZIN_GHIDRA_TEXT_BYTES,
} from "./RzGhidraLimits.js";
import {
  createRzGhidraResourceScope,
  inspectRzGhidraInstallation,
  rzGhidraChildEnvironment,
  rzGhidraRetainedResourceCleanupError,
  type RzGhidraInstallation,
  type RzGhidraProcessLauncher,
} from "./RzGhidraInstallation.js";
import {
  isRzGhidraOperation,
  rzGhidraLimitations,
  RZ_XREF_LIMITATION,
  type RzGhidraOperation,
} from "./RzGhidraProviderCapabilities.js";
import { rzGhidraQueryFailureForCaller } from "./RzGhidraQueryErrors.js";
import {
  RIZIN_GHIDRA_PROVIDER_ID,
  RZ_GHIDRA_PROVIDER_NAME,
} from "./RzGhidraRelease.js";
import { rzGhidraUnavailable } from "./RzGhidraUnavailable.js";

/** One analyzed function as rizin's `aflj` reports it, addresses normalized. */
interface RzGhidraFunction {
  readonly address: string;
  readonly name: string;
  readonly size: number;
  readonly blocks: number | null;
  readonly signature: string | null;
  readonly callrefs: readonly {
    readonly from: string;
    readonly to: string;
    readonly type: string;
  }[];
}

interface RzGhidraFunctionIndex {
  readonly functions: readonly RzGhidraFunction[];
  readonly byAddress: ReadonlyMap<string, RzGhidraFunction>;
  readonly byName: ReadonlyMap<string, readonly RzGhidraFunction[]>;
}

/** One rizin `izj` string, addresses normalized. Object-literal type (not an interface) so it stays assignable to JsonValue. */
type RzGhidraStringRow = {
  readonly address: string;
  readonly value: string;
  readonly length?: number;
  readonly section?: string;
  readonly type?: string;
};

/** One rizin `pDj` instruction, minus the esil noise. Object-literal type (not an interface) so it stays assignable to JsonValue. */
type RzGhidraInstructionRow = {
  readonly address: string;
  readonly disasm: string;
  readonly bytes?: string;
  readonly type?: string;
};

/** One normalized answer. Results are inline JSON; rz-ghidra retains no files. */
interface Answer {
  readonly result: JsonValue;
  readonly locations: readonly EvidenceLocation[];
  readonly limitations: readonly string[];
  readonly relationshipCoverage?: RelationshipCoverage;
  readonly referencesTruncated?: boolean;
}

/** Decimal u64 fields rizin emits, normalized to 0x before double rounding. */
const ADDRESS_KEYS = new Set([
  "offset",
  "vaddr",
  "paddr",
  "from",
  "to",
  "start",
  "end",
]);

const cancelled = (signal: AbortSignal | undefined): boolean =>
  signal?.aborted === true;

const message = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

/**
 * One rz-ghidra analysis session for one target.
 *
 * Drives one persistent rizin process (`rizin -N -0 <path>`) over the
 * NUL-framed `-0` protocol: a serial command queue, the whole-image `aa`
 * pass once per process, and session-scoped edits (renames, comments) that
 * live only in that process. The console is one-shot: a broken frame
 * interval drops it, and the next request respawns and re-analyzes.
 */
export class RzGhidraSessionClient implements AnalysisClient {
  readonly #target: BinaryTarget;
  readonly #profile: AnalysisProfileCommitment | undefined;
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #analysisTimeoutMs: number;
  readonly #frameTimeoutMs: number;
  readonly #deadline: RegexMatchingDeadline;
  readonly #heapRequest: RegexWorkerHeapRequest;
  readonly #launcher: RzGhidraProcessLauncher | undefined;
  readonly #resourceScope = new ArtifactResourceScope();
  /** Owns background work: aborting it cancels this session's console and analysis. */
  readonly #session = new AbortController();
  /** Requests and shared producers retain their resources until they settle. */
  readonly #active = new Set<Promise<unknown>>();
  #installation:
    | SharedStartupAttempt<Result<RzGhidraInstallation, AnalysisError>>
    | undefined;
  #console:
    | SharedStartupAttempt<Result<RzGhidraConsole, AnalysisError>>
    | undefined;
  #analyzed:
    | SharedStartupAttempt<Result<RzGhidraConsole, AnalysisError>>
    | undefined;
  /** Every spawned console; close stops each one and retries retained failures. */
  readonly #consoles: RzGhidraConsole[] = [];
  #functions: RzGhidraFunctionIndex | undefined;
  /** Set once close starts; new requests are refused from then on. */
  #closing = false;
  /** Set only when close has released every owned resource. */
  #closed = false;

  constructor(
    target: BinaryTarget,
    profile: AnalysisProfileCommitment | undefined,
    dependencies: {
      readonly environment: Readonly<NodeJS.ProcessEnv>;
      readonly analysisTimeoutMs: number;
      readonly frameTimeoutMs: number;
      readonly deadline: RegexMatchingDeadline;
      readonly heapRequest: RegexWorkerHeapRequest;
      readonly launcher?: RzGhidraProcessLauncher;
    },
  ) {
    this.#target = target;
    this.#profile = profile;
    this.#environment = dependencies.environment;
    this.#analysisTimeoutMs = dependencies.analysisTimeoutMs;
    this.#frameTimeoutMs = dependencies.frameTimeoutMs;
    this.#deadline = dependencies.deadline;
    this.#heapRequest = dependencies.heapRequest;
    this.#launcher = dependencies.launcher;
  }

  async execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions = {},
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (this.#closing)
      return err(
        rzGhidraUnavailable(operation, "This rizin-ghidra session is closed."),
      );
    return this.#own(
      this.#execute(operation, parameters, {
        ...options,
        signal:
          options.signal === undefined
            ? this.#session.signal
            : AbortSignal.any([this.#session.signal, options.signal]),
      }),
    );
  }

  /** Serial queue depth plus console readiness, for the session's health gate. */
  operationHealthSnapshot(): ProviderOperationHealth {
    const attempt = this.#console;
    const consoleReady =
      attempt === undefined ||
      (attempt.settled &&
        attempt.settlement.status === "completed" &&
        attempt.settlement.value.ok);
    return {
      state: this.#active.size === 0 && consoleReady ? "idle" : "busy",
      stage: null,
      retryAction: null,
      exitCode: null,
      requests: [],
    };
  }

  /**
   * Release everything this session owns. A failed close keeps reporting its
   * failure, and each later call retries the cleanup that remains.
   */
  async close(): Promise<Result<null, AnalysisError>> {
    if (this.#closed) return ok(null);
    if (!this.#closing) {
      this.#closing = true;
      this.#session.abort();
      this.#installation?.close();
      this.#console?.close();
      this.#analyzed?.close();
    }
    while (this.#active.size > 0) await Promise.allSettled(this.#active);
    const failures: ProviderCleanupError[] = [];
    for (const console of this.#consoles) {
      const closed = await console.close();
      if (!closed.ok)
        failures.push(
          new ProviderCleanupError(
            RIZIN_GHIDRA_PROVIDER_ID,
            closed.error.cleanupResources ?? [RIZIN_GHIDRA_PROVIDER_ID],
            { reason: closed.error.userMessage ?? closed.error.message },
            { cause: closed.error, operation: "close_binary" },
          ),
        );
    }
    try {
      await this.#resourceScope.close();
    } catch (cause: unknown) {
      if (!(cause instanceof ArtifactReaderFailure)) throw cause;
      const observation = ArtifactReaderFailure.cleanupObservation(
        cause,
        "rz-ghidra provider artifact",
      );
      failures.push(
        new ProviderCleanupError(
          RIZIN_GHIDRA_PROVIDER_ID,
          observation.resources,
          { reason: observation.reason },
          { cause, operation: "close_binary" },
        ),
      );
    }
    if (failures.length > 0)
      return err(
        new ProviderCleanupError(
          RIZIN_GHIDRA_PROVIDER_ID,
          failures.flatMap((failed) => failed.cleanupResources),
          {
            reason: failures
              .map((failed) =>
                String(failed.diagnostics?.["reason"] ?? failed.message),
              )
              .join("; "),
          },
          {
            cause: new AggregateError(
              failures,
              "rz-ghidra session cleanup remains incomplete",
            ),
            operation: "close_binary",
          },
        ).bindCleanupDependencies(failures),
      );
    this.#closed = true;
    return ok(null);
  }

  #own<T>(work: Promise<T>): Promise<T> {
    this.#active.add(work);
    const release = () => this.#active.delete(work);
    void work.then(release, release);
    return work;
  }

  async #execute(
    operation: AnalysisOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    options: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    if (cancelled(options.signal))
      return err(
        new AnalysisCancelledError(operation, {
          cause: options.signal?.reason,
        }),
      );
    if (operation !== "health" && !isRzGhidraOperation(operation))
      return err(
        rzGhidraUnavailable(
          operation,
          "rz-ghidra answers procedure, string, segment and name queries, pseudocode, disassembly, bytes, references and session edits; this operation needs another provider.",
        ),
      );
    const document = parameters.document;
    if (document !== undefined && document !== this.#target.path)
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage:
              "A rizin-ghidra session analyzes one program; omit document or pass the selected target path.",
          },
          [
            {
              path: ["document"],
              reason: "invalid_value",
              expected: this.#target.path,
            },
          ],
        ),
      );
    const installation = await this.#ensureInstallation(
      operation,
      options.signal,
    );
    if (!installation.ok) return installation;
    try {
      if (operation === "health")
        return ok(
          this.#execution([], installation.value, {
            result: {
              ready: true,
              rizin: {
                version: installation.value.version,
                verified: installation.value.verified,
                sha256: installation.value.sha256,
                plugin: "rz-ghidra",
              },
            },
            locations: [],
            limitations: [],
          }),
        );
      const limitations = rzGhidraLimitations(
        operation,
        this.#deadline,
        this.#heapRequest,
      );
      if (operation === "list_documents")
        return ok(
          this.#execution(limitations, installation.value, {
            result: [this.#target.path],
            locations: [],
            limitations: [],
          }),
        );
      let session = await this.#ensureConsole(
        installation.value,
        operation,
        options.signal,
      );
      if (!session.ok) return session;
      if (this.#needsAnalysis(operation))
        session = await this.#ensureAnalysis(
          installation.value,
          operation,
          options.signal,
        );
      if (!session.ok) return session;
      const answer = await this.#answer(
        operation,
        parameters,
        installation.value,
        session.value,
        options,
      );
      if (!answer.ok)
        return err(rzGhidraQueryFailureForCaller(answer.error, operation));
      if (cancelled(options.signal))
        return err(
          new AnalysisCancelledError(operation, {
            cause: options.signal?.reason,
          }),
        );
      return ok(this.#execution(limitations, installation.value, answer.value));
    } catch (cause: unknown) {
      if (cancelled(options.signal))
        return err(new AnalysisCancelledError(operation, { cause }));
      return err(this.#failure(operation, cause));
    }
  }

  #failure(operation: string, cause: unknown): AnalysisError {
    if (cause instanceof AnalysisError) return cause;
    return new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
      cause,
      userMessage: `rz-ghidra ${operation} failed: ${message(cause)}`,
    });
  }

  #execution(
    operationLimitations: readonly string[],
    installation: RzGhidraInstallation,
    answer: Answer,
  ): AnalysisExecution {
    return createAnalysisExecution(
      answer.result,
      {
        id: RIZIN_GHIDRA_PROVIDER_ID,
        name: RZ_GHIDRA_PROVIDER_NAME,
        version: installation.version,
      },
      {
        // The rizin process is live: renames, comments and the `aa` state
        // mutate in place, so a replayed observation would be wrong.
        cachePolicy: "live",
        limitations: [...operationLimitations, ...answer.limitations],
        locations: [
          { kind: "artifact-path", path: this.#target.path },
          ...answer.locations,
        ],
        ...(answer.referencesTruncated === undefined
          ? {}
          : { referencesTruncated: answer.referencesTruncated }),
        ...(answer.relationshipCoverage === undefined
          ? {}
          : { relationshipCoverage: answer.relationshipCoverage }),
        ...(this.#profile === undefined
          ? {}
          : { analysisProfile: this.#profile }),
      },
    );
  }

  /** Operations that consume the `aa`-built function and reference model. */
  #needsAnalysis(operation: RzGhidraOperation): boolean {
    return (
      operation !== "list_segments" &&
      operation !== "read_bytes" &&
      operation !== "set_comment" &&
      operation !== "comment"
    );
  }

  /** One installation producer; only the final departing caller stops it. */
  async #ensureInstallation(
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<RzGhidraInstallation, AnalysisError>> {
    let attempt = this.#installation;
    if (attempt === undefined) {
      attempt = new SharedStartupAttempt(
        (ownerSignal) => this.#own(this.#inspectInstallation(ownerSignal)),
        this.#session.signal,
      );
      const owned = attempt;
      this.#installation = owned;
      void owned.promise.then((result) => {
        // A proven cancellation has no reusable installation result. Its
        // complete cleanup precedes replacement; physical failures stay cached.
        if (
          this.#installation === owned &&
          owned.signal.aborted &&
          (result.ok ||
            (result.error instanceof AnalysisCancelledError &&
              !result.error.cleanupIncomplete))
        )
          this.#installation = undefined;
      });
    }
    const waited = await attempt.wait(signal);
    if (waited.status === "cancelled")
      return err(
        new AnalysisCancelledError(operation, { cause: signal?.reason }),
      );
    if (!waited.value.ok) {
      // A fresh caller can arrive while the previous final waiter joins stop.
      // Retry only proven cancellation, never an authored physical failure.
      if (
        !signal?.aborted &&
        attempt.signal.aborted &&
        waited.value.error instanceof AnalysisCancelledError &&
        !waited.value.error.cleanupIncomplete
      )
        return this.#ensureInstallation(operation, signal);
      return err(rzGhidraQueryFailureForCaller(waited.value.error, operation));
    }
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    return waited.value;
  }

  /**
   * Fingerprint, version-probe and plugin-probe the configured executable
   * (the provider already did this at open; the session re-verifies so a
   * swapped binary is refused), then check the profile-committed digest.
   */
  async #inspectInstallation(
    signal: AbortSignal,
  ): Promise<Result<RzGhidraInstallation, AnalysisError>> {
    const parentResourceScope: RetainedResourceScope = {
      retain: (owner, resource) =>
        this.#resourceScope.retain({
          kind: "lease",
          resource,
          lease: AnalysisCleanupLease.forCloseOwner(owner, resource),
        }),
      run: <T>(operation: () => Promise<T>) =>
        this.#resourceScope.run(operation),
    };
    const rzResources = createRzGhidraResourceScope(parentResourceScope);
    try {
      const inspected = await inspectRzGhidraInstallation(this.#environment, {
        resourceScope: rzResources.owner,
        signal,
        ...(this.#launcher === undefined
          ? {}
          : { processLauncher: this.#launcher }),
      });
      if (!inspected.ok) {
        const error = rzGhidraUnavailable("health", inspected.error.reason, {
          diagnostics: inspected.error.diagnostics,
          ...(!rzResources.hasPending
            ? {}
            : {
                cleanup: {
                  reason:
                    "rz-ghidra version-probe process cleanup is unconfirmed.",
                  resources: rzResources.cleanupResources ?? [],
                },
              }),
        });
        rzResources.bindRetainedFailure(error);
        return err(error);
      }
      const committed = this.#profile?.parameters["rz_sha256"];
      if (
        typeof committed === "string" &&
        committed.length > 0 &&
        committed !== inspected.value.sha256
      )
        return err(
          new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, "health", {
            userMessage:
              "The rizin executable changed after this target was opened; reopen the target to analyze it with the current executable.",
            diagnostics: {
              committed_sha256: committed,
              observed_sha256: inspected.value.sha256,
            },
          }),
        );
      return ok(inspected.value);
    } catch (cause: unknown) {
      const retainedCleanup = rzGhidraRetainedResourceCleanupError(
        cause,
        "health",
      );
      if (retainedCleanup !== undefined) return err(retainedCleanup);
      if (!(cause instanceof RegularFileCleanupFailure)) {
        const cancellation = rzResources.installationCancellationError(
          cause,
          "health",
        );
        if (cancellation !== undefined) return err(cancellation);
      }
      if (!(cause instanceof RegularFileCleanupFailure))
        return err(this.#failure("health", cause));
      const error = rzGhidraUnavailable(
        "health",
        `The rizin executable observation failed and its file cleanup is retained for a later retry: ${message(cause)}`,
      );
      rzResources.bindFailure(cause, error);
      return err(error);
    }
  }

  /** Spawn and open the one persistent console, shared across callers. */
  async #ensureConsole(
    installation: RzGhidraInstallation,
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<RzGhidraConsole, AnalysisError>> {
    let attempt = this.#console;
    if (attempt === undefined) {
      attempt = new SharedStartupAttempt(
        (ownerSignal) =>
          this.#own(this.#startConsole(installation, ownerSignal)),
        this.#session.signal,
      );
      this.#console = attempt;
      const owned = attempt;
      void owned.promise.then((result) => {
        // A failed start leaves a dead console; the next request respawns.
        // The instance stays in #consoles for close's cleanup retry.
        if (this.#console === owned && !result.ok) {
          this.#console = undefined;
          this.#analyzed = undefined;
          this.#functions = undefined;
        }
      });
    }
    const waited = await attempt.wait(signal);
    if (waited.status === "cancelled")
      return err(
        new AnalysisCancelledError(operation, { cause: signal?.reason }),
      );
    if (!waited.value.ok)
      return err(rzGhidraQueryFailureForCaller(waited.value.error, operation));
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    return waited.value;
  }

  async #startConsole(
    installation: RzGhidraInstallation,
    signal: AbortSignal,
  ): Promise<Result<RzGhidraConsole, AnalysisError>> {
    const console = new RzGhidraConsole(
      {
        path: this.#target.path,
        rizinCommand: installation.executable,
        defaultTimeoutMs: this.#frameTimeoutMs,
        maxFrameBytes: RIZIN_GHIDRA_FRAME_BYTES,
      },
      silentLogger,
      rzGhidraChildEnvironment(installation.configuration),
    );
    this.#consoles.push(console);
    const opened = await console.open(signal);
    if (!opened.ok) return err(this.#consoleStartupError(opened.error, signal));
    // Prove the plugin the whole provider exists for: pdgs lists the
    // embedded Sleigh languages; empty output is plain rizin, not rz-ghidra.
    const probe = await console.healthCheck();
    if (!probe.ok) {
      await console.close();
      return err(this.#consoleStartupError(probe.error, signal));
    }
    return ok(console);
  }

  #consoleStartupError(
    error: AnalysisError,
    signal: AbortSignal,
  ): AnalysisError {
    if (signal.aborted && error instanceof AnalysisCancelledError) return error;
    return rzGhidraQueryFailureForCaller(error, "open_binary");
  }

  /** The one whole-image `aa` pass, shared by every later operation. */
  async #ensureAnalysis(
    installation: RzGhidraInstallation,
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<RzGhidraConsole, AnalysisError>> {
    const console = await this.#ensureConsole(installation, operation, signal);
    if (!console.ok) return console;
    let attempt = this.#analyzed;
    if (attempt === undefined) {
      attempt = new SharedStartupAttempt(
        (ownerSignal) =>
          this.#own(
            this.#analyze(installation, console.value, operation, ownerSignal),
          ),
        this.#session.signal,
      );
      this.#analyzed = attempt;
    }
    const waited = await attempt.wait(signal);
    if (waited.status === "cancelled")
      return err(
        new AnalysisCancelledError(operation, { cause: signal?.reason }),
      );
    if (!waited.value.ok)
      return err(rzGhidraQueryFailureForCaller(waited.value.error, operation));
    if (signal?.aborted)
      return err(
        new AnalysisCancelledError(operation, { cause: signal.reason }),
      );
    return waited.value;
  }

  async #analyze(
    installation: RzGhidraInstallation,
    console: RzGhidraConsole,
    operation: string,
    signal: AbortSignal,
  ): Promise<Result<RzGhidraConsole, AnalysisError>> {
    const deadline = rzGhidraAnalysisDeadline(installation.configuration);
    const sent = await this.#send(
      console,
      "aa",
      operation,
      signal,
      deadline,
      this.#analysisTimeoutMs,
    );
    if (!sent.ok) return sent;
    if (sent.value.length !== 0)
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: `The rizin analysis pass produced unexpected output: ${sent.value.slice(-RIZIN_GHIDRA_DIAGNOSTIC_BYTES)}`,
        }),
      );
    return ok(console);
  }

  /**
   * A broken one-shot console is replaced for the next request; stop the
   * abandoned process now so it does not outlive the session.
   */
  #dropConsole(console: RzGhidraConsole): void {
    const attempt = this.#console;
    if (attempt === undefined) return;
    const settlement = attempt.settlement;
    if (
      settlement.status !== "completed" ||
      !settlement.value.ok ||
      settlement.value.value !== console
    )
      return;
    this.#console = undefined;
    this.#analyzed = undefined;
    this.#functions = undefined;
    void console.close();
  }

  /**
   * One serial console line. The console caps frames and deadlines itself;
   * this maps its transport failures onto the caller's operation and the
   * setting that owns the deadline.
   */
  #send(
    console: RzGhidraConsole,
    line: string,
    operation: string,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
    timeoutMs?: number,
  ): Promise<Result<string, AnalysisError>> {
    return console
      .send(line, {
        ...(signal === undefined ? {} : { signal }),
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
      })
      .then((result) => {
        if (result.ok) return result;
        // Every console send failure breaks the one-shot NUL stream.
        this.#dropConsole(console);
        return err(this.#mapSendFailure(result.error, operation, deadline));
      });
  }

  #mapSendFailure(
    error: AnalysisError,
    operation: string,
    deadline: RzGhidraDeadline,
  ): AnalysisError {
    if (
      error instanceof AnalysisCapabilityUnavailableError &&
      // The console's oversize-frame protocol message; a breached frame cap
      // is a resource constraint, not a capability gap.
      error.message.includes("NUL frame exceeding")
    )
      return new AnalysisResourceConstraintError(
        operation,
        "memory",
        "The rizin response frame exceeded the console's NUL-stream protocol limit.",
        null,
        error.capturedOutput === undefined
          ? {}
          : { capturedOutput: error.capturedOutput },
      );
    if (error instanceof AnalysisTimeoutError)
      return new AnalysisTimeoutError(operation, error.timeoutMs, {
        cause: error,
        userMessage: `The rizin response took longer than ${String(error.timeoutMs)} ms. Raise ${deadline.setting} to allow slower responses.`,
        remediationAction: `Raise ${deadline.setting} above ${String(error.timeoutMs)} ms.`,
        ...(error.capturedOutput !== undefined
          ? { capturedOutput: error.capturedOutput }
          : {}),
        ...(error.cleanup !== undefined ? { cleanup: error.cleanup } : {}),
      });
    return rzGhidraQueryFailureForCaller(error, operation);
  }

  /** One console line that answers a frame, parsed u64-safe. */
  async #frame(
    console: RzGhidraConsole,
    line: string,
    operation: string,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
    limit: number = RIZIN_GHIDRA_FRAME_BYTES,
    timeoutMs?: number,
  ): Promise<Result<unknown, AnalysisError>> {
    const result = await this.#send(
      console,
      line,
      operation,
      signal,
      deadline,
      timeoutMs,
    );
    if (!result.ok) return result;
    const text = result.value;
    if (text.length === 0)
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: `rz-ghidra ${this.#commandName(line)} returned no data.`,
        }),
      );
    try {
      return ok(parseRzGhidraJson(text, limit, ADDRESS_KEYS));
    } catch (cause: unknown) {
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: `rz-ghidra ${this.#commandName(line)} output is not usable JSON: ${message(cause)}`,
          diagnostics: {
            frame: text.slice(-RIZIN_GHIDRA_DIAGNOSTIC_BYTES),
          },
        }),
      );
    }
  }

  /**
   * One console line expected to answer an empty frame; any output is the
   * engine reporting a failure of the command itself.
   */
  async #sendEmpty(
    console: RzGhidraConsole,
    line: string,
    operation: string,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
    timeoutMs?: number,
  ): Promise<Result<null, AnalysisError>> {
    const result = await this.#send(
      console,
      line,
      operation,
      signal,
      deadline,
      timeoutMs,
    );
    if (!result.ok) return result;
    if (result.value.length === 0) return ok(null);
    return err(
      new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
        userMessage: `rz-ghidra ${this.#commandName(line)} produced unexpected output: ${result.value.slice(-RIZIN_GHIDRA_DIAGNOSTIC_BYTES)}`,
      }),
    );
  }

  #commandName(line: string): string {
    return line.split(" ")[0] ?? line;
  }

  async #answer(
    operation: RzGhidraOperation,
    parameters: Readonly<Record<string, JsonValue>>,
    installation: RzGhidraInstallation,
    console: RzGhidraConsole,
    options: ExecutionOptions,
  ): Promise<Result<Answer, AnalysisError>> {
    const signal = options.signal;
    const deadline = rzGhidraFrameDeadline(installation.configuration);
    switch (operation) {
      case "list_segments":
        return this.#listSegments(operation, console, signal, deadline);
      case "list_procedures":
      case "search_procedures":
        return this.#procedureAnswer(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "list_strings":
      case "search_strings":
        return this.#stringAnswer(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "list_names":
        return this.#listNames(operation, console, signal, deadline);
      case "procedure_address":
        return this.#procedureAddress(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "address_name":
        return this.#addressName(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "procedure_info":
        return this.#procedureInfo(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "procedure_pseudo_code":
        return this.#procedurePseudoCode(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "procedure_assembly":
      case "read_function_instructions":
        return this.#disassemblyAnswer(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "read_bytes":
        return this.#readBytes(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "xrefs":
        return this.#xrefs(operation, parameters, console, signal, deadline);
      case "procedure_callers":
      case "procedure_callees":
        return this.#callRelation(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "set_address_name":
        return this.#setAddressName(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "set_comment":
        return this.#setComment(
          operation,
          parameters,
          console,
          signal,
          deadline,
        );
      case "comment":
        return this.#comment(operation, parameters, console, signal, deadline);
      case "list_documents":
        // Answered before the console in #execute; this branch is
        // unreachable and only keeps the switch exhaustive.
        return err(
          new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
            userMessage: "list_documents needs no rizin console.",
          }),
        );
    }
  }

  async #listSegments(
    operation: string,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const frame = await this.#frame(
      console,
      "iSj",
      operation,
      signal,
      deadline,
    );
    if (!frame.ok) return frame;
    if (!Array.isArray(frame.value))
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: "The rizin section list is not a JSON array.",
        }),
      );
    const rows = (frame.value as unknown[])
      .map((row) => {
        if (typeof row !== "object" || row === null) return undefined;
        const record = row as Record<string, unknown>;
        const name = typeof record.name === "string" ? record.name : undefined;
        const address =
          typeof record.vaddr === "string" ? record.vaddr : undefined;
        // The NULL pseudo-section (vaddr 0xffffffffffffffff) is a rizin
        // placeholder, not a segment.
        if (
          name === undefined ||
          name.length === 0 ||
          address === undefined ||
          record.type === "NULL"
        )
          return undefined;
        return { address, value: name };
      })
      .filter(
        (row): row is { address: string; value: string } => row !== undefined,
      );
    return ok({ result: rows, locations: [], limitations: [] });
  }

  async #procedureAnswer(
    operation: "list_procedures" | "search_procedures",
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const query =
      operation === "search_procedures"
        ? analysisSearchQuerySchema.safeParse(parameters)
        : undefined;
    if (query !== undefined && !query.success)
      return err(
        analysisInputErrorFromIssues(operation, query.error.issues, parameters),
      );
    const functions = await this.#loadFunctions(
      operation,
      console,
      signal,
      deadline,
    );
    if (!functions.ok) return functions;
    let selected = functions.value.functions;
    if (query?.success === true) {
      if (query.data.mode === "regex") {
        const matched = await matchRegexValues({
          operation,
          pattern: query.data.pattern,
          caseSensitive: query.data.case_sensitive,
          values: functions.value.functions.map(({ name }) => name),
          signal,
          deadline: this.#deadline,
          heapRequest: this.#heapRequest,
        });
        if (!matched.ok) return matched;
        selected = matched.value
          .map((index) => functions.value.functions[index])
          .filter((entry): entry is RzGhidraFunction => entry !== undefined);
      } else {
        const predicate = analysisSearchPredicate(query.data);
        selected = functions.value.functions.filter((entry) =>
          predicate(entry.name),
        );
      }
    }
    return ok({
      result: selected.map(({ address, name }) => ({ address, value: name })),
      locations: [],
      limitations: [],
    });
  }

  async #stringAnswer(
    operation: "list_strings" | "search_strings",
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const query =
      operation === "search_strings"
        ? analysisSearchQuerySchema.safeParse(parameters)
        : undefined;
    if (query !== undefined && !query.success)
      return err(
        analysisInputErrorFromIssues(operation, query.error.issues, parameters),
      );
    const frame = await this.#frame(
      console,
      "izj",
      operation,
      signal,
      deadline,
    );
    if (!frame.ok) return frame;
    if (!Array.isArray(frame.value))
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: "The rizin string list is not a JSON array.",
        }),
      );
    const items: RzGhidraStringRow[] = (frame.value as unknown[])
      .map((row): RzGhidraStringRow | undefined => {
        if (typeof row !== "object" || row === null) return undefined;
        const record = row as Record<string, unknown>;
        const address =
          typeof record.vaddr === "string" ? record.vaddr : undefined;
        const value =
          typeof record.string === "string" ? record.string : undefined;
        if (address === undefined || value === undefined) return undefined;
        return {
          address,
          value,
          ...(typeof record.length === "number"
            ? { length: record.length }
            : {}),
          ...(typeof record.section === "string"
            ? { section: record.section }
            : {}),
          ...(typeof record.type === "string" ? { type: record.type } : {}),
        };
      })
      .filter((item): item is RzGhidraStringRow => item !== undefined);
    let selected = items;
    if (query?.success === true) {
      if (query.data.mode === "regex") {
        const matched = await matchRegexValues({
          operation,
          pattern: query.data.pattern,
          caseSensitive: query.data.case_sensitive,
          values: items.map(({ value }) => value),
          signal,
          deadline: this.#deadline,
          heapRequest: this.#heapRequest,
        });
        if (!matched.ok) return matched;
        selected = matched.value
          .map((index) => items[index])
          .filter((item): item is RzGhidraStringRow => item !== undefined);
      } else {
        const predicate = analysisSearchPredicate(query.data);
        selected = items.filter((item) => predicate(item.value));
      }
    }
    return ok({ result: selected, locations: [], limitations: [] });
  }

  async #listNames(
    operation: string,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const functions = await this.#loadFunctions(
      operation,
      console,
      signal,
      deadline,
    );
    if (!functions.ok) return functions;
    const flags = await this.#frame(
      console,
      "flj",
      operation,
      signal,
      deadline,
    );
    if (!flags.ok) return flags;
    const symbols = await this.#frame(
      console,
      "isj",
      operation,
      signal,
      deadline,
    );
    if (!symbols.ok) return symbols;
    const names = new Map<string, string>();
    // Function names are the most specific owner of a code address; symbols
    // and bare flags fill the rest without overwriting them.
    for (const { address, name } of functions.value.functions)
      if (name !== "") names.set(address, name);
    for (const row of Array.isArray(symbols.value) ? symbols.value : []) {
      if (typeof row !== "object" || row === null) continue;
      const record = row as Record<string, unknown>;
      const address =
        typeof record.vaddr === "string" ? record.vaddr : undefined;
      const name = typeof record.name === "string" ? record.name : undefined;
      if (
        address === undefined ||
        address === "0x0" ||
        name === undefined ||
        name.length === 0
      )
        continue;
      if (!names.has(address)) names.set(address, name);
    }
    for (const row of Array.isArray(flags.value) ? flags.value : []) {
      if (typeof row !== "object" || row === null) continue;
      const record = row as Record<string, unknown>;
      const address =
        typeof record.offset === "string" ? record.offset : undefined;
      const name = typeof record.name === "string" ? record.name : undefined;
      if (
        address === undefined ||
        address === "0x0" ||
        name === undefined ||
        name.length === 0
      )
        continue;
      if (!names.has(address)) names.set(address, name);
    }
    const result = [...names.entries()]
      .map(([address, value]) => ({ address, value }))
      .sort((a, b) => {
        const aAddress = BigInt(a.address);
        const bAddress = BigInt(b.address);
        if (aAddress !== bAddress) return aAddress < bAddress ? -1 : 1;
        return a.value < b.value ? -1 : a.value > b.value ? 1 : 0;
      });
    return ok({ result, locations: [], limitations: [] });
  }

  /**
   * The `aflj` function table, fetched once per console. It is the whole
   * function-and-call-reference model every later operation resolves against.
   */
  async #loadFunctions(
    operation: string,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<RzGhidraFunctionIndex, AnalysisError>> {
    if (this.#functions !== undefined) return ok(this.#functions);
    const frame = await this.#frame(
      console,
      "aflj",
      operation,
      signal,
      deadline,
    );
    if (!frame.ok) return frame;
    if (!Array.isArray(frame.value))
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: "The rizin function list is not a JSON array.",
        }),
      );
    const functions: RzGhidraFunction[] = [];
    for (const row of frame.value as unknown[]) {
      if (typeof row !== "object" || row === null) continue;
      const record = row as Record<string, unknown>;
      const address = normalizeRzGhidraAddress(record.offset);
      if (address === undefined) continue;
      const callrefs = (Array.isArray(record.callrefs) ? record.callrefs : [])
        .filter(
          (ref): ref is { from: string; to: string; type: string } =>
            typeof ref === "object" &&
            ref !== null &&
            typeof (ref as Record<string, unknown>).from === "string" &&
            typeof (ref as Record<string, unknown>).to === "string" &&
            typeof (ref as Record<string, unknown>).type === "string",
        )
        .map((ref) => ref as { from: string; to: string; type: string });
      functions.push({
        address,
        name: typeof record.name === "string" ? record.name : "",
        size: typeof record.size === "number" ? record.size : 0,
        blocks: typeof record.nbbs === "number" ? record.nbbs : null,
        signature:
          typeof record.signature === "string" ? record.signature : null,
        callrefs,
      });
    }
    const byAddress = new Map<string, RzGhidraFunction>();
    const byName = new Map<string, RzGhidraFunction[]>();
    for (const entry of functions) {
      byAddress.set(entry.address, entry);
      if (entry.name !== "") {
        const named = byName.get(entry.name);
        if (named === undefined) byName.set(entry.name, [entry]);
        else named.push(entry);
      }
    }
    this.#functions = { functions, byAddress, byName };
    return ok(this.#functions);
  }

  /** Resolve a procedure by exact entry address or exact name. */
  #resolve(
    operation: string,
    raw: unknown,
    functions: RzGhidraFunctionIndex,
  ): Result<RzGhidraFunction, AnalysisError> {
    if (typeof raw !== "string" || raw.length === 0)
      return err(
        new AnalysisInputError(
          operation,
          { userMessage: "procedure is required." },
          [{ path: ["procedure"], reason: "missing_argument" }],
        ),
      );
    const selector = raw;
    const address = normalizeRzGhidraAddress(selector);
    if (address !== undefined) {
      const entry = functions.byAddress.get(address);
      return entry === undefined
        ? err(
            new AnalysisInputError(operation, {
              userMessage: `${address} is not a procedure entry rz-ghidra found; list_procedures shows the entries it found.`,
            }),
          )
        : ok(entry);
    }
    const matches = functions.byName.get(selector) ?? [];
    const first = matches[0];
    if (matches.length === 1 && first !== undefined) return ok(first);
    return err(
      new AnalysisInputError(operation, {
        userMessage:
          matches.length === 0
            ? `rz-ghidra found no procedure named ${selector}; search_procedures finds similar names.`
            : `${selector} names ${String(matches.length)} rz-ghidra entries (${matches
                .map(({ address }) => address)
                .join(", ")}); select one by address.`,
      }),
    );
  }

  /** Headless rz-ghidra has no cursor: addresses are explicit 0x u64 strings. */
  #requireAddress(
    operation: string,
    raw: unknown,
    field: string,
  ): Result<string, AnalysisError> {
    if (typeof raw !== "string" || raw.length === 0)
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage: `rz-ghidra has no cursor; pass an explicit 0x-prefixed ${field}.`,
          },
          [{ path: [field], reason: "missing_argument" }],
        ),
      );
    const address = normalizeRzGhidraAddress(raw);
    if (address === undefined)
      return err(
        new AnalysisInputError(
          operation,
          { userMessage: "Use an explicit hexadecimal u64 string address." },
          [{ path: [field], reason: "invalid_format" }],
        ),
      );
    return ok(address);
  }

  async #procedureAddress(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const functions = await this.#loadFunctions(
      operation,
      console,
      signal,
      deadline,
    );
    if (!functions.ok) return functions;
    const entry = this.#resolve(
      operation,
      parameters.procedure,
      functions.value,
    );
    if (!entry.ok) return entry;
    const address = entry.value.address;
    return ok({
      result: address,
      locations: [{ kind: "address", address }],
      limitations: [],
    });
  }

  async #addressName(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const selected = this.#requireAddress(
      operation,
      parameters.address,
      "address",
    );
    if (!selected.ok) return selected;
    const address = selected.value;
    const locations = [{ kind: "address" as const, address }];
    const functions = await this.#loadFunctions(
      operation,
      console,
      signal,
      deadline,
    );
    if (!functions.ok) return functions;
    const entry = functions.value.byAddress.get(address);
    if (entry !== undefined && entry.name !== "")
      return ok({ result: entry.name, locations, limitations: [] });
    // Data addresses fall back to flags and symbols; the newest flag at the
    // address is what an analyst set most recently.
    const flags = await this.#frame(
      console,
      "flj",
      operation,
      signal,
      deadline,
    );
    if (!flags.ok) return flags;
    let name: string | undefined;
    if (Array.isArray(flags.value))
      for (const row of flags.value as unknown[]) {
        if (typeof row !== "object" || row === null) continue;
        const record = row as Record<string, unknown>;
        if (record.offset !== address) continue;
        if (typeof record.name === "string" && record.name.length > 0)
          name = record.name;
      }
    if (name === undefined) {
      const symbols = await this.#frame(
        console,
        "isj",
        operation,
        signal,
        deadline,
      );
      if (!symbols.ok) return symbols;
      if (Array.isArray(symbols.value))
        for (const row of symbols.value as unknown[]) {
          if (typeof row !== "object" || row === null) continue;
          const record = row as Record<string, unknown>;
          if (record.vaddr !== address) continue;
          if (typeof record.name === "string" && record.name.length > 0) {
            name = record.name;
            break;
          }
        }
    }
    return ok({ result: name ?? null, locations, limitations: [] });
  }

  async #procedureInfo(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const functions = await this.#loadFunctions(
      operation,
      console,
      signal,
      deadline,
    );
    if (!functions.ok) return functions;
    const entry = this.#resolve(
      operation,
      parameters.procedure,
      functions.value,
    );
    if (!entry.ok) return entry;
    const { address, name, size, blocks, signature } = entry.value;
    return ok({
      result: { address, name, size, blocks, signature },
      locations: [{ kind: "address", address }],
      limitations: [],
    });
  }

  async #procedurePseudoCode(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const functions = await this.#loadFunctions(
      operation,
      console,
      signal,
      deadline,
    );
    if (!functions.ok) return functions;
    const entry = this.#resolve(
      operation,
      parameters.procedure,
      functions.value,
    );
    if (!entry.ok) return entry;
    const address = entry.value.address;
    const locations = [{ kind: "address" as const, address }];
    const seek = await this.#sendEmpty(
      console,
      `s ${address}`,
      operation,
      signal,
      deadline,
    );
    if (!seek.ok) return seek;
    const sent = await this.#send(console, "pdgj", operation, signal, deadline);
    if (!sent.ok) return sent;
    const frame = sent.value;
    if (frame.length === 0)
      return err(
        rzGhidraUnavailable(
          operation,
          `rz-ghidra returned no pseudocode for ${address}.`,
        ),
      );
    let parsed: Record<string, unknown> | null = null;
    try {
      const value = parseRzGhidraJson(
        frame,
        RIZIN_GHIDRA_TEXT_BYTES,
        ADDRESS_KEYS,
      );
      if (typeof value === "object" && value !== null)
        parsed = value as Record<string, unknown>;
    } catch {
      parsed = null;
    }
    const code = parsed === null ? undefined : parsed.code;
    if (typeof code === "string")
      return ok({ result: code, locations, limitations: [] });
    // pdgj reports decompiler failures as {"errors": [...]} or ERROR: text.
    const reasons =
      parsed === null
        ? [frame.slice(-RIZIN_GHIDRA_DIAGNOSTIC_BYTES)]
        : (Array.isArray(parsed.errors)
            ? (parsed.errors as unknown[])
            : []
          ).filter((reason): reason is string => typeof reason === "string");
    return err(
      rzGhidraUnavailable(
        operation,
        `rz-ghidra could not decompile ${address}: ${reasons.join("; ") || "the decompiler returned no code."}`,
      ),
    );
  }

  async #disassemblyAnswer(
    operation: "procedure_assembly" | "read_function_instructions",
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const functions = await this.#loadFunctions(
      operation,
      console,
      signal,
      deadline,
    );
    if (!functions.ok) return functions;
    const entry = this.#resolve(
      operation,
      parameters.procedure,
      functions.value,
    );
    if (!entry.ok) return entry;
    const address = entry.value.address;
    const locations = [{ kind: "address" as const, address }];
    if (entry.value.size <= 0)
      return err(
        rzGhidraUnavailable(
          operation,
          `rz-ghidra reports no body for ${address}; nothing to disassemble.`,
        ),
      );
    const seek = await this.#sendEmpty(
      console,
      `s ${address}`,
      operation,
      signal,
      deadline,
    );
    if (!seek.ok) return seek;
    const frame = await this.#frame(
      console,
      `pDj ${String(Math.ceil(entry.value.size))}`,
      operation,
      signal,
      deadline,
    );
    if (!frame.ok) return frame;
    if (!Array.isArray(frame.value))
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: "The rizin disassembly is not a JSON array.",
        }),
      );
    const rows: RzGhidraInstructionRow[] = (frame.value as unknown[])
      .map((row): RzGhidraInstructionRow | undefined => {
        if (typeof row !== "object" || row === null) return undefined;
        const record = row as Record<string, unknown>;
        const rowAddress =
          typeof record.offset === "string" ? record.offset : undefined;
        const disasm =
          typeof record.disasm === "string" ? record.disasm : undefined;
        if (rowAddress === undefined || disasm === undefined) return undefined;
        return {
          address: rowAddress,
          disasm,
          ...(typeof record.bytes === "string" ? { bytes: record.bytes } : {}),
          ...(typeof record.type === "string" ? { type: record.type } : {}),
        };
      })
      .filter((row): row is RzGhidraInstructionRow => row !== undefined);
    if (operation === "procedure_assembly") {
      if (rows.length === 0)
        return err(
          rzGhidraUnavailable(
            operation,
            `rz-ghidra returned no disassembly for ${address}.`,
          ),
        );
      return ok({
        result: rows.map(({ disasm }) => disasm).join("\n"),
        locations,
        limitations: [],
      });
    }
    return ok({ result: rows, locations, limitations: [] });
  }

  async #readBytes(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const selected = this.#requireAddress(
      operation,
      parameters.address,
      "address",
    );
    if (!selected.ok) return selected;
    const address = selected.value;
    const locations = [{ kind: "address" as const, address }];
    const length = parameters.length;
    if (typeof length !== "number" || !Number.isInteger(length) || length <= 0)
      return err(
        new AnalysisInputError(
          operation,
          { userMessage: "length must be a positive integer byte count." },
          [{ path: ["length"], reason: "out_of_range" }],
        ),
      );
    const seek = await this.#sendEmpty(
      console,
      `s ${address}`,
      operation,
      signal,
      deadline,
    );
    if (!seek.ok) return seek;
    const frame = await this.#frame(
      console,
      `pxj ${String(length)}`,
      operation,
      signal,
      deadline,
    );
    if (!frame.ok) return frame;
    if (!Array.isArray(frame.value))
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: "The rizin byte dump is not a JSON array.",
        }),
      );
    // Unmapped reads answer 0xff bytes, rizin's unmapped convention.
    const hex = (frame.value as unknown[])
      .filter((byte): byte is number => typeof byte === "number")
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
    return ok({ result: hex, locations, limitations: [] });
  }

  async #xrefs(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const selected = this.#requireAddress(
      operation,
      parameters.address,
      "address",
    );
    if (!selected.ok) return selected;
    const address = selected.value;
    const locations = [{ kind: "address" as const, address }];
    const seek = await this.#sendEmpty(
      console,
      `s ${address}`,
      operation,
      signal,
      deadline,
    );
    if (!seek.ok) return seek;
    const frame = await this.#frame(
      console,
      "axtj",
      operation,
      signal,
      deadline,
    );
    if (!frame.ok) return frame;
    if (!Array.isArray(frame.value))
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: "The rizin reference list is not a JSON array.",
        }),
      );
    const sources = new Set<string>();
    for (const row of frame.value as unknown[]) {
      if (typeof row !== "object" || row === null) continue;
      const record = row as Record<string, unknown>;
      if (record.to !== address) continue;
      if (typeof record.from === "string") sources.add(record.from);
    }
    return ok({
      result: [...sources],
      locations,
      limitations: [],
      referencesTruncated: false,
    });
  }

  /**
   * Whole-function call edges from `aflj` callrefs: `axtj`/`axfj` are
   * block-scoped in rizin 0.9.1, so they under-report functions with
   * multiple blocks.
   */
  async #callRelation(
    operation: "procedure_callers" | "procedure_callees",
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const functions = await this.#loadFunctions(
      operation,
      console,
      signal,
      deadline,
    );
    if (!functions.ok) return functions;
    const entry = this.#resolve(
      operation,
      parameters.procedure,
      functions.value,
    );
    if (!entry.ok) return entry;
    const address = entry.value.address;
    const addresses =
      operation === "procedure_callers"
        ? [
            ...new Set(
              functions.value.functions
                .filter(
                  (functionEntry) =>
                    functionEntry.address !== address &&
                    functionEntry.callrefs.some(
                      ({ to, type }) => to === address && type === "CALL",
                    ),
                )
                .map(({ address }) => address),
            ),
          ]
        : [
            ...new Set(
              entry.value.callrefs
                .filter(({ type }) => type === "CALL")
                .map(({ to }) => to),
            ),
          ];
    // The one `aflj` frame reports every resolved static call edge; the
    // limit is rizin's static resolution, not a truncated read.
    const relationshipCoverage: RelationshipCoverage = {
      status: "partial",
      limitations: [RZ_XREF_LIMITATION],
      limited_directions:
        operation === "procedure_callers" ? ["callers"] : ["callees"],
    };
    return ok({
      result: addresses,
      locations: [{ kind: "address", address }],
      limitations: [],
      relationshipCoverage,
    });
  }

  async #setAddressName(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const selected = this.#requireAddress(
      operation,
      parameters.address,
      "address",
    );
    if (!selected.ok) return selected;
    const address = selected.value;
    const locations = [{ kind: "address" as const, address }];
    const name = parameters.name;
    if (typeof name !== "string" || name.length === 0)
      return err(
        new AnalysisInputError(
          operation,
          { userMessage: "name must be a non-empty string." },
          [{ path: ["name"], reason: "missing_argument" }],
        ),
      );
    if (name.includes("\n"))
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage:
              "A rizin-ghidra name must be a single line; the console protocol cannot carry newlines.",
          },
          [{ path: ["name"], reason: "invalid_format" }],
        ),
      );
    const functions = await this.#loadFunctions(
      operation,
      console,
      signal,
      deadline,
    );
    if (!functions.ok) return functions;
    const isFunction = functions.value.byAddress.has(address);
    const seek = await this.#sendEmpty(
      console,
      `s ${address}`,
      operation,
      signal,
      deadline,
    );
    if (!seek.ok) return seek;
    // afn renames the function at the seek (and leaves its old flags); f
    // plants a flag, the only edit possible at a non-function.
    const edit = await this.#sendEmpty(
      console,
      isFunction ? `afn ${name}` : `f ${name}`,
      operation,
      signal,
      deadline,
    );
    if (!edit.ok) return edit;
    let readBack: string | undefined;
    if (isFunction) {
      const frame = await this.#frame(
        console,
        "aflj",
        operation,
        signal,
        deadline,
      );
      if (!frame.ok) return frame;
      if (Array.isArray(frame.value))
        for (const row of frame.value as unknown[]) {
          if (typeof row !== "object" || row === null) continue;
          const record = row as Record<string, unknown>;
          if (record.offset !== address) continue;
          if (typeof record.name === "string" && record.name.length > 0)
            readBack = record.name;
        }
      // The rename invalidates the cached function table for later resolves.
      this.#functions = undefined;
    } else {
      const frame = await this.#frame(
        console,
        "flj",
        operation,
        signal,
        deadline,
      );
      if (!frame.ok) return frame;
      if (Array.isArray(frame.value))
        for (const row of frame.value as unknown[]) {
          if (typeof row !== "object" || row === null) continue;
          const record = row as Record<string, unknown>;
          if (record.offset !== address) continue;
          if (typeof record.name === "string" && record.name.length > 0)
            readBack = record.name;
        }
    }
    if (readBack === undefined || readBack.length === 0)
      return err(
        new ProviderAdapterError(RIZIN_GHIDRA_PROVIDER_ID, operation, {
          userMessage: `rz-ghidra accepted the edit but recorded no name at ${address}.`,
        }),
      );
    return ok({ result: readBack, locations, limitations: [] });
  }

  async #setComment(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const selected = this.#requireAddress(
      operation,
      parameters.address,
      "address",
    );
    if (!selected.ok) return selected;
    const address = selected.value;
    const locations = [{ kind: "address" as const, address }];
    const comment = parameters.comment;
    if (typeof comment !== "string")
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage:
              "comment must be a string; an empty string clears the comment.",
          },
          [{ path: ["comment"], reason: "invalid_type" }],
        ),
      );
    if (comment.includes("\n"))
      return err(
        new AnalysisInputError(
          operation,
          {
            userMessage:
              "A rizin-ghidra comment must be a single line; the console protocol cannot carry newlines.",
          },
          [{ path: ["comment"], reason: "invalid_format" }],
        ),
      );
    const seek = await this.#sendEmpty(
      console,
      `s ${address}`,
      operation,
      signal,
      deadline,
    );
    if (!seek.ok) return seek;
    const write = await this.#sendEmpty(
      console,
      comment === "" ? "CC-*" : `CC ${comment}`,
      operation,
      signal,
      deadline,
    );
    if (!write.ok) return write;
    const frame = await this.#frame(
      console,
      "CClj",
      operation,
      signal,
      deadline,
    );
    if (!frame.ok) return frame;
    let readBack: string | undefined;
    if (Array.isArray(frame.value))
      for (const row of frame.value as unknown[]) {
        if (typeof row !== "object" || row === null) continue;
        const record = row as Record<string, unknown>;
        if (record.offset !== address) continue;
        if (typeof record.name === "string") readBack = record.name;
      }
    // CClj entries record exactly what rizin stored; at a section start that
    // includes rizin's own section decoration before the comment text.
    return ok({ result: readBack ?? "", locations, limitations: [] });
  }

  async #comment(
    operation: string,
    parameters: Readonly<Record<string, JsonValue>>,
    console: RzGhidraConsole,
    signal: AbortSignal | undefined,
    deadline: RzGhidraDeadline,
  ): Promise<Result<Answer, AnalysisError>> {
    const selected = this.#requireAddress(
      operation,
      parameters.address,
      "address",
    );
    if (!selected.ok) return selected;
    const address = selected.value;
    const locations = [{ kind: "address" as const, address }];
    const frame = await this.#frame(
      console,
      "CClj",
      operation,
      signal,
      deadline,
    );
    if (!frame.ok) return frame;
    let value: string | null = null;
    if (Array.isArray(frame.value))
      for (const row of frame.value as unknown[]) {
        if (typeof row !== "object" || row === null) continue;
        const record = row as Record<string, unknown>;
        if (record.offset !== address) continue;
        if (typeof record.name === "string" && record.name.length > 0)
          value = record.name;
      }
    return ok({ result: value, locations, limitations: [] });
  }
}
