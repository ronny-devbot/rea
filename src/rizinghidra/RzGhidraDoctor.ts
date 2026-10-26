import type {
  DoctorProviderCheck,
  DoctorProviderInspection,
} from "../application/Doctor.js";
import type { RetainedResourceScope } from "../application/AnalysisProvider.js";
import { RegularFileCleanupFailure } from "../filesystem/OwnedRegularFile.js";
import {
  createRzGhidraResourceScope,
  inspectRzGhidraInstallation,
  rzGhidraInstallationFailureDiagnostics,
  rzGhidraRetainedResourceCleanupError,
  type RzGhidraReadinessFailure,
} from "./RzGhidraInstallation.js";
import {
  RIZIN_COMMAND_REMEDIATION,
  RIZIN_GHIDRA_PROVIDER_ID,
  RIZIN_GHIDRA_VERIFIED_VERSION,
  RIZIN_UNSUPPORTED_HOST_REMEDIATION,
  RIZIN_VERSION_PROBE_REMEDIATION,
  RZ_GHIDRA_PLUGIN_REMEDIATION,
} from "./RzGhidraRelease.js";

/** Settings a registration may carry; only those the caller set explicitly. */
const REGISTRATION_SETTINGS = [
  "REA_RIZIN_COMMAND",
  "REA_RIZIN_ANALYSIS_TIMEOUT_MS",
  "REA_RIZIN_FRAME_TIMEOUT_MS",
] as const;

const message = (cause: unknown): string =>
  cause instanceof Error ? cause.message : String(cause);

/**
 * Project rizin-ghidra readiness into the doctor contract without writing
 * anything. Rizin opens the target read-only with `-N`, so unlike Kuna there
 * is no cache to check: installation, version and plugin are the whole story.
 */
export const inspectRzGhidraProvider = async (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform: NodeJS.Platform = process.platform,
  options: {
    readonly resourceScope: RetainedResourceScope;
    readonly signal?: AbortSignal;
  },
): Promise<DoctorProviderInspection> => {
  const rzGhidraResources = createRzGhidraResourceScope(options.resourceScope);
  let installation: Awaited<ReturnType<typeof inspectRzGhidraInstallation>>;
  try {
    installation = await inspectRzGhidraInstallation(environment, {
      platform,
      resourceScope: rzGhidraResources.owner,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  } catch (cause: unknown) {
    const retainedCleanup = rzGhidraRetainedResourceCleanupError(
      cause,
      "doctor",
    );
    if (retainedCleanup !== undefined)
      return {
        id: RIZIN_GHIDRA_PROVIDER_ID,
        configured: environment.REA_RIZIN_COMMAND !== undefined,
        available: false,
        providerVersion: null,
        registrationEnvironment: {},
        checks: [
          {
            name: "installation",
            ok: false,
            code: "cleanup_incomplete",
            detail: retainedCleanup.message,
            remediation: null,
            classification: "config_drift",
            details: {
              cleanup_incomplete: true,
              cleanup_resources: [...retainedCleanup.cleanupResources],
            },
          },
        ],
      };
    if (!(cause instanceof RegularFileCleanupFailure)) {
      const cancellation = rzGhidraResources.installationCancellationError(
        cause,
        "doctor",
      );
      if (cancellation !== undefined) throw cancellation;
      throw cause;
    }
    return {
      id: RIZIN_GHIDRA_PROVIDER_ID,
      configured: environment.REA_RIZIN_COMMAND !== undefined,
      available: false,
      providerVersion: null,
      registrationEnvironment: {},
      checks: [
        {
          name: "installation",
          ok: false,
          code: "cleanup_incomplete",
          detail: `rizin-ghidra installation inspection could not confirm file cleanup: ${message(cause)}`,
          remediation: null,
          classification: "config_drift",
          details: {
            cleanup_incomplete: true,
            ...rzGhidraInstallationFailureDiagnostics(cause),
          },
        },
      ],
    };
  }
  const configured =
    environment.REA_RIZIN_COMMAND !== undefined &&
    environment.REA_RIZIN_COMMAND.length > 0;
  const base = {
    id: RIZIN_GHIDRA_PROVIDER_ID,
    configured,
    available: false,
    providerVersion: null,
    registrationEnvironment: {},
  } as const;
  if (!installation.ok) {
    const check = installationFailure(installation.error, configured);
    const cleanupResources = rzGhidraResources.cleanupResources;
    if (!rzGhidraResources.hasPending) return { ...base, checks: [check] };
    return {
      ...base,
      checks: [
        {
          ...check,
          code: "cleanup_incomplete",
          details: {
            ...installation.error.diagnostics,
            cleanup_incomplete: true,
            ...(cleanupResources === undefined
              ? {}
              : { cleanup_resources: [...cleanupResources] }),
          },
        },
      ],
    };
  }
  const { value } = installation;
  return {
    id: RIZIN_GHIDRA_PROVIDER_ID,
    configured,
    available: true,
    providerVersion: value.version,
    registrationEnvironment: Object.fromEntries(
      REGISTRATION_SETTINGS.flatMap((name) => {
        const setting = environment[name];
        return setting === undefined ? [] : [[name, setting]];
      }),
    ),
    checks: [
      {
        name: "installation",
        ok: true,
        code: null,
        detail: `${value.executable} is an executable regular file (sha256 ${value.sha256}).`,
        remediation: null,
        classification: "config_drift",
        details: {
          executable: value.executable,
          sha256: value.sha256,
          bytes: value.bytes,
          script: value.script,
        },
      },
      {
        name: "version",
        ok: true,
        code: null,
        detail: `${value.executable} reports rizin ${value.version}${
          value.verified
            ? ", the release REA verified."
            : `; REA verified ${RIZIN_GHIDRA_VERIFIED_VERSION}, so this release is unverified.`
        }`,
        remediation: null,
        classification: "config_drift",
        details: {
          version: value.version,
          verified_release: value.verified,
          verified_version: RIZIN_GHIDRA_VERIFIED_VERSION,
        },
      },
      // The `pd?` help line proves the rz-ghidra plugin is registered but not
      // that the Sleigh language files it decompiles with are present; those
      // surface only as per-function decompile failures at runtime. No
      // one-shot probe can confirm sleigh-home, so it is folded into this
      // plugin check rather than reported as a separate, always-unknown check.
      {
        name: "rz-ghidra-plugin",
        ok: true,
        code: null,
        detail: `The one-shot pd? probe lists the pdg (rz-ghidra) decompiler in ${value.executable}.`,
        remediation: null,
        classification: "config_drift",
        details: {
          probe: "rizin -q -e scr.color=off -c pd?",
          pdg_listed: true,
        },
      },
    ],
  };
};

const installationFailure = (
  failure: RzGhidraReadinessFailure,
  configured: boolean,
): DoctorProviderCheck => ({
  name: "installation",
  ok: false,
  code: failure.code,
  detail: failure.reason,
  remediation:
    failure.remediation ??
    (failure.code === "unsupported_host"
      ? RIZIN_UNSUPPORTED_HOST_REMEDIATION
      : failure.code === "version_unresolved"
        ? RIZIN_VERSION_PROBE_REMEDIATION
        : failure.code === "plugin_missing"
          ? RZ_GHIDRA_PLUGIN_REMEDIATION
          : RIZIN_COMMAND_REMEDIATION),
  classification:
    failure.code === "unsupported_host"
      ? "unsupported_host"
      : configured
        ? "config_drift"
        : "missing_analysis_engine",
  details: failure.diagnostics,
});
