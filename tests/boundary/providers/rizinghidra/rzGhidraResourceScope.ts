import type { RetainedResourceScope } from "../../../../src/application/AnalysisProvider.js";
import type { RzGhidraInstallationOptions } from "../../../../src/rizinghidra/RzGhidraInstallation.js";
import { inspectRzGhidraInstallation } from "../../../../src/rizinghidra/RzGhidraInstallation.js";
import { inspectRzGhidraProvider } from "../../../../src/rizinghidra/RzGhidraDoctor.js";
import { createInspectionResources } from "../../../fixtures/inspectionResources.js";

export const withRzGhidraResourceScope = async <T>(
  operation: (owner: RetainedResourceScope) => Promise<T>,
): Promise<T> => {
  const scope = createInspectionResources();
  try {
    return await operation(scope.owner);
  } finally {
    await scope.close();
  }
};

export const inspectRzGhidraInstallationOwned = (
  environment: Readonly<NodeJS.ProcessEnv>,
  options: Omit<RzGhidraInstallationOptions, "resourceScope"> = {},
) =>
  withRzGhidraResourceScope((resourceScope) =>
    inspectRzGhidraInstallation(environment, { ...options, resourceScope }),
  );

export const inspectRzGhidraProviderOwned = (
  environment: Readonly<NodeJS.ProcessEnv>,
  platform?: NodeJS.Platform,
) =>
  withRzGhidraResourceScope((resourceScope) =>
    inspectRzGhidraProvider(environment, platform, { resourceScope }),
  );
