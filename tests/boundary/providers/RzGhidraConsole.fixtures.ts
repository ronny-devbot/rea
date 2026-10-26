import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * Fake rizin implementing the `-0` NUL protocol: an init NUL ~50 ms after
 * spawn, then exactly one NUL-delimited frame per stdin line.
 */
export interface RzGhidraFakeOptions {
  /** Treat `q` like any other command so the fake never exits on it. */
  readonly ignoreQuit?: boolean;
  /** Never emit the init NUL (startup-timeout tests). */
  readonly noInitNul?: boolean;
}

const renderFakeRizin = (
  options: RzGhidraFakeOptions,
): string => `#!/usr/bin/env bash
set -u
# The console must launch rizin as: rizin -N -0 <absolute target path>.
if [ "\${1:-}" != "-N" ] || [ "\${2:-}" != "-0" ] || [ -z "\${3:-}" ]; then
  echo "unexpected rizin argv: $*" >&2
  exit 99
fi
sleep ${options.noInitNul ? "2" : "0.05"}
${options.noInitNul ? "" : "printf '\\0'\n"}
while IFS= read -r line; do
  case "$line" in
    pdgs)
      printf 'x86:LE:64:default\\n\\0'
      ;;
    aflj)
      printf '[{"offset":1,"name":"sym.main","size":10,"callrefs":[],"datarefs":[]}]\\n\\0'
      ;;
    big)
      head -c 200000 /dev/zero | tr '\\0' 'x'
      printf '\\0'
      ;;
    SLOW)
      sleep 2
      printf 'slow-done\\n\\0'
      ;;
    stderr)
      head -c 100000 /dev/zero | tr '\\0' 'a' 1>&2
      printf 'stderr-tail\\n' 1>&2
      printf 'stderr-done\\n\\0'
      ;;
    die)
      exit 7
      ;;
${
  options.ignoreQuit
    ? ""
    : `    q)
      printf '\\0'
      exit 0
      ;;
`
}    *)
      printf 'ECHO:%s\\n\\0' "$line"
      ;;
  esac
done
exit 0
`;

/** Write one fake rizin executable under directory; returns its path. */
export const writeFakeRizin = async (
  directory: string,
  name: string,
  options: RzGhidraFakeOptions = {},
): Promise<string> => {
  const path = join(directory, name);
  await writeFile(path, renderFakeRizin(options));
  await chmod(path, 0o755);
  return path;
};
