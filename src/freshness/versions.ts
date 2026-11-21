import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { VcrError } from '../core/errors';

const execFileAsync = promisify(execFile);

export const DEFAULT_SEMVER_PATTERN = /(\d+\.\d+\.\d+(?:-[\w.]+)?)/;
export const DEFAULT_CLI_VERSION_TIMEOUT_MS = 10_000;
export const DEFAULT_CLI_VERSION_MAX_BUFFER = 1024 * 1024;

export interface CliVersionOptions {
  /** Arguments passed directly to `execFile` (shell disabled). Defaults to `['--version']`. */
  readonly args?: readonly string[];
  /** Regex extracting the version string (uses capture group 1 if present, else full match). Defaults to semver. */
  readonly regex?: RegExp;
  /** Optional PATH override for resolving the CLI binary. */
  readonly pathEnv?: string;
  /** Additional environment variables passed to the version probe. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Timeout in milliseconds before aborting the CLI version probe. Defaults to 10_000. */
  readonly timeoutMs?: number;
  /** Maximum stdout/stderr buffer in bytes. Defaults to 1 MiB. */
  readonly maxBuffer?: number;
}

export interface HttpVersionOptions {
  readonly init?: RequestInit;
  /** Extract the version from a response header (e.g. `etag`, `x-api-version`). */
  readonly header?: string;
  /** Custom extractor receiving the full HTTP `Response`. */
  readonly extract?: (response: Response) => string | Promise<string>;
  /** Optional custom fetch implementation. */
  readonly fetchImpl?: typeof fetch;
}

/** Resolves a CLI binary's installed version safely via `execFile` (`shell: false`) with timeout and buffer limits. */
export const fetchCliVersion = async (
  binary: string,
  options: CliVersionOptions = {},
): Promise<string> => {
  const args = options.args ? [...options.args] : ['--version'];
  const regex = options.regex ?? DEFAULT_SEMVER_PATTERN;
  const timeout = options.timeoutMs ?? DEFAULT_CLI_VERSION_TIMEOUT_MS;
  const maxBuffer = options.maxBuffer ?? DEFAULT_CLI_VERSION_MAX_BUFFER;
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...(options.pathEnv ? { PATH: options.pathEnv } : {}),
    ...options.env,
  };
  let stdout = '';
  let stderr = '';
  try {
    const result = await execFileAsync(binary, args, {
      env,
      timeout,
      maxBuffer,
      shell: false,
      encoding: 'utf8',
    });
    stdout = result.stdout;
    stderr = result.stderr;
  } catch (error) {
    throw new VcrError(
      'version_resolution_failed',
      `VCR: failed to resolve CLI version for "${binary} ${args.join(' ')}"`,
      { cause: error },
    );
  }
  const output = `${stdout}\n${stderr}`;
  const match = output.match(new RegExp(regex.source, regex.flags.replace(/[gy]/g, '')));
  const version = match?.[1] ?? match?.[0];
  if (!version) {
    throw new VcrError(
      'version_resolution_failed',
      `VCR: no version match for "${binary} ${args.join(' ')}" in "${output.trim()}"`,
    );
  }
  return version;
};

/** Resolves an upstream service version from a URL via custom extractor, response header, or SHA-256 body digest. */
export const fetchHttpVersion = async (
  url: string,
  options: HttpVersionOptions = {},
): Promise<string> => {
  const fetchFn = options.fetchImpl ?? globalThis.fetch;
  const response = await fetchFn(url, { redirect: 'follow', ...options.init });
  if (!response.ok) {
    throw new VcrError(
      'version_resolution_failed',
      `VCR: fetchHttpVersion(${url}) returned ${response.status} ${response.statusText}`,
    );
  }

  if (options.extract) {
    const extracted = await options.extract(response);
    if (!extracted) {
      throw new VcrError(
        'version_resolution_failed',
        `VCR: fetchHttpVersion(${url}) extractor returned an empty string`,
      );
    }
    return extracted;
  }

  if (options.header) {
    const value = response.headers.get(options.header);
    if (!value) {
      throw new VcrError(
        'version_resolution_failed',
        `VCR: fetchHttpVersion(${url}) missing header "${options.header}"`,
      );
    }
    return value.replace(/"/g, '');
  }

  const text = await response.text();
  return createHash('sha256').update(text).digest('hex').slice(0, 12);
};

/** Resolves installed versions for each CLI name present on this machine, skipping unavailable binaries. */
export const fetchInstalledVersions = async (
  clis: readonly string[],
  options: CliVersionOptions = {},
): Promise<Record<string, string>> => {
  const out: Record<string, string> = {};
  await Promise.all(
    clis.map(async (cli) => {
      try {
        out[cli] = await fetchCliVersion(cli, options);
      } catch {
        /* Binary is not installed in this environment (e.g. CI). */
      }
    }),
  );
  return out;
};

const ISO_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}(?:[T\s].*)?$/;
const SEMVER_PATTERN = /^v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;
const NUMERIC_ID_PATTERN = /^\d+$/;

const comparePrerelease = (leftPre: string | undefined, rightPre: string | undefined): number => {
  if (leftPre === rightPre) return 0;
  if (leftPre === undefined) return 1; // Release > pre-release per SemVer 2.0.0
  if (rightPre === undefined) return -1;

  const leftParts = leftPre.split('.');
  const rightParts = rightPre.split('.');
  const length = Math.max(leftParts.length, rightParts.length);

  for (let i = 0; i < length; i++) {
    const a = leftParts[i];
    const b = rightParts[i];
    if (a === undefined) return -1;
    if (b === undefined) return 1;
    if (a === b) continue;

    const aNum = NUMERIC_ID_PATTERN.test(a);
    const bNum = NUMERIC_ID_PATTERN.test(b);
    if (aNum && bNum) {
      const diff = Number(a) - Number(b);
      if (diff !== 0) return Math.sign(diff);
    } else if (aNum) {
      return -1; // Numeric identifiers have lower precedence than non-numeric per SemVer 2.0.0
    } else if (bNum) {
      return 1;
    } else {
      return a < b ? -1 : 1;
    }
  }
  return 0;
};

/** Compares SemVer 2.0.0 (with pre-release tags), ISO dates (`YYYY-MM-DD`), or opaque version/digest strings (`-1`, `0`, `1`). */
export const compareVersions = (left: string, right: string): number => {
  const a = left.trim();
  const b = right.trim();
  if (a === b) return 0;

  if (ISO_DATE_PATTERN.test(a) && ISO_DATE_PATTERN.test(b)) {
    return a < b ? -1 : 1;
  }

  const aSem = a.match(SEMVER_PATTERN);
  const bSem = b.match(SEMVER_PATTERN);
  if (aSem?.[1] && bSem?.[1]) {
    const aCore = aSem[1].split('.').map(Number);
    const bCore = bSem[1].split('.').map(Number);
    const length = Math.max(aCore.length, bCore.length);
    for (let i = 0; i < length; i++) {
      const diff = (aCore[i] ?? 0) - (bCore[i] ?? 0);
      if (diff !== 0) return Math.sign(diff);
    }
    return comparePrerelease(aSem[2], bSem[2]);
  }

  return a < b ? -1 : 1;
};
