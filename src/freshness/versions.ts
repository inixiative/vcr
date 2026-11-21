import { exec } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { VcrError } from '../core/errors';

const execAsync = promisify(exec);

export const DEFAULT_SEMVER_PATTERN = /(\d+\.\d+\.\d+(?:-[\w.]+)?)/;

export interface CliVersionOptions {
  /** Flag or subcommand appended after the binary name. Defaults to `--version`. */
  readonly command?: string;
  /** Regex capturing the version in group 1. Defaults to semver. */
  readonly regex?: RegExp;
  /** Optional PATH override for resolving the CLI binary. */
  readonly pathEnv?: string;
  /** Additional environment variables passed to the version probe. */
  readonly env?: Readonly<Record<string, string | undefined>>;
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

/** Resolves a CLI binary's installed version string by invoking it with `--version` (or a custom subcommand). */
export const fetchCliVersion = async (
  binary: string,
  options: CliVersionOptions = {},
): Promise<string> => {
  const subcommand = options.command ?? '--version';
  const regex = options.regex ?? DEFAULT_SEMVER_PATTERN;
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...(options.pathEnv ? { PATH: options.pathEnv } : {}),
    ...options.env,
  };
  let stdout = '';
  let stderr = '';
  try {
    const result = await execAsync(`${binary} ${subcommand}`, { env });
    stdout = result.stdout;
    stderr = result.stderr;
  } catch (error) {
    throw new VcrError(
      'version_resolution_failed',
      `VCR: failed to resolve CLI version for "${binary} ${subcommand}"`,
      { cause: error },
    );
  }
  const output = `${stdout}\n${stderr}`;
  const match = output.match(regex);
  if (!match?.[1]) {
    throw new VcrError(
      'version_resolution_failed',
      `VCR: no version match for "${binary} ${subcommand}" in "${output.trim()}"`,
    );
  }
  return match[1];
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

/** Compares two numeric dotted version strings (`-1`, `0`, `1`); missing trailing segments count as zero. */
export const compareVersions = (left: string, right: string): number => {
  const parse = (value: string): number[] =>
    (value.match(/\d+(?:\.\d+)*/)?.[0] ?? '0').split('.').map(Number);
  const a = parse(left);
  const b = parse(right);
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index++) {
    const diff = (a[index] ?? 0) - (b[index] ?? 0);
    if (diff !== 0) return Math.sign(diff);
  }
  return 0;
};
