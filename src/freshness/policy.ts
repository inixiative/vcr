import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { VcrError } from '../core/errors';
import type { VcrCassette } from '../core/types';
import { createScrubber } from '../scrub/scrubber';
import type { Scrubber, ScrubOptions } from '../scrub/types';
import { fetchCassettePaths, PENDING_CASSETTE_SUFFIX, POLICY_FILENAME } from './pending';
import { compareVersions } from './versions';

export interface FreshnessPolicy {
  /** Maximum age in days accepted for committed cassettes. */
  readonly maxAgeDays: number;
  /** Minimum accepted versions keyed by CLI binary name or package/service metadata key. */
  readonly blessed: Readonly<Record<string, string>>;
}

export type FreshnessFindingCode =
  | 'pending_drift'
  | 'unscrubbed_secret'
  | 'invalid_cassette'
  | 'missing_stamp'
  | 'expired_cassette'
  | 'missing_version'
  | 'below_blessed_version'
  | 'below_installed_version';

export interface FreshnessFinding {
  readonly cassette: string;
  readonly code: FreshnessFindingCode;
  readonly problem: string;
}

export interface CassetteValidationResult {
  readonly ok: boolean;
  readonly errors: readonly string[];
}

export interface CheckFreshnessOptions {
  /** Reference epoch timestamp in ms. Defaults to `Date.now()`. */
  readonly now?: number;
  /** Explicit policy object; if omitted, read from `<fixturesDir>/policy.json`. */
  readonly policy?: FreshnessPolicy;
  /** Currently installed CLI versions keyed by CLI name. */
  readonly installed?: Readonly<Record<string, string>>;
  /** Currently installed package/metadata versions keyed by metadata key (e.g. `@scope/pkg`). */
  readonly packageVersions?: Readonly<Record<string, string>>;
  /** Optional scrubber or scrub options used for secret leak detection. */
  readonly scrubber?: Scrubber | ScrubOptions;
}

export interface BlessPolicyOptions {
  /** Additional package/metadata versions to raise in `policy.blessed`. */
  readonly metadataVersions?: Readonly<Record<string, string>>;
}

const MS_PER_DAY = 86_400_000;

const isScrubberHandle = (value: Scrubber | ScrubOptions | undefined): value is Scrubber =>
  Boolean(value && typeof value === 'object' && 'findUnscrubbedSecrets' in value);

/** Returns the path to `policy.json` inside `fixturesDir`. */
export const policyPathForDirectory = (fixturesDir: string): string =>
  join(fixturesDir, POLICY_FILENAME);

/** Reads and parses `<fixturesDir>/policy.json`. */
export const fetchFreshnessPolicy = (fixturesDir: string): FreshnessPolicy => {
  const filePath = policyPathForDirectory(fixturesDir);
  if (!existsSync(filePath)) {
    throw new VcrError('invalid_cassette', `VCR: freshness policy not found at "${filePath}"`, {
      cassette: filePath,
    });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(filePath, 'utf8'));
  } catch (error) {
    throw new VcrError(
      'invalid_cassette',
      `VCR: freshness policy "${filePath}" is not valid JSON`,
      {
        cassette: filePath,
        cause: error,
      },
    );
  }
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    typeof (parsed as { maxAgeDays?: unknown }).maxAgeDays !== 'number' ||
    !(parsed as { blessed?: unknown }).blessed ||
    typeof (parsed as { blessed?: unknown }).blessed !== 'object'
  ) {
    throw new VcrError(
      'invalid_cassette',
      `VCR: freshness policy "${filePath}" must contain numeric "maxAgeDays" and object "blessed"`,
      { cassette: filePath },
    );
  }
  return parsed as FreshnessPolicy;
};

/** Writes a `FreshnessPolicy` to `<fixturesDir>/policy.json`. */
export const writeFreshnessPolicy = (fixturesDir: string, policy: FreshnessPolicy): void => {
  const filePath = policyPathForDirectory(fixturesDir);
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(policy, null, 2)}\n`);
};

/** Raises `policy.blessed` versions to match the newest committed cassettes under `fixturesDir`. */
export const blessFreshnessPolicy = (
  fixturesDir: string,
  options: BlessPolicyOptions = {},
): FreshnessPolicy => {
  const existing = fetchFreshnessPolicy(fixturesDir);
  const blessed: Record<string, string> = { ...existing.blessed };

  const raise = (key: string, candidate: string): void => {
    const current = blessed[key];
    if (!current || compareVersions(candidate, current) > 0) {
      blessed[key] = candidate;
    }
  };

  for (const filePath of fetchCassettePaths(fixturesDir, { includePending: false })) {
    let cassette: VcrCassette;
    try {
      cassette = JSON.parse(readFileSync(filePath, 'utf8')) as VcrCassette;
    } catch {
      continue;
    }
    const cli = cassette.recorded?.cli;
    if (cli && cassette.version) raise(cli, cassette.version);
    if (cassette.recorded?.metadata) {
      for (const [key, version] of Object.entries(cassette.recorded.metadata)) {
        if (key in blessed) raise(key, version);
      }
    }
  }

  if (options.metadataVersions) {
    for (const [key, version] of Object.entries(options.metadataVersions)) {
      raise(key, version);
    }
  }

  const next: FreshnessPolicy = { maxAgeDays: existing.maxAgeDays, blessed };
  writeFreshnessPolicy(fixturesDir, next);
  return next;
};

/** Validates the structure of a parsed cassette object, returning every error found. */
export const validateCassette = (raw: unknown): CassetteValidationResult => {
  const errors: string[] = [];
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { ok: false, errors: ['cassette root must be a JSON object'] };
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj.status !== 'number' || !Number.isFinite(obj.status)) {
    errors.push('missing or non-numeric "status" field');
  }
  if (
    obj.headers !== undefined &&
    (!obj.headers || typeof obj.headers !== 'object' || Array.isArray(obj.headers))
  ) {
    errors.push('"headers" must be an object when present');
  }
  if (obj.bodyFile !== undefined && typeof obj.bodyFile !== 'string') {
    errors.push('"bodyFile" must be a string when present');
  }
  if (obj.entries !== undefined && !Array.isArray(obj.entries)) {
    errors.push('"entries" must be an array when present');
  }
  if (obj.recorded !== undefined) {
    if (!obj.recorded || typeof obj.recorded !== 'object' || Array.isArray(obj.recorded)) {
      errors.push('"recorded" must be an object when present');
    } else {
      const stamp = obj.recorded as Record<string, unknown>;
      if (typeof stamp.recordedAt !== 'string' || Number.isNaN(Date.parse(stamp.recordedAt))) {
        errors.push('"recorded.recordedAt" must be a valid ISO timestamp');
      }
      if (typeof stamp.service !== 'string' || !stamp.service) {
        errors.push('"recorded.service" must be a non-empty string');
      }
    }
  }
  return { ok: errors.length === 0, errors };
};

/** Checks every cassette under `fixturesDir` for pending drift, secret leaks, expiry, and version freshness. */
export const checkCassetteFreshness = (
  fixturesDir: string,
  options: CheckFreshnessOptions = {},
): FreshnessFinding[] => {
  const policy = options.policy ?? fetchFreshnessPolicy(fixturesDir);
  const now = options.now ?? Date.now();
  const scrubber = isScrubberHandle(options.scrubber)
    ? options.scrubber
    : createScrubber(options.scrubber);

  const findings: FreshnessFinding[] = [];
  for (const filePath of fetchCassettePaths(fixturesDir, { includePending: true })) {
    const cassetteName = relative(fixturesDir, filePath);
    const push = (code: FreshnessFindingCode, problem: string): void => {
      findings.push({ cassette: cassetteName, code, problem });
    };

    if (filePath.endsWith(PENDING_CASSETTE_SUFFIX)) {
      push(
        'pending_drift',
        'unreviewed live drift; review it, then accept or discard the pending cassette',
      );
      continue;
    }

    const rawText = readFileSync(filePath, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      for (const leak of scrubber.findUnscrubbedSecrets(rawText)) {
        push('unscrubbed_secret', leak.message);
      }
      push('invalid_cassette', 'is not valid JSON');
      continue;
    }

    for (const leak of scrubber.findUnscrubbedSecrets(parsed)) {
      push('unscrubbed_secret', leak.path ? `${leak.path}: ${leak.message}` : leak.message);
    }

    const validation = validateCassette(parsed);
    if (!validation.ok) {
      for (const error of validation.errors) push('invalid_cassette', error);
      continue;
    }

    const cassette = parsed as VcrCassette;
    const recorded = cassette.recorded;
    if (!recorded?.recordedAt) {
      push('missing_stamp', 'has no recording stamp');
      continue;
    }

    const recordedAtMs = Date.parse(recorded.recordedAt);
    const ageDays = (now - recordedAtMs) / MS_PER_DAY;
    if (!(ageDays <= policy.maxAgeDays)) {
      push(
        'expired_cassette',
        `recorded ${Math.floor(ageDays)} days ago; the limit is ${policy.maxAgeDays}`,
      );
    }

    if (recorded.cli) {
      if (!cassette.version) {
        push('missing_version', `has no ${recorded.cli} version`);
      } else {
        const blessed = policy.blessed[recorded.cli];
        if (blessed && compareVersions(cassette.version, blessed) < 0) {
          push(
            'below_blessed_version',
            `recorded on ${recorded.cli} ${cassette.version}; blessed is ${blessed}`,
          );
        }
        const installed = options.installed?.[recorded.cli];
        if (installed && compareVersions(cassette.version, installed) < 0) {
          push(
            'below_installed_version',
            `recorded on ${recorded.cli} ${cassette.version}; installed is ${installed}`,
          );
        }
      }
    }

    if (recorded.metadata) {
      for (const [pkg, recordedVersion] of Object.entries(recorded.metadata)) {
        const blessedPkg = policy.blessed[pkg];
        if (blessedPkg && compareVersions(recordedVersion, blessedPkg) < 0) {
          push(
            'below_blessed_version',
            `recorded with ${pkg} ${recordedVersion}; blessed is ${blessedPkg}`,
          );
        }
        const installedPkg = options.packageVersions?.[pkg];
        if (installedPkg && compareVersions(recordedVersion, installedPkg) < 0) {
          push(
            'below_installed_version',
            `recorded with ${pkg} ${recordedVersion}; installed is ${installedPkg}`,
          );
        }
      }
    }
  }

  return findings;
};

/** Throws `VcrError('stale_cassette')` listing every finding if any cassette under `fixturesDir` fails freshness checks. */
export const assertCassettesFresh = (
  fixturesDir: string,
  options: CheckFreshnessOptions = {},
): void => {
  const findings = checkCassetteFreshness(fixturesDir, options);
  if (findings.length === 0) return;
  const summary = findings.map((finding) => `${finding.cassette}: ${finding.problem}`).join('\n');
  throw new VcrError('stale_cassette', `VCR: cassette freshness check failed:\n${summary}`, {
    details: { findings },
  });
};
