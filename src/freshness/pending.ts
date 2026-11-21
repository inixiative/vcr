import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { VcrError } from '../core/errors';
import {
  assertPathWithin,
  assertSafePathSegment,
  cassettePayloadForSignature,
  fromPendingCassettePath,
  PENDING_CASSETTE_SUFFIX,
  POLICY_FILENAME,
  writeFileAtomic,
} from '../core/fs-utils';
import type { VcrCassette } from '../core/types';
import {
  compareSignatures,
  compareVolatileSignatures,
  type SignatureOptions,
  signatureOfCassette,
} from './signature';

export { PENDING_CASSETTE_SUFFIX, POLICY_FILENAME };

export interface AcceptedDrift {
  readonly cassette: string;
  readonly pending: string;
  readonly differences: readonly string[];
}

export interface FetchCassettePathsOptions {
  /** Include `.pending.json` files in the returned list. Defaults to true. */
  readonly includePending?: boolean;
}

/** Lists all cassette JSON paths under `fixturesDir` (sorted), excluding `policy.json`, rejecting escaping symlinks. */
export const fetchCassettePaths = (
  fixturesDir: string,
  options: FetchCassettePathsOptions = {},
): string[] => {
  const includePending = options.includePending ?? true;
  const policyFile = join(fixturesDir, POLICY_FILENAME);
  const out: string[] = [];

  if (!existsSync(fixturesDir)) return out;
  const canonicalRoot = realpathSync(fixturesDir);

  const walk = (directory: string): void => {
    for (const name of readdirSync(directory)) {
      const fullPath = join(directory, name);
      const stats = lstatSync(fullPath);
      if (stats.isSymbolicLink()) {
        let targetReal: string;
        try {
          targetReal = realpathSync(fullPath);
        } catch (error) {
          throw new VcrError('invalid_cassette', `VCR: broken symlink "${fullPath}"`, {
            cassette: fullPath,
            cause: error,
          });
        }
        assertPathWithin(canonicalRoot, targetReal);
        continue;
      }
      if (stats.isDirectory()) {
        walk(fullPath);
      } else if (name.endsWith('.json') && fullPath !== policyFile) {
        if (!includePending && name.endsWith(PENDING_CASSETTE_SUFFIX)) continue;
        out.push(fullPath);
      }
    }
  };

  walk(fixturesDir);
  return out.sort();
};

/** Lists all unreviewed `.pending.json` drift cassettes under `fixturesDir`. */
export const fetchPendingCassettes = (fixturesDir: string): string[] =>
  fetchCassettePaths(fixturesDir, { includePending: true }).filter((filePath) =>
    filePath.endsWith(PENDING_CASSETTE_SUFFIX),
  );

const parseCassetteFile = (filePath: string): VcrCassette => {
  try {
    return JSON.parse(readFileSync(filePath, 'utf8')) as VcrCassette;
  } catch (error) {
    throw new VcrError('invalid_cassette', `VCR: cassette "${filePath}" contains invalid JSON`, {
      cassette: filePath,
      cause: error,
    });
  }
};

const signatureOfFile = (filePath: string, options?: SignatureOptions) => {
  const cassette = parseCassetteFile(filePath);
  return signatureOfCassette(cassette.status, cassettePayloadForSignature(cassette), options);
};

/** Returns structural differences between a committed cassette and a candidate recording file. */
export const diffCassetteDrift = (
  committedPath: string,
  candidatePath: string,
  options?: SignatureOptions,
): string[] => {
  if (!existsSync(committedPath)) return ['new cassette'];
  return compareSignatures(
    signatureOfFile(committedPath, options),
    signatureOfFile(candidatePath, options),
    options,
  );
};

/** Returns volatile (non-blocking) notice differences between two cassette JSON strings. */
export const diffVolatileCassetteNotices = (
  beforeJson: string,
  afterJson: string,
  options?: SignatureOptions,
): string[] => {
  const before = JSON.parse(beforeJson) as VcrCassette;
  const after = JSON.parse(afterJson) as VcrCassette;
  return compareVolatileSignatures(
    signatureOfCassette(before.status, cassettePayloadForSignature(before), options),
    signatureOfCassette(after.status, cassettePayloadForSignature(after), options),
    options,
  );
};

const promotedSidecarName = (bodyFile: string): string | undefined => {
  const idx = bodyFile.lastIndexOf('.pending.');
  if (idx === -1) return undefined;
  return `${bodyFile.slice(0, idx)}.${bodyFile.slice(idx + '.pending.'.length)}`;
};

interface PlannedAcceptance {
  readonly cassettePath: string;
  readonly pendingPath: string;
  readonly differences: readonly string[];
  readonly pendingCassette: VcrCassette;
  readonly pendingSidecarPath?: string;
  readonly promotedSidecarPath?: string;
  readonly promotedBodyFile?: string;
}

/** Atomically validates and promotes every `.pending.json` recording (and pending binary sidecar) under `fixturesDir`. */
export const acceptPendingCassettes = (
  fixturesDir: string,
  options?: SignatureOptions,
): AcceptedDrift[] => {
  const pendingPaths = fetchPendingCassettes(fixturesDir);
  const plan: PlannedAcceptance[] = [];

  // Pass 1: parse, validate paths/sidecars, and compute all diffs before mutating disk.
  for (const pendingPath of pendingPaths) {
    const cassettePath = assertPathWithin(fixturesDir, fromPendingCassettePath(pendingPath));
    const pendingCassette = parseCassetteFile(pendingPath);
    const differences = diffCassetteDrift(cassettePath, pendingPath, options);

    let pendingSidecarPath: string | undefined;
    let promotedSidecarPath: string | undefined;
    let promotedBodyFile: string | undefined;
    if (pendingCassette.bodyFile) {
      assertSafePathSegment(pendingCassette.bodyFile, 'bodyFile');
      const dir = dirname(pendingPath);
      const nextName = promotedSidecarName(pendingCassette.bodyFile);
      if (nextName) {
        assertSafePathSegment(nextName, 'bodyFile');
        pendingSidecarPath = assertPathWithin(dir, join(dir, pendingCassette.bodyFile));
        if (!existsSync(pendingSidecarPath)) {
          throw new VcrError(
            'invalid_cassette',
            `VCR: pending cassette "${pendingPath}" references missing binary sidecar "${pendingCassette.bodyFile}"`,
            { cassette: pendingPath },
          );
        }
        promotedSidecarPath = assertPathWithin(dir, join(dir, nextName));
        promotedBodyFile = nextName;
      }
    }

    plan.push({
      cassettePath,
      pendingPath,
      differences,
      pendingCassette,
      pendingSidecarPath,
      promotedSidecarPath,
      promotedBodyFile,
    });
  }

  // Pass 2: promote sidecars and cassettes atomically.
  const accepted: AcceptedDrift[] = [];
  for (const item of plan) {
    if (item.pendingSidecarPath && item.promotedSidecarPath && item.promotedBodyFile) {
      renameSync(item.pendingSidecarPath, item.promotedSidecarPath);
      const promoted: VcrCassette = {
        ...item.pendingCassette,
        bodyFile: item.promotedBodyFile,
      };
      writeFileAtomic(item.cassettePath, `${JSON.stringify(promoted, null, 2)}\n`);
      rmSync(item.pendingPath, { force: true });
    } else {
      renameSync(item.pendingPath, item.cassettePath);
    }
    accepted.push({
      cassette: item.cassettePath,
      pending: item.pendingPath,
      differences: item.differences,
    });
  }

  return accepted;
};

/** Deletes every `.pending.json` drift file (and any associated pending binary sidecar) under `fixturesDir`. */
export const discardPendingCassettes = (fixturesDir: string): string[] => {
  const pending = fetchPendingCassettes(fixturesDir);
  for (const filePath of pending) {
    try {
      const parsed = JSON.parse(readFileSync(filePath, 'utf8')) as VcrCassette;
      if (parsed.bodyFile && promotedSidecarName(parsed.bodyFile)) {
        assertSafePathSegment(parsed.bodyFile, 'bodyFile');
        const dir = dirname(filePath);
        const sidecarPath = assertPathWithin(dir, join(dir, parsed.bodyFile));
        rmSync(sidecarPath, { force: true });
      }
    } catch {
      /* Invalid JSON pending file still gets discarded below. */
    }
    rmSync(filePath, { force: true });
  }
  return pending;
};
