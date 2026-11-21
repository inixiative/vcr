import { existsSync, readdirSync, readFileSync, renameSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { VcrCassette } from '../core/types';
import {
  compareSignatures,
  compareVolatileSignatures,
  type SignatureOptions,
  signatureOfCassette,
} from './signature';

export const PENDING_CASSETTE_SUFFIX = '.pending.json';
export const POLICY_FILENAME = 'policy.json';

export interface AcceptedDrift {
  readonly cassette: string;
  readonly pending: string;
  readonly differences: readonly string[];
}

export interface FetchCassettePathsOptions {
  /** Include `.pending.json` files in the returned list. Defaults to true. */
  readonly includePending?: boolean;
}

/** Lists all cassette JSON paths under `fixturesDir` (sorted), excluding `policy.json`. */
export const fetchCassettePaths = (
  fixturesDir: string,
  options: FetchCassettePathsOptions = {},
): string[] => {
  const includePending = options.includePending ?? true;
  const policyFile = join(fixturesDir, POLICY_FILENAME);
  const out: string[] = [];

  const walk = (directory: string): void => {
    for (const name of readdirSync(directory)) {
      const fullPath = join(directory, name);
      if (statSync(fullPath).isDirectory()) {
        walk(fullPath);
      } else if (name.endsWith('.json') && fullPath !== policyFile) {
        if (!includePending && name.endsWith(PENDING_CASSETTE_SUFFIX)) continue;
        out.push(fullPath);
      }
    }
  };

  if (existsSync(fixturesDir)) walk(fixturesDir);
  return out.sort();
};

/** Lists all unreviewed `.pending.json` drift cassettes under `fixturesDir`. */
export const fetchPendingCassettes = (fixturesDir: string): string[] =>
  fetchCassettePaths(fixturesDir, { includePending: true }).filter((filePath) =>
    filePath.endsWith(PENDING_CASSETTE_SUFFIX),
  );

const parseCassetteFile = (filePath: string): VcrCassette =>
  JSON.parse(readFileSync(filePath, 'utf8')) as VcrCassette;

const signatureOfFile = (filePath: string, options?: SignatureOptions) => {
  const cassette = parseCassetteFile(filePath);
  const payload = cassette.entries !== undefined ? { entries: cassette.entries } : cassette.body;
  return signatureOfCassette(cassette.status, payload, options);
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
  const beforePayload = before.entries !== undefined ? { entries: before.entries } : before.body;
  const afterPayload = after.entries !== undefined ? { entries: after.entries } : after.body;
  return compareVolatileSignatures(
    signatureOfCassette(before.status, beforePayload, options),
    signatureOfCassette(after.status, afterPayload, options),
    options,
  );
};

/** Promotes every `.pending.json` recording under `fixturesDir` to replace its committed cassette. */
export const acceptPendingCassettes = (
  fixturesDir: string,
  options?: SignatureOptions,
): AcceptedDrift[] => {
  const accepted: AcceptedDrift[] = [];
  for (const pendingPath of fetchPendingCassettes(fixturesDir)) {
    const cassettePath = pendingPath.replace(/\.pending\.json$/, '.json');
    const differences = diffCassetteDrift(cassettePath, pendingPath, options);
    renameSync(pendingPath, cassettePath);
    accepted.push({ cassette: cassettePath, pending: pendingPath, differences });
  }
  return accepted;
};

/** Deletes every `.pending.json` drift file under `fixturesDir` without touching committed cassettes. */
export const discardPendingCassettes = (fixturesDir: string): string[] => {
  const pending = fetchPendingCassettes(fixturesDir);
  for (const filePath of pending) rmSync(filePath, { force: true });
  return pending;
};
