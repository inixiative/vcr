import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { VcrError } from './errors';
import type { VcrCassette } from './types';

export const PENDING_CASSETTE_SUFFIX = '.pending.json';
export const POLICY_FILENAME = 'policy.json';

const SAFE_BINARY_EXT_PATTERN = /^\.[A-Za-z0-9._-]+$/;

/** Asserts that a single path segment contains no traversal tokens, separators, or null bytes. */
export const assertSafePathSegment = (value: string, fieldName: string): void => {
  if (
    !value ||
    value === '.' ||
    value === '..' ||
    value.includes('/') ||
    value.includes('\\') ||
    value.includes('\0') ||
    value.includes('..')
  ) {
    throw new VcrError(
      'invalid_cassette',
      `VCR: invalid ${fieldName} "${value}" (must be a single safe path segment)`,
    );
  }
};

/** Asserts that a binary sidecar extension starts with `.` and contains no path traversal. */
export const assertSafeBinaryExtension = (ext: string): string => {
  if (!SAFE_BINARY_EXT_PATTERN.test(ext) || ext.includes('..')) {
    throw new VcrError(
      'invalid_cassette',
      `VCR: invalid binaryExtension "${ext}" (must start with "." and contain no path separators)`,
    );
  }
  return ext;
};

/** Asserts that `candidatePath` resolves strictly inside `rootDir`, preventing path traversal. */
export const assertPathWithin = (rootDir: string, candidatePath: string): string => {
  const root = resolve(rootDir);
  const target = resolve(candidatePath);
  const rel = relative(root, target);
  if (
    !rel ||
    rel === '..' ||
    rel.startsWith(`..${sep}`) ||
    rel.startsWith('../') ||
    isAbsolute(rel)
  ) {
    throw new VcrError(
      'invalid_cassette',
      `VCR: path "${candidatePath}" escapes root directory "${rootDir}"`,
      { cassette: candidatePath },
    );
  }
  return target;
};

/** Writes a file atomically via a same-directory temp file + rename, cleaning up on failure. */
export const writeFileAtomic = (filePath: string, content: string | Uint8Array): void => {
  mkdirSync(dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.tmp-${process.pid}-${randomUUID()}`;
  try {
    writeFileSync(tempPath, content);
    renameSync(tempPath, filePath);
  } catch (error) {
    rmSync(tempPath, { force: true });
    throw error;
  }
};

/** Converts a `.json` cassette path to its `.pending.json` hold-back path. */
export const toPendingCassettePath = (filePath: string): string => {
  if (filePath.endsWith(PENDING_CASSETTE_SUFFIX)) return filePath;
  if (!filePath.endsWith('.json')) {
    throw new VcrError(
      'invalid_cassette',
      `VCR: expected a .json cassette path, received "${filePath}"`,
      { cassette: filePath },
    );
  }
  return `${filePath.slice(0, -'.json'.length)}${PENDING_CASSETTE_SUFFIX}`;
};

/** Converts a `.pending.json` path back to its committed `.json` path. */
export const fromPendingCassettePath = (filePath: string): string => {
  if (!filePath.endsWith(PENDING_CASSETTE_SUFFIX)) {
    throw new VcrError(
      'invalid_cassette',
      `VCR: expected a ${PENDING_CASSETTE_SUFFIX} path, received "${filePath}"`,
      { cassette: filePath },
    );
  }
  return `${filePath.slice(0, -PENDING_CASSETTE_SUFFIX.length)}.json`;
};

/** Computes a sidecar filename beside a cassette path (inserting `.pending` when target is pending). */
export const sidecarNameForCassette = (cassettePath: string, extension: string): string => {
  const safeExt = assertSafeBinaryExtension(extension);
  if (cassettePath.endsWith(PENDING_CASSETTE_SUFFIX)) {
    const base = basename(cassettePath, PENDING_CASSETTE_SUFFIX);
    return `${base}.pending${safeExt}`;
  }
  const base = basename(cassettePath, extname(cassettePath));
  return `${base}${safeExt}`;
};

/** Returns the signature payload for a cassette (`{ entries }` for multi-entry cassettes, else `body`). */
export const cassettePayloadForSignature = (
  cassette: Pick<VcrCassette, 'body' | 'entries'>,
): unknown => (cassette.entries !== undefined ? { entries: cassette.entries } : cassette.body);

/** Reads a cassette's body, loading and path-validating any binary `bodyFile` sidecar. */
export const readCassetteBody = <T>(cassette: VcrCassette<unknown, T>, cassettePath: string): T => {
  if (!cassette.bodyFile) return cassette.body as T;
  assertSafePathSegment(cassette.bodyFile, 'bodyFile');
  const cassetteDir = dirname(cassettePath);
  const sidecarPath = assertPathWithin(cassetteDir, join(cassetteDir, cassette.bodyFile));
  return readFileSync(sidecarPath) as unknown as T;
};
