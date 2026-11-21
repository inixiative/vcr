export interface CassetteSignature {
  readonly status: number;
  readonly shape: Readonly<Record<string, readonly string[]>>;
}

export interface SignatureOptions {
  /** Maximum object/array nesting depth included in shape paths. Defaults to 3. */
  readonly maxDepth?: number;
  /** Pattern for dynamic ID-keyed object properties collapsed to `<id>`. */
  readonly idKeyPattern?: RegExp;
  /** Event kinds whose presence or shape changes are notices rather than drift. */
  readonly volatileKinds?: readonly RegExp[];
  /** Dotted paths inside events whose changes are notices rather than drift. */
  readonly volatilePaths?: readonly RegExp[];
  /** Custom event discriminator extractor for transcript frames. */
  readonly eventKindOf?: (event: unknown) => string;
}

export const DEFAULT_SIGNATURE_MAX_DEPTH = 3;
export const DEFAULT_ID_KEY_PATTERN = /^[a-z]+_[A-Za-z0-9]{16,}$/;
export const DEFAULT_VOLATILE_KINDS: readonly RegExp[] = [/^stderr$/];
export const DEFAULT_VOLATILE_PATHS: readonly RegExp[] = [];

const collectPaths = (
  value: unknown,
  maxDepth: number,
  idKeyPattern: RegExp,
  prefix = '',
  depth = 0,
  out = new Set<string>(),
  ancestors = new WeakSet<object>(),
): Set<string> => {
  if (Array.isArray(value)) {
    if (depth >= maxDepth) {
      out.add(`${prefix}[]`);
      return out;
    }
    if (ancestors.has(value)) {
      out.add(`${prefix}[]:circular`);
      return out;
    }
    if (!value.length) out.add(`${prefix}[]`);
    ancestors.add(value);
    try {
      for (const item of value) {
        collectPaths(item, maxDepth, idKeyPattern, `${prefix}[]`, depth + 1, out, ancestors);
      }
    } finally {
      ancestors.delete(value);
    }
    return out;
  }

  if (value && typeof value === 'object') {
    if (depth >= maxDepth) {
      out.add(`${prefix}{}`);
      return out;
    }
    if (ancestors.has(value)) {
      out.add(`${prefix}{}:circular`);
      return out;
    }
    ancestors.add(value);
    try {
      const entries = Object.entries(value);
      if (!entries.length && prefix) out.add(`${prefix}{}`);
      for (const [rawKey, child] of entries) {
        const key = idKeyPattern.test(rawKey) ? '<id>' : rawKey;
        const nextPrefix = prefix ? `${prefix}.${key}` : key;
        collectPaths(child, maxDepth, idKeyPattern, nextPrefix, depth + 1, out, ancestors);
      }
    } finally {
      ancestors.delete(value);
    }
    return out;
  }

  out.add(`${prefix}:${value === null ? 'null' : typeof value}`);
  return out;
};

/** Extracts a structural discriminator string for a protocol event or JSON-RPC message. */
export const eventKindOf = (event: unknown): string => {
  if (!event || typeof event !== 'object') return typeof event;
  const record = event as Record<string, unknown>;
  const item = record.item as Record<string, unknown> | undefined;
  const params = record.params as Record<string, unknown> | undefined;
  const nestedItem = params?.item as Record<string, unknown> | undefined;
  const nested = (item?.type ?? nestedItem?.type) as string | undefined;

  const message = record.message as { content?: unknown } | undefined;
  const blocks = Array.isArray(message?.content)
    ? [
        ...new Set(
          (message.content as Array<{ type?: unknown }>)
            .map((block) => block?.type)
            .filter((type): type is string => typeof type === 'string'),
        ),
      ]
        .sort()
        .join('+')
    : undefined;

  const parts = [record.type, record.subtype, record.method, nested, blocks || undefined].filter(
    (part): part is string => typeof part === 'string',
  );
  if (parts.length) return parts.join(':');
  if ('id' in record && ('result' in record || 'error' in record)) {
    return 'result' in record ? 'rpc:result' : 'rpc:error';
  }
  return 'object';
};

const parseFrameJson = (line: string): unknown => {
  try {
    return JSON.parse(line);
  } catch {
    return line;
  }
};

interface TranscriptLike {
  readonly kind: 'process' | 'websocket';
  readonly argv?: readonly string[];
  readonly frames: ReadonlyArray<{
    readonly stream: string;
    readonly data: string;
    readonly kept?: true;
  }>;
  readonly exit?: { readonly code: number | null };
}

const isTranscriptLike = (body: unknown): body is TranscriptLike => {
  if (!body || typeof body !== 'object') return false;
  const candidate = body as { kind?: unknown; frames?: unknown };
  return (
    (candidate.kind === 'process' || candidate.kind === 'websocket') &&
    Array.isArray(candidate.frames)
  );
};

/** Computes a structural signature of a cassette response or transcript independent of variable values. */
export const signatureOfCassette = (
  status: number,
  body: unknown,
  options: SignatureOptions = {},
): CassetteSignature => {
  const maxDepth = options.maxDepth ?? DEFAULT_SIGNATURE_MAX_DEPTH;
  const idKeyPattern = options.idKeyPattern ?? DEFAULT_ID_KEY_PATTERN;
  const resolveEventKind = options.eventKindOf ?? eventKindOf;

  const shape: Record<string, Set<string>> = {};
  const kindSet = (kind: string): Set<string> => {
    const existing = shape[kind];
    if (existing) return existing;
    const created = new Set<string>();
    shape[kind] = created;
    return created;
  };
  const addShape = (kind: string, value: unknown): void => {
    const set = kindSet(kind);
    for (const path of collectPaths(value, maxDepth, idKeyPattern)) set.add(path);
  };

  if (isTranscriptLike(body)) {
    if (body.argv) {
      shape.argv = new Set(body.argv.filter((arg) => arg.startsWith('-')));
    }
    for (const frame of body.frames) {
      if (frame.stream === 'stderr') {
        if (frame.kept) {
          kindSet('stderr:kept').add(`text:${frame.data.replace(/\bpid \d+/g, 'pid N')}`);
        } else {
          kindSet('stderr').add('text');
        }
        continue;
      }
      const event = parseFrameJson(frame.data);
      addShape(`${frame.stream}:${resolveEventKind(event)}`, event);
    }
    if (body.exit) {
      shape.exit = new Set([String(body.exit.code)]);
    }
  } else {
    addShape('body', body);
  }

  return {
    status,
    shape: Object.fromEntries(
      Object.entries(shape)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([kind, set]) => [kind, [...set].sort()]),
    ),
  };
};

const diffShapeEntries = (
  before: CassetteSignature,
  after: CassetteSignature,
  pickKind: (kind: string) => boolean,
  pickPath: (path: string) => boolean = () => true,
): string[] => {
  const differences: string[] = [];
  const kinds = new Set([...Object.keys(before.shape), ...Object.keys(after.shape)]);
  for (const kind of [...kinds].sort().filter(pickKind)) {
    const was = before.shape[kind];
    const now = after.shape[kind];
    if (!was) {
      differences.push(`new ${kind}`);
      continue;
    }
    if (!now) {
      differences.push(`missing ${kind}`);
      continue;
    }
    const added = now.filter((path) => !was.includes(path) && pickPath(path));
    const removed = was.filter((path) => !now.includes(path) && pickPath(path));
    if (added.length) differences.push(`${kind} added ${added.join(', ')}`);
    if (removed.length) differences.push(`${kind} removed ${removed.join(', ')}`);
  }
  return differences;
};

const isVolatileKind = (kind: string, patterns: readonly RegExp[]): boolean =>
  patterns.some((pattern) => pattern.test(kind));

const isVolatilePath = (path: string, patterns: readonly RegExp[]): boolean =>
  patterns.some((pattern) => pattern.test(path));

/** Returns human-readable structural drift between two signatures, excluding configured volatile kinds/paths. */
export const compareSignatures = (
  before: CassetteSignature,
  after: CassetteSignature,
  options: SignatureOptions = {},
): string[] => {
  const volatileKinds = options.volatileKinds ?? DEFAULT_VOLATILE_KINDS;
  const volatilePaths = options.volatilePaths ?? DEFAULT_VOLATILE_PATHS;
  return [
    ...(before.status !== after.status ? [`status ${before.status} -> ${after.status}`] : []),
    ...diffShapeEntries(
      before,
      after,
      (kind) => !isVolatileKind(kind, volatileKinds),
      (path) => !isVolatilePath(path, volatilePaths),
    ),
  ];
};

/** Returns differences limited to volatile kinds/paths so callers can log notices without holding back recordings. */
export const compareVolatileSignatures = (
  before: CassetteSignature,
  after: CassetteSignature,
  options: SignatureOptions = {},
): string[] => {
  const volatileKinds = options.volatileKinds ?? DEFAULT_VOLATILE_KINDS;
  const volatilePaths = options.volatilePaths ?? DEFAULT_VOLATILE_PATHS;
  return [
    ...diffShapeEntries(before, after, (kind) => isVolatileKind(kind, volatileKinds)),
    ...diffShapeEntries(
      before,
      after,
      (kind) => !isVolatileKind(kind, volatileKinds),
      (path) => isVolatilePath(path, volatilePaths),
    ),
  ];
};
