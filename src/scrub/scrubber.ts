import { realpathSync } from 'node:fs';
import { hostname, tmpdir, userInfo } from 'node:os';
import { VcrError } from '../core/errors';
import {
  BUILT_IN_SECRET_DETECTORS,
  DEFAULT_IDENTITY_KEY_PATTERN,
  DEFAULT_SECRET_HEADERS,
  DEFAULT_SECRET_KEY_PATTERN,
  DEFAULT_SECRET_QUERY_PARAMS,
  defaultPlaceholderFor,
  EMAIL_PATTERN,
  GENERIC_OS_USERNAMES,
  HOME_PATH_LEAK_PATTERN,
  INLINE_ENV_SECRET_PATTERN,
  IPV4_PATTERN,
  IPV6_PATTERN,
  SAFE_PLACEHOLDER_PATTERN,
  UUID_EXACT_PATTERN,
  UUID_GLOBAL_PATTERN,
} from './patterns';
import type {
  HeaderInput,
  LeakFinding,
  Scrubber,
  ScrubContext,
  ScrubOptions,
  ScrubPlaceholderKind,
  ScrubPlaceholderResolver,
  ScrubRule,
} from './types';

const DEFAULT_MIN_KNOWN_SECRET_LENGTH = 4;
const MAX_EMBEDDED_JSON_ATTEMPTS = 64;
const MAX_EMBEDDED_JSON_SLICE_BYTES = 256 * 1024;
const SECRET_KEY_REDACTED_SEGMENT = '<secret-key>';

const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const ensureGlobalFlags = (flags: string): string =>
  flags.includes('g') ? flags.replace(/y/g, '') : `${flags.replace(/y/g, '')}g`;

const stripStatefulFlags = (pattern: RegExp): RegExp =>
  new RegExp(pattern.source, pattern.flags.replace(/[gy]/g, ''));

const safeDecodeURIComponent = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

const pathVariants = (path: string | undefined): string[] => {
  if (!path) return [];
  const normalized = path.replace(/\/+$/, '');
  if (normalized.length <= 1) return [];
  const out = new Set<string>([normalized]);
  try {
    out.add(realpathSync(normalized).replace(/\/+$/, ''));
  } catch {
    /* Non-existent paths only have their lexical spelling. */
  }
  for (const candidate of [...out]) {
    if (candidate.startsWith('/private/')) out.add(candidate.slice('/private'.length));
  }
  return [...out].filter((value) => value.length > 1).sort((a, b) => b.length - a.length);
};

/** Returns the real OS user's home directory, independent of temporary HOME overrides. */
export const accountHomeDirectory = (): string => userInfo().homedir;

const buildPathRules = (context: ScrubContext): Array<[RegExp, string]> => {
  const rules: Array<[RegExp, string]> = [];
  if (context.pathPlaceholders) {
    for (const [placeholder, rawPath] of Object.entries(context.pathPlaceholders)) {
      for (const variant of pathVariants(rawPath)) {
        rules.push([new RegExp(escapeRegExp(variant), 'g'), placeholder]);
      }
    }
  }
  for (const cwd of pathVariants(context.cwd)) {
    rules.push([new RegExp(escapeRegExp(cwd), 'g'), '{{cwd}}']);
  }
  for (const temp of pathVariants(tmpdir())) {
    rules.push([new RegExp(escapeRegExp(temp), 'g'), '{{tmp}}']);
  }
  for (const home of pathVariants(accountHomeDirectory())) {
    rules.push([new RegExp(escapeRegExp(home), 'g'), '~']);
  }
  const username = userInfo().username;
  if (username.length > 2 && !GENERIC_OS_USERNAMES.has(username.toLowerCase())) {
    rules.push([new RegExp(`\\b${escapeRegExp(username)}\\b`, 'gi'), 'user']);
  }
  const shortHost = hostname().split('.')[0] ?? '';
  if (
    shortHost.length > 2 &&
    shortHost.toLowerCase() !== 'localhost' &&
    shortHost.toLowerCase() !== 'host'
  ) {
    rules.push([new RegExp(`\\b${escapeRegExp(shortHost)}(\\.[A-Za-z0-9-]+)*\\b`, 'gi'), 'host']);
  }
  return rules;
};

const mergeContexts = (
  base: ScrubContext | undefined,
  override: ScrubContext | undefined,
): ScrubContext => {
  if (!base) return override ?? {};
  if (!override) return base;
  return {
    cwd: override.cwd ?? base.cwd,
    pathPlaceholders:
      base.pathPlaceholders || override.pathPlaceholders
        ? { ...base.pathPlaceholders, ...override.pathPlaceholders }
        : undefined,
  };
};

const buildKnownSecretsPattern = (
  secrets: readonly string[] | undefined,
  minLength: number,
): RegExp | undefined => {
  if (!secrets?.length) return undefined;
  const expanded = new Set<string>();
  for (const raw of secrets) {
    const trimmed = raw.trim();
    if (trimmed.length < minLength) continue;
    expanded.add(raw);
    if (trimmed !== raw) expanded.add(trimmed);
    const encoded = encodeURIComponent(raw);
    if (encoded !== raw) expanded.add(encoded);
    const encodedTrimmed = encodeURIComponent(trimmed);
    if (encodedTrimmed !== trimmed) expanded.add(encodedTrimmed);
  }
  const sorted = [...expanded].sort((a, b) => b.length - a.length);
  if (sorted.length === 0) return undefined;
  return new RegExp(sorted.map(escapeRegExp).join('|'), 'g');
};

const buildQueryParamPattern = (paramNames: ReadonlySet<string>): RegExp => {
  const escaped = [...paramNames].map(escapeRegExp).sort((a, b) => b.length - a.length);
  return new RegExp(
    `([?&#](?:${escaped.join('|')})=)(?!<REDACTED:|REDACTED\\b)([^&#\\s"']+)`,
    'gi',
  );
};

const applyCustomRule = (text: string, rule: ScrubRule): string => {
  const regex = new RegExp(rule.pattern.source, ensureGlobalFlags(rule.pattern.flags));
  if (typeof rule.placeholder === 'function') {
    const fn = rule.placeholder;
    return text.replace(regex, (match, ...args: unknown[]) => {
      const groups = args.filter((item): item is string => typeof item === 'string');
      return fn(match, ...groups);
    });
  }
  const literal = rule.placeholder;
  return text.replace(regex, () => literal);
};

const ALL_PLACEHOLDER_KINDS: readonly ScrubPlaceholderKind[] = [
  'secret',
  'bearer',
  'basic',
  'dpop',
  'fly_token',
  'jwt',
  'private_key',
  'anthropic_key',
  'openai_key',
  'github_token',
  'google_key',
  'slack_token',
  'slack_webhook',
  'render_token',
  'kingdom_token',
  'aws_key',
  'provider_token',
  'api_token',
  'url_credential',
  'header_secret',
  'key_secret',
  'query_secret',
  'email',
  'ip',
  'uuid',
];

const buildSafePlaceholderSet = (
  placeholderFor: ScrubPlaceholderResolver,
  extraSafeValues: ReadonlySet<string>,
): Set<string> => {
  const values = new Set<string>(extraSafeValues);
  for (const kind of ALL_PLACEHOLDER_KINDS) {
    const sample = placeholderFor(kind, '');
    if (!sample) continue;
    values.add(sample);
    if (kind === 'bearer') values.add(`Bearer ${sample}`);
    if (kind === 'basic') values.add(`Basic ${sample}`);
    if (kind === 'dpop') values.add(`DPoP ${sample}`);
    if (kind === 'fly_token') values.add(`FlyV1 ${sample}`);
  }
  return values;
};

const isSafePlaceholder = (
  value: string,
  safeValues: ReadonlySet<string>,
  safeLower: ReadonlySet<string>,
): boolean => {
  if (value === '') return true;
  if (SAFE_PLACEHOLDER_PATTERN.test(value)) return true;
  if (safeValues.has(value)) return true;
  return safeLower.has(value.toLowerCase());
};

const collectSafeSpans = (
  text: string,
  safeValues: ReadonlySet<string>,
): Array<readonly [number, number]> => {
  const spans: Array<readonly [number, number]> = [];
  for (const match of text.matchAll(/<REDACTED(?::[A-Z0-9_-]+)?>/gi)) {
    const idx = match.index;
    if (idx !== undefined) spans.push([idx, idx + match[0].length]);
  }
  for (const token of safeValues) {
    if (!token || token.startsWith('<REDACTED')) continue;
    let at = text.indexOf(token);
    while (at !== -1) {
      spans.push([at, at + token.length]);
      at = text.indexOf(token, at + token.length);
    }
  }
  return spans;
};

const isInsideSpans = (
  start: number,
  end: number,
  spans: ReadonlyArray<readonly [number, number]>,
): boolean => spans.some(([s, e]) => start >= s && end <= e);

/** Linear scanner for `"key": "value"` and `\"key\": \"value\"` pairs inside arbitrary text. */
const extractJsonStringPairs = (text: string): Array<readonly [string, string]> => {
  const pairs: Array<readonly [string, string]> = [];
  const len = text.length;
  let i = 0;

  const readQuoted = (
    pos: number,
    escaped: boolean,
  ): { value: string; next: number } | undefined => {
    let cur = pos;
    let out = '';
    while (cur < len) {
      const ch = text[cur];
      if (escaped) {
        if (ch === '\\' && text[cur + 1] === '"') {
          return { value: out, next: cur + 2 };
        }
        if (ch === '\\' && cur + 1 < len) {
          out += text[cur + 1];
          cur += 2;
          continue;
        }
        if (ch === '"') return undefined;
      } else {
        if (ch === '"') return { value: out, next: cur + 1 };
        if (ch === '\\' && cur + 1 < len) {
          out += text[cur + 1];
          cur += 2;
          continue;
        }
      }
      out += ch ?? '';
      cur++;
    }
    return undefined;
  };

  while (i < len) {
    const isEscapedQuote = text[i] === '\\' && text[i + 1] === '"';
    const isRawQuote = text[i] === '"';
    if (!isEscapedQuote && !isRawQuote) {
      i++;
      continue;
    }

    const keyStart = isEscapedQuote ? i + 2 : i + 1;
    const keyRes = readQuoted(keyStart, isEscapedQuote);
    if (!keyRes) {
      i++;
      continue;
    }

    let j = keyRes.next;
    while (
      j < len &&
      (text[j] === ' ' || text[j] === '\t' || text[j] === '\r' || text[j] === '\n')
    ) {
      j++;
    }
    if (text[j] !== ':') {
      i = keyRes.next;
      continue;
    }
    j++;
    while (
      j < len &&
      (text[j] === ' ' || text[j] === '\t' || text[j] === '\r' || text[j] === '\n')
    ) {
      j++;
    }

    const valMatchesQuote = isEscapedQuote
      ? text[j] === '\\' && text[j + 1] === '"'
      : text[j] === '"';
    if (!valMatchesQuote) {
      i = j;
      continue;
    }

    const valStart = isEscapedQuote ? j + 2 : j + 1;
    const valRes = readQuoted(valStart, isEscapedQuote);
    if (!valRes) {
      i = j + 1;
      continue;
    }

    if (/^[A-Za-z0-9_-]+$/.test(keyRes.value)) {
      pairs.push([keyRes.value, valRes.value]);
    }
    i = valRes.next;
  }

  return pairs;
};

const scrubAuthorizationHeaderValue = (
  value: string,
  placeholderFor: ScrubPlaceholderResolver,
): string => {
  const trimmed = value.trim();
  if (/^Bearer\s+/i.test(trimmed)) return `Bearer ${placeholderFor('bearer', trimmed)}`;
  if (/^Basic\s+/i.test(trimmed)) return `Basic ${placeholderFor('basic', trimmed)}`;
  if (/^DPoP\s+/i.test(trimmed)) return `DPoP ${placeholderFor('dpop', trimmed)}`;
  if (/^FlyV1\s+/i.test(trimmed)) return `FlyV1 ${placeholderFor('fly_token', trimmed)}`;
  return placeholderFor('header_secret', trimmed);
};

const toHeaderEntries = (headers: HeaderInput): Array<[string, string]> => {
  if (headers instanceof Headers) {
    const entries: Array<[string, string]> = [];
    headers.forEach((value, key) => {
      entries.push([key, value]);
    });
    return entries;
  }
  if (Array.isArray(headers)) {
    return headers.map(([key, value]) => [key, value]);
  }
  return Object.entries(headers);
};

export const createScrubber = (options: ScrubOptions = {}): Scrubber => {
  const placeholderFor = options.placeholderFor ?? defaultPlaceholderFor;
  const minKnownSecretLength = options.minKnownSecretLength ?? DEFAULT_MIN_KNOWN_SECRET_LENGTH;
  const knownSecretsPattern = buildKnownSecretsPattern(options.knownSecrets, minKnownSecretLength);
  const customRules = options.rules ?? [];
  const scrubPaths = options.scrubPaths ?? true;
  const scrubEmails = options.scrubEmails ?? true;
  const scrubIps = options.scrubIps ?? false;
  const scrubUuids = options.scrubUuids ?? false;

  const secretHeaders = new Set<string>(DEFAULT_SECRET_HEADERS);
  for (const header of options.extraSecretHeaders ?? []) {
    secretHeaders.add(header.toLowerCase());
  }

  const secretQueryParams = new Set<string>(DEFAULT_SECRET_QUERY_PARAMS);
  for (const param of options.extraSecretQueryParams ?? []) {
    secretQueryParams.add(param.toLowerCase());
  }
  const queryParamPattern = buildQueryParamPattern(secretQueryParams);

  const extraSecretKeys = (options.extraSecretKeyPatterns ?? []).map(stripStatefulFlags);
  const extraIdentityKeys = (options.extraIdentityKeyPatterns ?? []).map(stripStatefulFlags);

  const isSecretKey = (key: string): boolean =>
    secretHeaders.has(key.toLowerCase()) ||
    DEFAULT_SECRET_KEY_PATTERN.test(key) ||
    extraSecretKeys.some((pattern) => pattern.test(key));

  const isIdentityKey = (key: string): boolean =>
    DEFAULT_IDENTITY_KEY_PATTERN.test(key) ||
    extraIdentityKeys.some((pattern) => pattern.test(key));

  const customPlaceholderValues = new Set<string>();
  for (const rule of customRules) {
    if (typeof rule.placeholder === 'string') customPlaceholderValues.add(rule.placeholder);
  }
  const safePlaceholderValues = buildSafePlaceholderSet(placeholderFor, customPlaceholderValues);
  const safePlaceholderLower = new Set<string>(
    [...safePlaceholderValues].map((v) => v.toLowerCase()),
  );

  const pathRuleCache = new Map<string, Array<[RegExp, string]>>();
  const resolvePathRules = (context: ScrubContext): Array<[RegExp, string]> => {
    if (!scrubPaths) return [];
    const cacheKey = JSON.stringify({
      cwd: context.cwd ?? '',
      pathPlaceholders: context.pathPlaceholders ?? {},
    });
    const cached = pathRuleCache.get(cacheKey);
    if (cached) return cached;
    const computed = buildPathRules(context);
    pathRuleCache.set(cacheKey, computed);
    return computed;
  };

  const scrubKnownSecrets = (text: string): string => {
    if (!knownSecretsPattern || !text) return text;
    return text.replace(new RegExp(knownSecretsPattern.source, 'g'), (match) =>
      placeholderFor('secret', match),
    );
  };

  const scrubText = (text: string, overrideContext?: ScrubContext): string => {
    if (!text) return text;
    const context = mergeContexts(options.context, overrideContext);
    let out = scrubKnownSecrets(text);

    for (const [pattern, replacement] of resolvePathRules(context)) {
      const literal = replacement;
      out = out.replace(new RegExp(pattern.source, pattern.flags), () => literal);
    }

    for (const detector of BUILT_IN_SECRET_DETECTORS) {
      const regex = new RegExp(detector.pattern.source, ensureGlobalFlags(detector.pattern.flags));
      out = out.replace(regex, (match, ...args: unknown[]) => {
        const placeholder = placeholderFor(detector.kind, match);
        if (detector.preserveGroup !== undefined) {
          const groupVal = args[detector.preserveGroup - 1];
          const prefix = typeof groupVal === 'string' ? groupVal : '';
          return `${prefix}${placeholder}${detector.suffix ?? ''}`;
        }
        return placeholder;
      });
    }

    out = out.replace(
      new RegExp(queryParamPattern.source, ensureGlobalFlags(queryParamPattern.flags)),
      (match, prefix: string, valuePart: string) =>
        isSafePlaceholder(valuePart, safePlaceholderValues, safePlaceholderLower)
          ? match
          : `${prefix}${placeholderFor('query_secret', match)}`,
    );

    out = out.replace(
      new RegExp(
        INLINE_ENV_SECRET_PATTERN.source,
        ensureGlobalFlags(INLINE_ENV_SECRET_PATTERN.flags),
      ),
      (match, prefix: string, quote: string, valuePart: string) =>
        isSafePlaceholder(valuePart, safePlaceholderValues, safePlaceholderLower)
          ? match
          : `${prefix}${quote}${placeholderFor('secret', match)}${quote}`,
    );

    if (scrubEmails) {
      out = out.replace(new RegExp(EMAIL_PATTERN.source, 'g'), (match) =>
        placeholderFor('email', match),
      );
    }

    if (scrubIps) {
      out = out.replace(new RegExp(IPV4_PATTERN.source, 'g'), (match) =>
        match === '0.0.0.0' ? match : placeholderFor('ip', match),
      );
      out = out.replace(new RegExp(IPV6_PATTERN.source, 'g'), (match) =>
        placeholderFor('ip', match),
      );
    }

    if (scrubUuids) {
      out = out.replace(new RegExp(UUID_GLOBAL_PATTERN.source, 'gi'), (match) =>
        placeholderFor('uuid', match),
      );
    }

    for (const rule of customRules) {
      out = applyCustomRule(out, rule);
    }

    return out;
  };

  const scrubParamEntries = (
    params: URLSearchParams,
    context: ScrubContext,
    sortKeys: boolean,
  ): string => {
    const entries: Array<[string, string]> = [];
    params.forEach((value, key) => {
      entries.push([key, value]);
    });
    if (sortKeys) entries.sort(([a], [b]) => a.localeCompare(b));
    return entries
      .map(([key, value]) => {
        const encodedKey = encodeURIComponent(key);
        if (secretQueryParams.has(key.toLowerCase())) {
          return `${encodedKey}=${placeholderFor('query_secret', value)}`;
        }
        const scrubbedVal = scrubText(value, context);
        if (isSafePlaceholder(scrubbedVal, safePlaceholderValues, safePlaceholderLower)) {
          return `${encodedKey}=${scrubbedVal}`;
        }
        return `${encodedKey}=${encodeURIComponent(scrubbedVal)}`;
      })
      .join('&');
  };

  const scrubUrl = (rawUrl: string, overrideContext?: ScrubContext): string => {
    const context = mergeContexts(options.context, overrideContext);
    const isProtocolRelative = rawUrl.startsWith('//');
    const isAbsolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl);

    let parsed: URL;
    try {
      parsed = isProtocolRelative
        ? new URL(`http:${rawUrl}`)
        : isAbsolute
          ? new URL(rawUrl)
          : new URL(rawUrl, 'http://vcr.invalid');
    } catch {
      return scrubText(rawUrl, context);
    }

    const scrubbedPath = scrubText(parsed.pathname, context);
    const queryStr = scrubParamEntries(parsed.searchParams, context, true);
    const queryString = queryStr ? `?${queryStr}` : '';

    let hash = '';
    if (parsed.hash) {
      const rawFragment = parsed.hash.slice(1);
      if (rawFragment.includes('=')) {
        const fragmentParams = new URLSearchParams(rawFragment);
        hash = `#${scrubParamEntries(fragmentParams, context, false)}`;
      } else {
        hash = `#${scrubText(rawFragment, context)}`;
      }
    }

    if (!isAbsolute && !isProtocolRelative) {
      return `${scrubbedPath}${queryString}${hash}`;
    }

    let authority = parsed.host;
    if (parsed.username || parsed.password) {
      const decodedUser = parsed.username ? safeDecodeURIComponent(parsed.username) : '';
      if (parsed.password) {
        const userPart = decodedUser ? scrubText(decodedUser, context) : '';
        const passPart = `:${placeholderFor('url_credential', parsed.password)}`;
        authority = `${userPart}${passPart}@${parsed.host}`;
      } else {
        // Username-only credentials (e.g. https://<token>@github.com) are scrubbed whole.
        authority = `${placeholderFor('url_credential', decodedUser)}@${parsed.host}`;
      }
    }

    const schemePrefix = isProtocolRelative ? '//' : `${parsed.protocol}//`;
    return `${schemePrefix}${authority}${scrubbedPath}${queryString}${hash}`;
  };

  const scrubHeaders = (
    headers: HeaderInput,
    overrideContext?: ScrubContext,
  ): Record<string, string> => {
    const context = mergeContexts(options.context, overrideContext);
    const entries = toHeaderEntries(headers).sort(([a], [b]) =>
      a.toLowerCase().localeCompare(b.toLowerCase()),
    );
    const out: Record<string, string> = {};
    for (const [rawKey, value] of entries) {
      const key = rawKey.toLowerCase();
      if (key === 'authorization' || key === 'proxy-authorization') {
        out[key] = scrubAuthorizationHeaderValue(value, placeholderFor);
      } else if (secretHeaders.has(key)) {
        out[key] = placeholderFor('header_secret', value);
      } else {
        const scrubbedVal = scrubText(value, context);
        const existing = out[key];
        out[key] = existing !== undefined ? `${existing}, ${scrubbedVal}` : scrubbedVal;
      }
    }
    return out;
  };

  const scrubIdentityLeaf = (value: string): string => {
    if (value === '') return value;
    if (UUID_EXACT_PATTERN.test(value)) return placeholderFor('uuid', value);
    if (value.includes('@')) return placeholderFor('email', value);
    return placeholderFor('key_secret', value);
  };

  const scrubValue = <T>(value: T, overrideContext?: ScrubContext): T => {
    const context = mergeContexts(options.context, overrideContext);
    const ancestors = new WeakSet<object>();

    const walk = (
      node: unknown,
      key: string | undefined,
      inSecret: boolean,
      inIdentity: boolean,
    ): unknown => {
      const keyIsSecret = key !== undefined && isSecretKey(key);
      const keyIsIdentity = key !== undefined && isIdentityKey(key);
      const secretBranch = inSecret || keyIsSecret;
      const identityBranch = inIdentity || keyIsIdentity;

      if (typeof node === 'string') {
        if (options.allowValue?.(key, node)) return node;
        if (isSafePlaceholder(node, safePlaceholderValues, safePlaceholderLower)) return node;
        if (secretBranch) {
          if (
            key !== undefined &&
            (key.toLowerCase() === 'authorization' || key.toLowerCase() === 'proxy-authorization')
          ) {
            return scrubAuthorizationHeaderValue(node, placeholderFor);
          }
          if (key !== undefined && secretHeaders.has(key.toLowerCase())) {
            return placeholderFor('header_secret', node);
          }
          return placeholderFor('key_secret', node);
        }
        if (identityBranch) return scrubIdentityLeaf(node);
        return scrubText(node, context);
      }

      if (node === null || typeof node !== 'object') return node;
      if (node instanceof Uint8Array) return node;
      if (node instanceof Date) return new Date(node.getTime());
      if (node instanceof URL) return scrubUrl(node.toString(), context);
      if (node instanceof Headers) return scrubHeaders(node, context);

      if (ancestors.has(node)) return '<CIRCULAR>';
      ancestors.add(node);
      try {
        if (node instanceof Error) {
          const out: Record<string, unknown> = {
            name: scrubText(node.name, context),
            message: scrubText(node.message, context),
          };
          if (node.stack) out.stack = scrubText(node.stack, context);
          if ('cause' in node && node.cause !== undefined) {
            out.cause = walk(node.cause, 'cause', secretBranch, identityBranch);
          }
          for (const [extraKey, extraVal] of Object.entries(node)) {
            out[scrubText(extraKey, context)] = walk(
              extraVal,
              extraKey,
              secretBranch,
              identityBranch,
            );
          }
          return out;
        }
        if (node instanceof Map) {
          const out = new Map<unknown, unknown>();
          for (const [k, v] of node.entries()) {
            const scrubbedKey = walk(k, undefined, secretBranch, identityBranch);
            const keyName = typeof k === 'string' ? k : undefined;
            out.set(scrubbedKey, walk(v, keyName, secretBranch, identityBranch));
          }
          return out;
        }
        if (node instanceof Set) {
          const out = new Set<unknown>();
          for (const item of node.values()) {
            out.add(walk(item, undefined, secretBranch, identityBranch));
          }
          return out;
        }
        if (Array.isArray(node)) {
          const filtered = options.filterArrayItem
            ? node.filter((item) => options.filterArrayItem?.(key, item) !== false)
            : node;
          return filtered.map((item) => walk(item, undefined, secretBranch, identityBranch));
        }

        const out: Record<string, unknown> = {};
        for (const [childKey, childValue] of Object.entries(node)) {
          out[scrubText(childKey, context)] = walk(
            childValue,
            childKey,
            secretBranch,
            identityBranch,
          );
        }
        return out;
      } finally {
        ancestors.delete(node);
      }
    };

    return walk(value, undefined, false, false) as T;
  };

  const scrubLine = (line: string, overrideContext?: ScrubContext): string => {
    const trimmed = line.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        return JSON.stringify(scrubValue(JSON.parse(trimmed), overrideContext));
      } catch {
        /* Not JSON; fall through to text scrubbing. */
      }
    }
    return scrubText(line, overrideContext);
  };

  const rehydratePlaceholders = (text: string, overrideContext?: ScrubContext): string => {
    const context = mergeContexts(options.context, overrideContext);
    const tmpVal = tmpdir().replace(/\/+$/, '');
    let out = text.replaceAll('{{tmp}}', () => tmpVal);
    if (context.cwd) {
      const cwdVal = context.cwd;
      out = out.replaceAll('{{cwd}}', () => cwdVal);
    }
    if (context.pathPlaceholders) {
      for (const [placeholder, rawPath] of Object.entries(context.pathPlaceholders)) {
        const targetVal = rawPath;
        out = out.replaceAll(placeholder, () => targetVal);
      }
    }
    return out;
  };

  const scanStringForLeaks = (
    text: string,
    path: string | undefined,
    findings: LeakFinding[],
  ): void => {
    if (!text) return;

    if (knownSecretsPattern) {
      const safeSpans = collectSafeSpans(text, safePlaceholderValues);
      for (const match of text.matchAll(new RegExp(knownSecretsPattern.source, 'g'))) {
        const start = match.index ?? 0;
        const end = start + match[0].length;
        if (isInsideSpans(start, end, safeSpans)) continue;
        findings.push({
          kind: 'known_secret',
          message: 'contains a known secret literal',
          ...(path ? { path } : {}),
        });
        break;
      }
    }

    if (scrubPaths && HOME_PATH_LEAK_PATTERN.test(text)) {
      findings.push({
        kind: 'home_path',
        message: 'contains a user home directory path',
        ...(path ? { path } : {}),
      });
    }

    if (scrubEmails && new RegExp(EMAIL_PATTERN.source).test(text)) {
      findings.push({
        kind: 'email',
        message: 'contains an unredacted email address',
        ...(path ? { path } : {}),
      });
    }

    for (const detector of BUILT_IN_SECRET_DETECTORS) {
      const regex = new RegExp(detector.pattern.source, ensureGlobalFlags(detector.pattern.flags));
      for (const match of text.matchAll(regex)) {
        const matchedText = match[0];
        if (isSafePlaceholder(matchedText, safePlaceholderValues, safePlaceholderLower)) continue;
        if (
          detector.preserveGroup !== undefined &&
          typeof match[detector.preserveGroup] === 'string'
        ) {
          const suffixLen = detector.suffix?.length ?? 0;
          const secretPart = matchedText.slice(
            match[detector.preserveGroup].length,
            suffixLen > 0 ? -suffixLen : undefined,
          );
          if (isSafePlaceholder(secretPart, safePlaceholderValues, safePlaceholderLower)) continue;
        }
        findings.push({
          kind: detector.id,
          message: `contains an unredacted ${detector.id.replace(/_/g, ' ')}`,
          ...(path ? { path } : {}),
        });
        break;
      }
    }

    for (const match of text.matchAll(
      new RegExp(queryParamPattern.source, ensureGlobalFlags(queryParamPattern.flags)),
    )) {
      const valuePart = match[2] ?? '';
      if (isSafePlaceholder(valuePart, safePlaceholderValues, safePlaceholderLower)) continue;
      findings.push({
        kind: 'query_secret',
        message: 'contains an unredacted secret query parameter',
        ...(path ? { path } : {}),
      });
      break;
    }

    for (const match of text.matchAll(
      new RegExp(
        INLINE_ENV_SECRET_PATTERN.source,
        ensureGlobalFlags(INLINE_ENV_SECRET_PATTERN.flags),
      ),
    )) {
      const valuePart = match[3] ?? '';
      if (isSafePlaceholder(valuePart, safePlaceholderValues, safePlaceholderLower)) continue;
      findings.push({
        kind: 'inline_secret',
        message: 'contains an unredacted inline secret assignment',
        ...(path ? { path } : {}),
      });
      break;
    }

    for (const rule of customRules) {
      if (rule.checkLeak === false) continue;
      const regex = new RegExp(rule.pattern.source, ensureGlobalFlags(rule.pattern.flags));
      for (const match of text.matchAll(regex)) {
        if (isSafePlaceholder(match[0], safePlaceholderValues, safePlaceholderLower)) continue;
        findings.push({
          kind: rule.id,
          message: `matched custom secret rule "${rule.id}"`,
          ...(path ? { path } : {}),
        });
        break;
      }
    }

    for (const [key, val] of extractJsonStringPairs(text)) {
      if (
        (isSecretKey(key) || isIdentityKey(key)) &&
        !isSafePlaceholder(val, safePlaceholderValues, safePlaceholderLower) &&
        !options.allowValue?.(key, val)
      ) {
        findings.push({
          kind: `unredacted_${key}`,
          message: `contains unredacted "${key}" field`,
          ...(path ? { path } : {}),
        });
      }
    }
  };

  const inspectKeyForLeaks = (
    rawKey: string,
    parentPath: string | undefined,
    findings: LeakFinding[],
  ): string => {
    const keyFindings: LeakFinding[] = [];
    scanStringForLeaks(rawKey, undefined, keyFindings);
    if (keyFindings.length === 0) {
      return parentPath ? `${parentPath}.${rawKey}` : rawKey;
    }
    const safePath = parentPath
      ? `${parentPath}.${SECRET_KEY_REDACTED_SEGMENT}`
      : SECRET_KEY_REDACTED_SEGMENT;
    for (const finding of keyFindings) {
      findings.push({
        kind: finding.kind,
        message: `${finding.message} in object/map key`,
        path: safePath,
      });
    }
    return safePath;
  };

  const findUnscrubbedSecrets = (input: unknown): LeakFinding[] => {
    const findings: LeakFinding[] = [];
    const ancestors = new WeakSet<object>();

    const walk = (
      node: unknown,
      key: string | undefined,
      path: string | undefined,
      inSecret: boolean,
      inIdentity: boolean,
    ): void => {
      const keyIsSecret = key !== undefined && isSecretKey(key);
      const keyIsIdentity = key !== undefined && isIdentityKey(key);
      const secretBranch = inSecret || keyIsSecret;
      const identityBranch = inIdentity || keyIsIdentity;

      if (typeof node === 'string') {
        if (
          (secretBranch || identityBranch) &&
          !isSafePlaceholder(node, safePlaceholderValues, safePlaceholderLower) &&
          !options.allowValue?.(key, node)
        ) {
          findings.push({
            kind: `unredacted_${key ?? (secretBranch ? 'secret' : 'identity')}`,
            message: `unredacted sensitive value at "${path ?? key ?? '<root>'}"`,
            ...(path ? { path } : {}),
          });
        }
        scanStringForLeaks(node, path, findings);

        // Bounded scan for embedded JSON objects or arrays inside string fields.
        let attempts = 0;
        for (let idx = 0; idx < node.length && attempts < MAX_EMBEDDED_JSON_ATTEMPTS; idx++) {
          const ch = node[idx];
          if (ch !== '{' && ch !== '[') continue;
          const remaining = node.length - idx;
          if (remaining > MAX_EMBEDDED_JSON_SLICE_BYTES) continue;
          attempts++;
          try {
            const parsed = JSON.parse(node.slice(idx)) as unknown;
            if (parsed && typeof parsed === 'object') {
              walk(parsed, undefined, path, false, false);
              break;
            }
          } catch {
            /* Not valid JSON starting at this offset. */
          }
        }
        return;
      }

      if (node === null || typeof node !== 'object') return;

      if (node instanceof Uint8Array) {
        const decoded = new TextDecoder('utf-8', { fatal: false }).decode(node);
        scanStringForLeaks(decoded, path, findings);
        return;
      }

      if (node instanceof URL) {
        scanStringForLeaks(node.toString(), path, findings);
        return;
      }

      if (node instanceof Headers) {
        for (const [hKey, hVal] of toHeaderEntries(node)) {
          const childPath = inspectKeyForLeaks(hKey, path, findings);
          walk(hVal, hKey, childPath, secretBranch, identityBranch);
        }
        return;
      }

      if (ancestors.has(node)) return;
      ancestors.add(node);
      try {
        if (node instanceof Error) {
          walk(node.name, 'name', path ? `${path}.name` : 'name', secretBranch, identityBranch);
          walk(
            node.message,
            'message',
            path ? `${path}.message` : 'message',
            secretBranch,
            identityBranch,
          );
          if (node.stack) {
            walk(
              node.stack,
              'stack',
              path ? `${path}.stack` : 'stack',
              secretBranch,
              identityBranch,
            );
          }
          if ('cause' in node && node.cause !== undefined) {
            walk(
              node.cause,
              'cause',
              path ? `${path}.cause` : 'cause',
              secretBranch,
              identityBranch,
            );
          }
          for (const [extraKey, extraVal] of Object.entries(node)) {
            const childPath = inspectKeyForLeaks(extraKey, path, findings);
            walk(extraVal, extraKey, childPath, secretBranch, identityBranch);
          }
          return;
        }
        if (Array.isArray(node)) {
          for (let index = 0; index < node.length; index++) {
            const childPath = path ? `${path}[${index}]` : `[${index}]`;
            walk(node[index], undefined, childPath, secretBranch, identityBranch);
          }
          return;
        }
        if (node instanceof Map) {
          for (const [k, v] of node.entries()) {
            const keyStr = typeof k === 'string' ? k : String(k);
            const childPath = inspectKeyForLeaks(keyStr, path, findings);
            if (k && typeof k === 'object') {
              walk(k, undefined, childPath, secretBranch, identityBranch);
            }
            walk(v, typeof k === 'string' ? k : undefined, childPath, secretBranch, identityBranch);
          }
          return;
        }
        if (node instanceof Set) {
          let index = 0;
          for (const item of node.values()) {
            const childPath = path ? `${path}[${index++}]` : `[${index++}]`;
            walk(item, undefined, childPath, secretBranch, identityBranch);
          }
          return;
        }
        for (const [childKey, childValue] of Object.entries(node)) {
          const childPath = inspectKeyForLeaks(childKey, path, findings);
          walk(childValue, childKey, childPath, secretBranch, identityBranch);
        }
      } finally {
        ancestors.delete(node);
      }
    };

    walk(input, undefined, undefined, false, false);

    const seen = new Set<string>();
    return findings.filter((finding) => {
      const dedupeKey = `${finding.kind}::${finding.path ?? ''}`;
      if (seen.has(dedupeKey)) return false;
      seen.add(dedupeKey);
      return true;
    });
  };

  const assertScrubbed = (input: unknown, label?: string): void => {
    const findings = findUnscrubbedSecrets(input);
    if (findings.length === 0) return;
    const summary = findings
      .map((finding) => (finding.path ? `${finding.path}: ${finding.message}` : finding.message))
      .join('; ');
    const target = label ? ` in "${label}"` : '';
    throw new VcrError(
      'unscrubbed_secret',
      `VCR: unscrubbed secret detected${target}: ${summary}`,
      {
        cassette: label,
        details: { findings },
      },
    );
  };

  return {
    scrubText,
    scrubValue,
    scrubLine,
    scrubUrl,
    scrubHeaders,
    rehydratePlaceholders,
    findUnscrubbedSecrets,
    assertScrubbed,
  };
};

const defaultScrubber = createScrubber();

/** Internal shared helper resolving either a `Scrubber` handle or `ScrubOptions` into a `Scrubber`. */
export const resolveScrubber = (input?: Scrubber | ScrubOptions): Scrubber => {
  if (!input) return defaultScrubber;
  if ('scrubText' in input && 'assertScrubbed' in input) return input;
  return createScrubber(input);
};

export const scrubText = (text: string, options?: ScrubOptions): string =>
  options ? createScrubber(options).scrubText(text) : defaultScrubber.scrubText(text);

export const scrubValue = <T>(value: T, options?: ScrubOptions): T =>
  options ? createScrubber(options).scrubValue(value) : defaultScrubber.scrubValue(value);

export const scrubLine = (line: string, options?: ScrubOptions): string =>
  options ? createScrubber(options).scrubLine(line) : defaultScrubber.scrubLine(line);

export const scrubUrl = (url: string, options?: ScrubOptions): string =>
  options ? createScrubber(options).scrubUrl(url) : defaultScrubber.scrubUrl(url);

export const scrubHeaders = (
  headers: HeaderInput,
  options?: ScrubOptions,
): Record<string, string> =>
  options ? createScrubber(options).scrubHeaders(headers) : defaultScrubber.scrubHeaders(headers);

export const rehydratePlaceholders = (text: string, context?: ScrubContext): string =>
  defaultScrubber.rehydratePlaceholders(text, context);

export const findUnscrubbedSecrets = (input: unknown, options?: ScrubOptions): LeakFinding[] =>
  options
    ? createScrubber(options).findUnscrubbedSecrets(input)
    : defaultScrubber.findUnscrubbedSecrets(input);

export const assertScrubbed = (
  input: unknown,
  options?: ScrubOptions & { label?: string },
): void =>
  options
    ? createScrubber(options).assertScrubbed(input, options.label)
    : defaultScrubber.assertScrubbed(input);
