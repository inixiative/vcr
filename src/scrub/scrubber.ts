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

const escapeRegExp = (value: string): string => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const ensureGlobalFlags = (flags: string): string => (flags.includes('g') ? flags : `${flags}g`);

const stripGlobalFlag = (flags: string): string => flags.replace(/g/g, '');

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

const normalizeKnownSecrets = (secrets: readonly string[] | undefined): string[] => {
  if (!secrets?.length) return [];
  const expanded = new Set<string>();
  for (const raw of secrets) {
    const trimmed = raw.trim();
    if (!trimmed) continue;
    expanded.add(raw);
    const encoded = encodeURIComponent(raw);
    if (encoded !== raw) expanded.add(encoded);
  }
  return [...expanded].sort((a, b) => b.length - a.length);
};

const buildQueryParamPattern = (paramNames: ReadonlySet<string>): RegExp => {
  const escaped = [...paramNames].map(escapeRegExp).sort((a, b) => b.length - a.length);
  return new RegExp(`([?&](?:${escaped.join('|')})=)(?!<REDACTED:|REDACTED\\b)[^&#\\s"']+`, 'gi');
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
  return text.replace(regex, rule.placeholder);
};

const isSafePlaceholder = (
  value: string,
  placeholderFor: ScrubPlaceholderResolver,
  extraSafeValues: ReadonlySet<string>,
): boolean => {
  if (value === '') return true;
  if (SAFE_PLACEHOLDER_PATTERN.test(value)) return true;
  if (extraSafeValues.has(value)) return true;
  const customKinds: ScrubPlaceholderKind[] = [
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
  for (const kind of customKinds) {
    const sample = placeholderFor(kind, '');
    if (value === sample) return true;
    if (
      (kind === 'bearer' && value.toLowerCase() === `bearer ${sample.toLowerCase()}`) ||
      (kind === 'basic' && value.toLowerCase() === `basic ${sample.toLowerCase()}`) ||
      (kind === 'dpop' && value.toLowerCase() === `dpop ${sample.toLowerCase()}`) ||
      (kind === 'fly_token' && value.toLowerCase() === `flyv1 ${sample.toLowerCase()}`)
    ) {
      return true;
    }
  }
  return false;
};

const formatPlaceholder = (
  placeholderFor: ScrubPlaceholderResolver,
  kind: ScrubPlaceholderKind,
  match: string,
): string => placeholderFor(kind, match);

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
  const knownSecrets = normalizeKnownSecrets(options.knownSecrets);
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

  const extraSecretKeys = options.extraSecretKeyPatterns ?? [];
  const extraIdentityKeys = options.extraIdentityKeyPatterns ?? [];

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

  const scrubText = (text: string, overrideContext?: ScrubContext): string => {
    if (!text) return text;
    const context = mergeContexts(options.context, overrideContext);
    let out = text;

    // Explicit known secrets run FIRST so malformed or short literals never slip past regexes.
    for (const secret of knownSecrets) {
      if (out.includes(secret)) {
        out = out.replaceAll(secret, formatPlaceholder(placeholderFor, 'secret', secret));
      }
    }

    for (const [pattern, replacement] of resolvePathRules(context)) {
      out = out.replace(pattern, replacement);
    }

    for (const detector of BUILT_IN_SECRET_DETECTORS) {
      const regex = new RegExp(detector.pattern.source, ensureGlobalFlags(detector.pattern.flags));
      out = out.replace(regex, (match, ...args: unknown[]) => {
        const placeholder = formatPlaceholder(placeholderFor, detector.kind, match);
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
      (match, prefix: string) =>
        `${prefix}${formatPlaceholder(placeholderFor, 'query_secret', match)}`,
    );

    out = out.replace(
      new RegExp(
        INLINE_ENV_SECRET_PATTERN.source,
        ensureGlobalFlags(INLINE_ENV_SECRET_PATTERN.flags),
      ),
      (match, prefix: string) => `${prefix}${formatPlaceholder(placeholderFor, 'secret', match)}`,
    );

    if (scrubEmails) {
      out = out.replace(new RegExp(EMAIL_PATTERN.source, 'g'), (match) =>
        formatPlaceholder(placeholderFor, 'email', match),
      );
    }

    if (scrubIps) {
      out = out.replace(new RegExp(IPV4_PATTERN.source, 'g'), (match) =>
        match === '0.0.0.0' ? match : formatPlaceholder(placeholderFor, 'ip', match),
      );
      out = out.replace(new RegExp(IPV6_PATTERN.source, 'g'), (match) =>
        formatPlaceholder(placeholderFor, 'ip', match),
      );
    }

    if (scrubUuids) {
      out = out.replace(new RegExp(UUID_GLOBAL_PATTERN.source, 'gi'), (match) =>
        match === formatPlaceholder(placeholderFor, 'uuid', match)
          ? match
          : formatPlaceholder(placeholderFor, 'uuid', match),
      );
    }

    for (const rule of customRules) {
      out = applyCustomRule(out, rule);
    }

    return out;
  };

  const scrubUrl = (rawUrl: string, overrideContext?: ScrubContext): string => {
    const context = mergeContexts(options.context, overrideContext);
    // Apply knownSecrets first so secrets embedded anywhere in the URL are caught even if malformed.
    let pre = rawUrl;
    for (const secret of knownSecrets) {
      if (pre.includes(secret)) {
        pre = pre.replaceAll(secret, formatPlaceholder(placeholderFor, 'secret', secret));
      }
    }

    const isAbsolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(pre);
    let parsed: URL;
    try {
      parsed = isAbsolute ? new URL(pre) : new URL(pre, 'http://vcr.invalid');
    } catch {
      return scrubText(pre, context);
    }

    const scrubbedPath = scrubText(parsed.pathname, context);
    const paramEntries: Array<[string, string]> = [];
    parsed.searchParams.forEach((value, key) => {
      paramEntries.push([key, value]);
    });
    paramEntries.sort(([a], [b]) => a.localeCompare(b));

    const queryParts = paramEntries.map(([key, value]) => {
      const encodedKey = encodeURIComponent(key);
      if (secretQueryParams.has(key.toLowerCase())) {
        return `${encodedKey}=${formatPlaceholder(placeholderFor, 'query_secret', value)}`;
      }
      const scrubbedVal = scrubText(value, context);
      if (SAFE_PLACEHOLDER_PATTERN.test(scrubbedVal)) {
        return `${encodedKey}=${scrubbedVal}`;
      }
      return `${encodedKey}=${encodeURIComponent(scrubbedVal)}`;
    });

    const queryString = queryParts.length ? `?${queryParts.join('&')}` : '';
    const hash = parsed.hash ? scrubText(parsed.hash, context) : '';

    if (!isAbsolute) {
      return `${scrubbedPath}${queryString}${hash}`;
    }

    let authority = parsed.host;
    if (parsed.username || parsed.password) {
      const userPart = parsed.username
        ? scrubText(decodeURIComponent(parsed.username), context)
        : '';
      const passPart = parsed.password
        ? `:${formatPlaceholder(placeholderFor, 'url_credential', parsed.password)}`
        : '';
      authority = `${userPart}${passPart}@${parsed.host}`;
    }

    return `${parsed.protocol}//${authority}${scrubbedPath}${queryString}${hash}`;
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
        out[key] = formatPlaceholder(placeholderFor, 'header_secret', value);
      } else {
        out[key] = scrubText(value, context);
      }
    }
    return out;
  };

  const scrubIdentityLeaf = (value: string): string => {
    if (value === '') return value;
    if (UUID_EXACT_PATTERN.test(value)) return formatPlaceholder(placeholderFor, 'uuid', value);
    if (value.includes('@')) return formatPlaceholder(placeholderFor, 'email', value);
    return formatPlaceholder(placeholderFor, 'key_secret', value);
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
        if (isSafePlaceholder(node, placeholderFor, customPlaceholderValues)) return node;
        if (secretBranch) {
          if (
            key !== undefined &&
            (key.toLowerCase() === 'authorization' || key.toLowerCase() === 'proxy-authorization')
          ) {
            return scrubAuthorizationHeaderValue(node, placeholderFor);
          }
          if (key !== undefined && secretHeaders.has(key.toLowerCase())) {
            return formatPlaceholder(placeholderFor, 'header_secret', node);
          }
          return formatPlaceholder(placeholderFor, 'key_secret', node);
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
          return {
            name: node.name,
            message: scrubText(node.message, context),
            ...(node.stack ? { stack: scrubText(node.stack, context) } : {}),
          };
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
    let out = text.replaceAll('{{tmp}}', tmpdir().replace(/\/+$/, ''));
    if (context.cwd) out = out.replaceAll('{{cwd}}', context.cwd);
    if (context.pathPlaceholders) {
      for (const [placeholder, rawPath] of Object.entries(context.pathPlaceholders)) {
        out = out.replaceAll(placeholder, rawPath);
      }
    }
    return out;
  };

  const scanStringForLeaks = (
    text: string,
    path: string | undefined,
    findings: LeakFinding[],
  ): void => {
    for (const secret of knownSecrets) {
      if (text.includes(secret)) {
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
        if (isSafePlaceholder(matchedText, placeholderFor, customPlaceholderValues)) continue;
        if (
          detector.preserveGroup !== undefined &&
          typeof match[detector.preserveGroup] === 'string'
        ) {
          const suffixLen = detector.suffix?.length ?? 0;
          const secretPart = matchedText.slice(
            match[detector.preserveGroup].length,
            suffixLen > 0 ? -suffixLen : undefined,
          );
          if (isSafePlaceholder(secretPart, placeholderFor, customPlaceholderValues)) continue;
        }
        findings.push({
          kind: detector.id,
          message: `contains an unredacted ${detector.id.replace(/_/g, ' ')}`,
          ...(path ? { path } : {}),
        });
        break;
      }
    }

    if (new RegExp(queryParamPattern.source, stripGlobalFlag(queryParamPattern.flags)).test(text)) {
      findings.push({
        kind: 'query_secret',
        message: 'contains an unredacted secret query parameter',
        ...(path ? { path } : {}),
      });
    }

    if (
      new RegExp(
        INLINE_ENV_SECRET_PATTERN.source,
        stripGlobalFlag(INLINE_ENV_SECRET_PATTERN.flags),
      ).test(text)
    ) {
      findings.push({
        kind: 'inline_secret',
        message: 'contains an unredacted inline secret assignment',
        ...(path ? { path } : {}),
      });
    }

    for (const rule of customRules) {
      if (rule.checkLeak === false) continue;
      const regex = new RegExp(rule.pattern.source, stripGlobalFlag(rule.pattern.flags));
      if (regex.test(text)) {
        findings.push({
          kind: rule.id,
          message: `matched custom secret rule "${rule.id}"`,
          ...(path ? { path } : {}),
        });
      }
    }

    // Check escaped or raw `"key": "value"` pairs embedded inside text streams.
    for (const match of text.matchAll(
      /(\\*)"([A-Za-z0-9_-]+)\1"\s*:\s*\1"((?:[^"\\]|\\(?!\1"))*)\1"/g,
    )) {
      const key = match[2];
      const val = match[3];
      if (
        key !== undefined &&
        val !== undefined &&
        (isSecretKey(key) || isIdentityKey(key)) &&
        !isSafePlaceholder(val, placeholderFor, customPlaceholderValues) &&
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
          !isSafePlaceholder(node, placeholderFor, customPlaceholderValues) &&
          !options.allowValue?.(key, node)
        ) {
          findings.push({
            kind: `unredacted_${key ?? (secretBranch ? 'secret' : 'identity')}`,
            message: `unredacted sensitive value at "${path ?? key ?? '<root>'}"`,
            ...(path ? { path } : {}),
          });
        }
        scanStringForLeaks(node, path, findings);

        // Inspect embedded JSON objects inside string fields (e.g. protocol frames or raw HTTP bodies).
        for (let start = node.indexOf('{'); start !== -1; start = node.indexOf('{', start + 1)) {
          try {
            const parsed = JSON.parse(node.slice(start)) as unknown;
            if (parsed && typeof parsed === 'object') {
              walk(parsed, undefined, path, false, false);
              break;
            }
          } catch {
            /* Not JSON starting at this offset. */
          }
        }
        return;
      }

      if (node === null || typeof node !== 'object' || node instanceof Uint8Array) return;
      if (node instanceof Headers) {
        for (const [hKey, hVal] of toHeaderEntries(node)) {
          const childPath = path ? `${path}.${hKey}` : hKey;
          walk(hVal, hKey, childPath, secretBranch, identityBranch);
        }
        return;
      }
      if (ancestors.has(node)) return;
      ancestors.add(node);
      try {
        if (Array.isArray(node)) {
          for (let index = 0; index < node.length; index++) {
            const childPath = path ? `${path}[${index}]` : `[${index}]`;
            walk(node[index], undefined, childPath, secretBranch, identityBranch);
          }
          return;
        }
        if (node instanceof Map) {
          for (const [k, v] of node.entries()) {
            const keyStr = String(k);
            const childPath = path ? `${path}.${keyStr}` : keyStr;
            walk(v, keyStr, childPath, secretBranch, identityBranch);
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
          const childPath = path ? `${path}.${childKey}` : childKey;
          walk(childValue, childKey, childPath, secretBranch, identityBranch);
        }
      } finally {
        ancestors.delete(node);
      }
    };

    walk(input, undefined, undefined, false, false);

    // Deduplicate findings by (kind, path) while preserving order.
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
