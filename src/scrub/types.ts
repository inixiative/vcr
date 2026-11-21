export type ScrubPlaceholderKind =
  | 'secret'
  | 'bearer'
  | 'basic'
  | 'dpop'
  | 'jwt'
  | 'private_key'
  | 'anthropic_key'
  | 'openai_key'
  | 'github_token'
  | 'google_key'
  | 'slack_token'
  | 'slack_webhook'
  | 'render_token'
  | 'fly_token'
  | 'kingdom_token'
  | 'aws_key'
  | 'provider_token'
  | 'api_token'
  | 'url_credential'
  | 'query_secret'
  | 'header_secret'
  | 'key_secret'
  | 'email'
  | 'ip'
  | 'uuid';

export type ScrubPlaceholderResolver = (kind: ScrubPlaceholderKind, match: string) => string;

export interface ScrubRule {
  readonly id: string;
  readonly pattern: RegExp;
  readonly placeholder: string | ((match: string, ...groups: string[]) => string);
  /** Whether matches of this rule should also fail leak detection. Defaults to true. */
  readonly checkLeak?: boolean;
}

export interface ScrubContext {
  /** Working directory normalized to `{{cwd}}` when path scrubbing is enabled. */
  readonly cwd?: string;
  /** Additional placeholder -> absolute path pairs normalized during scrubbing and restored on rehydration. */
  readonly pathPlaceholders?: Readonly<Record<string, string>>;
}

export interface ScrubOptions {
  readonly context?: ScrubContext;
  /** Exact literal secrets scrubbed BEFORE regex rules so malformed or non-standard secrets never leak. */
  readonly knownSecrets?: readonly string[];
  /** Custom domain-specific scrub rules applied after knownSecrets and built-in detectors. */
  readonly rules?: readonly ScrubRule[];
  /** Custom deterministic placeholder resolver. */
  readonly placeholderFor?: ScrubPlaceholderResolver;
  /** Additional header names (case-insensitive) treated as secret headers. */
  readonly extraSecretHeaders?: readonly string[];
  /** Additional URL query parameter names (case-insensitive) treated as secret query params. */
  readonly extraSecretQueryParams?: readonly string[];
  /** Additional object key patterns treated as secret keys. */
  readonly extraSecretKeyPatterns?: readonly RegExp[];
  /** Additional object key patterns treated as identity keys (all string descendants scrubbed). */
  readonly extraIdentityKeyPatterns?: readonly RegExp[];
  /** Normalize cwd, tmpdir, account home, username, and hostname. Defaults to true. */
  readonly scrubPaths?: boolean;
  /** Normalize email addresses to a deterministic placeholder. Defaults to true. */
  readonly scrubEmails?: boolean;
  /** Normalize IPv4 and IPv6 addresses to a deterministic placeholder. Defaults to false. */
  readonly scrubIps?: boolean;
  /** Normalize UUIDs anywhere in text to a deterministic placeholder. Defaults to false. */
  readonly scrubUuids?: boolean;
  /** Allowlist predicate for keeping non-sensitive enum values under identity keys. */
  readonly allowValue?: (key: string | undefined, value: string) => boolean;
  /** Predicate to drop array elements before scrubbing (returns false to omit). */
  readonly filterArrayItem?: (key: string | undefined, item: unknown) => boolean;
}

export interface LeakFinding {
  readonly kind: string;
  readonly message: string;
  readonly path?: string;
}

export type HeaderInput =
  | Headers
  | Readonly<Record<string, string>>
  | readonly (readonly [string, string])[];

export interface Scrubber {
  scrubText(text: string, context?: ScrubContext): string;
  scrubValue<T>(value: T, context?: ScrubContext): T;
  scrubLine(line: string, context?: ScrubContext): string;
  scrubUrl(url: string, context?: ScrubContext): string;
  scrubHeaders(headers: HeaderInput, context?: ScrubContext): Record<string, string>;
  rehydratePlaceholders(text: string, context?: ScrubContext): string;
  findUnscrubbedSecrets(input: unknown): LeakFinding[];
  assertScrubbed(input: unknown, label?: string): void;
}
