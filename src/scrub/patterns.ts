import type { ScrubPlaceholderKind, ScrubPlaceholderResolver } from './types';

export const REDACTED_UUID = '00000000-0000-4000-8000-000000000000';
export const REDACTED_EMAIL = 'redacted@example.invalid';
export const REDACTED_IP = '<REDACTED:IP>';

export const DEFAULT_PLACEHOLDERS: Readonly<Record<ScrubPlaceholderKind, string>> = {
  secret: '<REDACTED:SECRET>',
  bearer: '<REDACTED:BEARER>',
  basic: '<REDACTED:BASIC>',
  dpop: '<REDACTED:DPOP>',
  jwt: '<REDACTED:JWT>',
  private_key: '<REDACTED:PRIVATE_KEY>',
  anthropic_key: '<REDACTED:ANTHROPIC_KEY>',
  openai_key: '<REDACTED:OPENAI_KEY>',
  github_token: '<REDACTED:GITHUB_TOKEN>',
  google_key: '<REDACTED:GOOGLE_KEY>',
  slack_token: '<REDACTED:SLACK_TOKEN>',
  slack_webhook: '<REDACTED:SLACK_WEBHOOK>',
  render_token: '<REDACTED:RENDER_TOKEN>',
  fly_token: '<REDACTED:FLY_TOKEN>',
  kingdom_token: '<REDACTED:KINGDOM_TOKEN>',
  aws_key: '<REDACTED:AWS_KEY>',
  provider_token: '<REDACTED:PROVIDER_TOKEN>',
  api_token: '<REDACTED:API_TOKEN>',
  url_credential: '<REDACTED:URL_CREDENTIAL>',
  query_secret: '<REDACTED:QUERY_SECRET>',
  header_secret: '<REDACTED:HEADER_SECRET>',
  key_secret: '<REDACTED:SECRET>',
  email: REDACTED_EMAIL,
  ip: REDACTED_IP,
  uuid: REDACTED_UUID,
};

export const defaultPlaceholderFor: ScrubPlaceholderResolver = (kind) => DEFAULT_PLACEHOLDERS[kind];

export const DEFAULT_SECRET_HEADERS: readonly string[] = [
  'authorization',
  'proxy-authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-goog-api-key',
  'x-amz-security-token',
  'x-amz-signature',
  'stripe-signature',
  'x-auth-token',
  'x-csrf-token',
  'x-xsrf-token',
  'x-webhook-signature',
  'x-hub-signature',
  'x-hub-signature-256',
  'x-slack-signature',
];

export const DEFAULT_SECRET_QUERY_PARAMS: readonly string[] = [
  'key',
  'api_key',
  'apikey',
  'token',
  'access_token',
  'refresh_token',
  'id_token',
  'session_token',
  'secret',
  'password',
  'passwd',
  'sig',
  'signature',
  'x-amz-signature',
  'x-amz-credential',
  'x-amz-security-token',
  'client_secret',
];

export const DEFAULT_SECRET_KEY_PATTERN =
  /^(authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|x[-_]?api[-_]?key|x[-_]?goog[-_]?api[-_]?key|x[-_]?amz[-_]?security[-_]?token|stripe[-_]?signature|api[-_]?key|apiKey|(access|refresh|id|session|auth)[-_]?token|(access|refresh|id|session|auth)Token|client[-_]?secret|clientSecret|private[-_]?key|privateKey|signing[-_]?secret|signingSecret|secret|password|passwd|credential|credentials|token)$/i;

export const DEFAULT_IDENTITY_KEY_PATTERN =
  /^(e-?mail(_?address|Address)?|org(ani[sz]ation)?(_?(id|uuid|name|role)|(Id|Uuid|Name|Role))?|account(_?(id|uuid|name|email|type)|(Id|Uuid|Name|Email|Type))?|user(_?(id|uuid|email|name)|(Id|Uuid|Email|Name))|billing(_?\w+|[A-Z]\w*)?|subscription(_?(id|type|plan)|(Id|Type|Plan))?|plan(_?type|Type)|workspace(_?(id|name)|(Id|Name))|installation(_?id|Id)|chatgpt(_?(account|user|plan)(_?\w+)?))$/i;

export const UUID_EXACT_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const UUID_GLOBAL_PATTERN =
  /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;

export const EMAIL_PATTERN =
  /[A-Za-z0-9._%+-]+@(?!example\.invalid\b)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g;

export const IPV4_PATTERN =
  /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])/g;

export const IPV6_PATTERN =
  /(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}(?![A-Fa-f0-9:])/g;

export const HOME_PATH_LEAK_PATTERN = /\/(?:Users|home)\/(?!Shared\b)[A-Za-z0-9._-]+/;

export interface BuiltInSecretDetector {
  readonly id: string;
  readonly kind: ScrubPlaceholderKind;
  readonly pattern: RegExp;
  /** Prefix preserved when scrubbing (e.g. `Bearer ` before `<REDACTED:BEARER>`). */
  readonly preserveGroup?: number;
  readonly suffix?: string;
}

export const BUILT_IN_SECRET_DETECTORS: readonly BuiltInSecretDetector[] = [
  {
    id: 'pem_private_key',
    kind: 'private_key',
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
  },
  {
    id: 'anthropic_key',
    kind: 'anthropic_key',
    pattern: /\bsk-ant-(?!REDACTED\b)[A-Za-z0-9_-]{8,}/g,
  },
  {
    id: 'openai_key',
    kind: 'openai_key',
    pattern: /\bsk-(?!REDACTED\b)(?:proj-)?[A-Za-z0-9_-]{16,}/g,
  },
  {
    id: 'github_token',
    kind: 'github_token',
    pattern: /\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{20,}/g,
  },
  {
    id: 'google_api_key',
    kind: 'google_key',
    pattern: /\bAIza[A-Za-z0-9_-]{30,}/g,
  },
  {
    id: 'slack_token',
    kind: 'slack_token',
    pattern: /\bxox[abepors]-[A-Za-z0-9-]{10,}/g,
  },
  {
    id: 'slack_webhook',
    kind: 'slack_webhook',
    pattern: /(?:https?:\/\/)?hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
  },
  {
    id: 'render_token',
    kind: 'render_token',
    pattern: /\brnd_[A-Za-z0-9_-]{16,}/g,
  },
  {
    id: 'fly_token_prefix',
    kind: 'fly_token',
    pattern: /\bfo1_[A-Za-z0-9_-]{16,}/g,
  },
  {
    id: 'fly_v1_header',
    kind: 'fly_token',
    pattern: /\b(FlyV1\s+)(?!<REDACTED:|REDACTED\b)[A-Za-z0-9._~+/=,-]{12,}/g,
    preserveGroup: 1,
  },
  {
    id: 'kingdom_token',
    kind: 'kingdom_token',
    pattern: /\bkingdom_(?!REDACTED\b)(?:run_|refresh_)?[A-Za-z0-9_-]{20,}/g,
  },
  {
    id: 'aws_access_key',
    kind: 'aws_key',
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
  },
  {
    id: 'scoped_api_token',
    kind: 'api_token',
    pattern:
      /\b(?:local|pr|staging|prod|test)_(?:user|org|orgUser|space|spaceUser|integration)_[0-9a-f]{48}\b/g,
  },
  {
    id: 'provider_token',
    kind: 'provider_token',
    pattern:
      /\b(?:(?:npm_|glpat-|hf_|whsec_)[A-Za-z0-9_-]{16,}|[a-z]+_(?:live|test|prod|runtime)_[A-Za-z0-9]{16,})/g,
  },
  {
    id: 'jwt',
    kind: 'jwt',
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g,
  },
  {
    id: 'bearer_token',
    kind: 'bearer',
    pattern: /\b(Bearer\s+)(?!<REDACTED:|REDACTED\b)[A-Za-z0-9._~+/=-]{8,}/gi,
    preserveGroup: 1,
  },
  {
    id: 'basic_auth',
    kind: 'basic',
    pattern: /\b(Basic\s+)(?!<REDACTED:|REDACTED\b)[A-Za-z0-9+/=]{8,}/gi,
    preserveGroup: 1,
  },
  {
    id: 'dpop_token',
    kind: 'dpop',
    pattern: /\b(DPoP\s+)(?!<REDACTED:|REDACTED\b)[A-Za-z0-9._~+/=-]{8,}/gi,
    preserveGroup: 1,
  },
  {
    id: 'url_basic_auth',
    kind: 'url_credential',
    pattern: /\b([a-z][a-z0-9+.-]*:\/\/[^\s:/@]*:)(?!<REDACTED:)[^\s/]+@/gi,
    preserveGroup: 1,
    suffix: '@',
  },
];

export const INLINE_ENV_SECRET_PATTERN =
  /\b([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Z0-9_]*\s*[=:]\s*)["']?(?!<REDACTED:|REDACTED\b)[^\s"',}]{8,}["']?/g;

export const SAFE_PLACEHOLDER_PATTERN =
  /^(?:<REDACTED(?::[A-Z0-9_-]+)?>|(?:Bearer|Basic|DPoP|FlyV1)\s+<REDACTED(?::[A-Z0-9_-]+)?>|REDACTED|MASKED|00000000-0000-4000-8000-000000000000|redacted@example\.invalid)$/i;

export const GENERIC_OS_USERNAMES = new Set([
  'root',
  'user',
  'admin',
  'runner',
  'test',
  'app',
  'node',
  'bun',
  'ubuntu',
  'alpine',
  'nobody',
]);
