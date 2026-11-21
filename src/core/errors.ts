export type VcrErrorCode =
  | 'cassette_missing'
  | 'cassette_exhausted'
  | 'request_mismatch'
  | 'unscrubbed_secret'
  | 'drift_detected'
  | 'stale_cassette'
  | 'invalid_cassette'
  | 'live_budget_exceeded'
  | 'version_resolution_failed';

export interface VcrErrorDetails {
  readonly cassette?: string;
  readonly details?: Readonly<Record<string, unknown>>;
  readonly cause?: unknown;
}

export class VcrError extends Error {
  readonly code: VcrErrorCode;
  readonly cassette?: string;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(code: VcrErrorCode, message: string, options: VcrErrorDetails = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'VcrError';
    this.code = code;
    this.cassette = options.cassette;
    this.details = options.details;
  }
}

export const isVcrError = (error: unknown, code?: VcrErrorCode): error is VcrError =>
  error instanceof VcrError && (code === undefined || error.code === code);
