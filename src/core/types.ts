import type { SignatureOptions } from '../freshness/signature';
import type { Scrubber, ScrubOptions } from '../scrub/types';

export type VcrMode = 'replay' | 'auto' | 'record';

export const VCR_MODES: readonly VcrMode[] = ['replay', 'auto', 'record'] as const;

export const DEFAULT_MAX_LIVE_CALLS = 80;
export const DEFAULT_MODE_ENV_VAR = 'VCR_MODE';

export interface VcrRecordingStamp {
  readonly service: string;
  readonly transport: string;
  readonly recordedAt: string;
  readonly environment: string;
  readonly cli?: string;
  readonly model?: string;
  readonly durationMs?: number;
  readonly metadata?: Readonly<Record<string, string>>;
}

export interface VcrEntry<TRequest = unknown, TResponse = unknown> {
  readonly key?: string;
  readonly request?: TRequest;
  readonly status: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: TResponse | null;
  readonly bodyFile?: string;
}

export interface VcrCassette<TRequest = unknown, TResponse = unknown> {
  readonly version?: string;
  readonly transport?: string;
  readonly key?: string;
  readonly request?: TRequest;
  readonly status: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: TResponse | null;
  readonly bodyFile?: string;
  readonly entries?: readonly VcrEntry<TRequest, TResponse>[];
  readonly recorded?: VcrRecordingStamp;
}

export interface VcrResponse<T = unknown> {
  readonly status: number;
  readonly body: T;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface VcrMethodSanitizer {
  readonly transform?: (data: unknown) => unknown;
  readonly keys?: readonly string[];
  readonly isArray?: boolean;
  readonly binaryExtension?: string;
}

export type VcrVersionResolver = string | (() => string | Promise<string>);

export interface DriftFinding {
  readonly cassette: string;
  readonly pending: string;
  readonly differences: readonly string[];
}

export interface VcrLiveResult<TResponse = unknown> {
  readonly status: number;
  readonly body: TResponse;
  readonly headers?: Readonly<Record<string, string>>;
  readonly metadata?: Readonly<Record<string, string>>;
}

export interface VcrTransport<TRequest = unknown, TResponse = unknown> {
  /** Transport identifier stamped onto recorded cassettes (e.g. 'http', 'sql', 'rpc'). */
  readonly name: string;
  /** Deterministic canonical key for a request, used for matching and mismatch errors. */
  canonicalKey(request: TRequest): string;
  /** Scrubs a request before recording or comparing on replay. */
  scrubRequest(request: TRequest, scrubber: Scrubber): TRequest;
  /** Scrubs a response payload before persisting to disk. */
  scrubResponse(response: TResponse, scrubber: Scrubber): TResponse;
  /** Optional custom matcher; returns a human-readable mismatch description, or undefined if matched. */
  matchRequest?(recorded: TRequest, incoming: TRequest): string | undefined;
  /** Executes the real upstream operation when recording. */
  executeLive(request: TRequest): Promise<VcrLiveResult<TResponse>>;
}

export interface VcrSessionOptions {
  /** Maximum live upstream calls permitted in a single session. Defaults to 80. */
  readonly maxLiveCalls?: number;
}

export interface VcrRecorderOptions {
  /** Stable identifier for the upstream service (keys version cache and recording stamps). */
  readonly service: string;
  /** Upstream version string or resolver callback stamped into recorded cassettes. */
  readonly version: VcrVersionResolver;
  /** Explicit VCR mode; when omitted, resolved via `modeEnvVar` (default `VCR_MODE`). */
  readonly mode?: VcrMode;
  /** Environment variable checked when `mode` is omitted. Defaults to `VCR_MODE`. */
  readonly modeEnvVar?: string;
  /** Environment label stamped into recordings (e.g. 'terminal', 'ci', 'daemon'). */
  readonly environment?: string;
  /** Optional directory where recordings are written instead of `fixturesDir`. */
  readonly outputDir?: string;
  /** Optional CLI binary name stamped into recordings for freshness checks. */
  readonly cli?: string;
  /** Optional model identifier stamped into recordings. */
  readonly model?: string;
  /** Optional package/runtime metadata versions stamped into recordings. */
  readonly metadata?: Readonly<Record<string, string>>;
  /** Scrubber instance or options used to sanitize and assert cassettes before disk writes. */
  readonly scrubber?: Scrubber | ScrubOptions;
  /** Optional per-method custom sanitizers applied before global scrubbing. */
  readonly sanitizers?: Readonly<Record<string, VcrMethodSanitizer>>;
  /** Structural signature options for drift detection. */
  readonly signature?: SignatureOptions;
  /** Verify recorded cassettes with `assertScrubbed` before writing to disk. Defaults to true. */
  readonly verifyScrubbed?: boolean;
  /** When true, throw `VcrError('drift_detected')` after holding back drifted cassettes to `.pending.json`. Defaults to false. */
  readonly throwOnDrift?: boolean;
  /** Optional callback invoked whenever structural drift is detected during recording. */
  readonly onDrift?: (finding: DriftFinding) => void;
  /** Optional shared session state (version cache, live call budget, written map, drift list). */
  readonly session?: VcrSession;
}

export interface ResolveModeOptions {
  readonly mode?: VcrMode;
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly envVar?: string;
}

export interface StoreCassetteInput<TRequest = unknown, TResponse = unknown> {
  readonly transport?: string;
  readonly key?: string;
  readonly request?: TRequest;
  readonly status: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: TResponse | null;
  readonly bodyFile?: string;
  readonly entries?: readonly VcrEntry<TRequest, TResponse>[];
}

export interface VcrSession {
  readonly versionCache: Map<string, string>;
  readonly drift: DriftFinding[];
  readonly written: Map<string, string>;
  liveCalls: number;
  maxLiveCalls: number;
  spendLiveCall(label: string): void;
  seedVersion(service: string, version: string): void;
  clearVersionCache(): void;
  reset(): void;
}
