import { VcrError } from './errors';
import {
  DEFAULT_MAX_LIVE_CALLS,
  DEFAULT_MODE_ENV_VAR,
  type DriftFinding,
  type ResolveModeOptions,
  VCR_MODES,
  type VcrMode,
  type VcrSession,
  type VcrSessionOptions,
} from './types';

const parseEnvMaxLive = (): number => {
  const raw = process.env.VCR_MAX_LIVE;
  if (!raw) return DEFAULT_MAX_LIVE_CALLS;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : DEFAULT_MAX_LIVE_CALLS;
};

/** Resolves the active VCR mode by precedence: explicit option -> env var -> `'replay'`. */
export const resolveVcrMode = (options: ResolveModeOptions = {}): VcrMode => {
  if (options.mode !== undefined) return options.mode;
  const env = options.env ?? process.env;
  const envVar = options.envVar ?? DEFAULT_MODE_ENV_VAR;
  const raw = env[envVar]?.trim();
  if (!raw) return 'replay';
  if ((VCR_MODES as readonly string[]).includes(raw)) return raw as VcrMode;
  throw new VcrError(
    'invalid_cassette',
    `VCR: invalid mode "${raw}" in ${envVar} (expected one of: ${VCR_MODES.join(', ')})`,
  );
};

/** Creates an isolated VCR session holding version cache, live call budget, written cassette paths, and drift findings. */
export const createVcrSession = (options: VcrSessionOptions = {}): VcrSession => {
  const versionCache = new Map<string, string>();
  const drift: DriftFinding[] = [];
  const written = new Map<string, string>();

  const session: VcrSession = {
    versionCache,
    drift,
    written,
    liveCalls: 0,
    maxLiveCalls: options.maxLiveCalls ?? parseEnvMaxLive(),
    spendLiveCall(label: string): void {
      const limit = options.maxLiveCalls ?? session.maxLiveCalls;
      if (++session.liveCalls > limit) {
        throw new VcrError(
          'live_budget_exceeded',
          `VCR: live call budget of ${limit} spent; refusing "${label}"`,
          { details: { limit, liveCalls: session.liveCalls, label } },
        );
      }
    },
    seedVersion(service: string, version: string): void {
      versionCache.set(service, version);
    },
    clearVersionCache(): void {
      versionCache.clear();
    },
    reset(): void {
      versionCache.clear();
      drift.length = 0;
      written.clear();
      session.liveCalls = 0;
      session.maxLiveCalls = options.maxLiveCalls ?? parseEnvMaxLive();
    },
  };

  return session;
};

export const defaultVcrSession: VcrSession = createVcrSession();

/** Pre-seeds the default session's version cache so recorders for `service` skip live version probes. */
export const seedVcrServiceVersion = (service: string, version: string): void => {
  defaultVcrSession.seedVersion(service, version);
};

/** Clears cached upstream service versions in the default VCR session. */
export const clearVcrVersionCache = (): void => {
  defaultVcrSession.clearVersionCache();
};

/** Resets the default VCR session's version cache, live call count, written paths, and drift log. */
export const resetDefaultVcrSession = (): void => {
  defaultVcrSession.reset();
};
