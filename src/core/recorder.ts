import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join, relative } from 'node:path';
import {
  type CassetteSignature,
  compareSignatures,
  type SignatureOptions,
  signatureOfCassette,
} from '../freshness/signature';
import { createScrubber } from '../scrub/scrubber';
import type { Scrubber, ScrubOptions } from '../scrub/types';
import { VcrError } from './errors';
import { defaultVcrSession, resolveVcrMode } from './session';
import type {
  DriftFinding,
  StoreCassetteInput,
  VcrCassette,
  VcrMethodSanitizer,
  VcrMode,
  VcrRecorderOptions,
  VcrRecordingStamp,
  VcrResponse,
  VcrSession,
  VcrTransport,
  VcrVersionResolver,
} from './types';

const isScrubberHandle = (value: Scrubber | ScrubOptions | undefined): value is Scrubber =>
  Boolean(value && typeof value === 'object' && 'scrubText' in value && 'assertScrubbed' in value);

const writeCassetteJson = (filePath: string, data: unknown): void => {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`);
};

const maskValuesAtKeyPaths = <T>(data: T, keys: readonly string[]): T => {
  if (!keys.length) return data;
  const clone = structuredClone(data);
  for (const key of keys) maskKeyPath(clone, key.split('.'));
  return clone;
};

const maskKeyPath = (node: unknown, parts: readonly string[]): void => {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) maskKeyPath(item, parts);
    return;
  }
  const record = node as Record<string, unknown>;
  const [head, ...rest] = parts;
  if (head === undefined) return;
  if (rest.length === 0) {
    if (head in record) {
      const current = record[head];
      record[head] =
        current === null || current === undefined || typeof current === 'object'
          ? current
          : '<REDACTED:SECRET>';
    }
    return;
  }
  maskKeyPath(record[head], rest);
};

const signatureForCassette = (
  cassette: Pick<VcrCassette, 'status' | 'body' | 'entries'>,
  options?: SignatureOptions,
): CassetteSignature => {
  const payload = cassette.entries !== undefined ? { entries: cassette.entries } : cassette.body;
  return signatureOfCassette(cassette.status, payload, options);
};

export class VcrRecorder {
  readonly service: string;
  readonly fixturesDir: string;
  readonly cli?: string;
  readonly model?: string;
  readonly metadata?: Readonly<Record<string, string>>;
  readonly scrubber: Scrubber;
  readonly session: VcrSession;

  private readonly explicitMode?: VcrMode;
  private readonly modeEnvVar?: string;
  private readonly environment?: string;
  private readonly outputDir?: string;
  private readonly versionResolver: VcrVersionResolver;
  private readonly sanitizers: Readonly<Record<string, VcrMethodSanitizer>>;
  private readonly signatureOptions?: SignatureOptions;
  private readonly verifyScrubbed: boolean;
  private readonly throwOnDrift: boolean;
  private readonly onDrift?: (finding: DriftFinding) => void;

  private readonly queues = new Map<string, string[]>();
  private readonly pendingWrites = new Set<Promise<unknown>>();
  private drifted = false;
  private readonly undriftedWrites = new Map<
    string,
    { readonly target: string; readonly previous: string | undefined }
  >();

  constructor(fixturesDir: string, options: VcrRecorderOptions) {
    this.fixturesDir = fixturesDir;
    this.service = options.service;
    this.versionResolver = options.version;
    this.explicitMode = options.mode;
    this.modeEnvVar = options.modeEnvVar;
    this.environment = options.environment;
    this.outputDir = options.outputDir;
    this.cli = options.cli;
    this.model = options.model;
    this.metadata = options.metadata;
    this.sanitizers = options.sanitizers ?? {};
    this.signatureOptions = options.signature;
    this.verifyScrubbed = options.verifyScrubbed ?? true;
    this.throwOnDrift = options.throwOnDrift ?? false;
    this.onDrift = options.onDrift;
    this.session = options.session ?? defaultVcrSession;
    this.scrubber = isScrubberHandle(options.scrubber)
      ? options.scrubber
      : createScrubber(options.scrubber);
  }

  get mode(): VcrMode {
    return resolveVcrMode({ mode: this.explicitMode, envVar: this.modeEnvVar });
  }

  queue(method: string, cassetteName: string): this {
    const queue = this.queues.get(method) ?? [];
    queue.push(cassetteName);
    this.queues.set(method, queue);
    return this;
  }

  queueMany(method: string, cassetteNames: readonly string[]): this {
    for (const name of cassetteNames) this.queue(method, name);
    return this;
  }

  popCassettePath(method: string): string {
    const queue = this.queues.get(method);
    const cassetteName = queue?.shift();
    if (!cassetteName) {
      throw new VcrError('cassette_exhausted', `VCR: no cassette queued for "${method}"`, {
        details: { method, service: this.service },
      });
    }
    return join(this.fixturesDir, `${method}.${cassetteName}.json`);
  }

  shouldReplay(cassettePath: string, recordOnce = false): boolean {
    const activeMode = this.mode;
    if (activeMode === 'replay') return true;
    if (recordOnce && this.session.written.has(cassettePath)) return true;
    if (activeMode === 'auto') {
      const resolved = this.session.written.get(cassettePath) ?? cassettePath;
      return existsSync(resolved);
    }
    return false;
  }

  async fetchServiceVersion(): Promise<string> {
    const cached = this.session.versionCache.get(this.service);
    if (cached !== undefined) return cached;
    const resolved =
      typeof this.versionResolver === 'string'
        ? this.versionResolver
        : await this.versionResolver();
    if (!resolved) {
      throw new VcrError(
        'version_resolution_failed',
        `VCR: version resolver returned an empty string (service=${this.service})`,
        { details: { service: this.service } },
      );
    }
    this.session.versionCache.set(this.service, resolved);
    return resolved;
  }

  fetchCassette<TRequest = unknown, TResponse = unknown>(
    requestedPath: string,
  ): VcrCassette<TRequest, TResponse> {
    const resolvedPath = this.session.written.get(requestedPath) ?? requestedPath;
    if (!existsSync(resolvedPath)) {
      throw new VcrError(
        'cassette_missing',
        `VCR: cassette "${basename(resolvedPath)}" is missing; record it in "record" or "auto" mode`,
        { cassette: resolvedPath },
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(resolvedPath, 'utf8'));
    } catch (error) {
      throw new VcrError(
        'invalid_cassette',
        `VCR: cassette "${basename(resolvedPath)}" contains invalid JSON`,
        { cassette: resolvedPath, cause: error },
      );
    }
    if (
      !parsed ||
      typeof parsed !== 'object' ||
      typeof (parsed as { status?: unknown }).status !== 'number'
    ) {
      throw new VcrError(
        'invalid_cassette',
        `VCR: cassette "${basename(resolvedPath)}" is missing a numeric "status" field`,
        { cassette: resolvedPath },
      );
    }
    return parsed as VcrCassette<TRequest, TResponse>;
  }

  async capture<T>(method: string, executeLive: () => Promise<T>): Promise<T> {
    const cassettePath = this.popCassettePath(method);
    if (this.shouldReplay(cassettePath)) {
      const saved = this.fetchCassette<unknown, T>(cassettePath);
      if (saved.status >= 400) {
        throw new Error(typeof saved.body === 'string' ? saved.body : JSON.stringify(saved.body));
      }
      if (saved.bodyFile) {
        const resolvedPath = this.session.written.get(cassettePath) ?? cassettePath;
        return readFileSync(join(dirname(resolvedPath), saved.bodyFile)) as unknown as T;
      }
      return saved.body as T;
    }

    this.session.spendLiveCall(`${this.service} ${method}`);
    const started = Date.now();
    try {
      const sanitized = this.sanitizeMethodPayload(method, await executeLive());
      await this.persistPayload(cassettePath, method, sanitized, 200, undefined, {
        durationMs: Date.now() - started,
      });
      return sanitized;
    } catch (error) {
      const message = this.scrubber.scrubText(
        error instanceof Error ? error.message : String(error),
      );
      await this.storeCassette(
        cassettePath,
        { transport: 'capture', status: 500, body: message },
        { durationMs: Date.now() - started },
      );
      throw error;
    }
  }

  async captureResponse<T>(
    method: string,
    executeLive: () => Promise<VcrResponse<T>>,
  ): Promise<VcrResponse<T>> {
    const cassettePath = this.popCassettePath(method);
    if (this.shouldReplay(cassettePath)) {
      const saved = this.fetchCassette<unknown, T>(cassettePath);
      const resolvedPath = this.session.written.get(cassettePath) ?? cassettePath;
      const body = saved.bodyFile
        ? (readFileSync(join(dirname(resolvedPath), saved.bodyFile)) as unknown as T)
        : (saved.body as T);
      return {
        status: saved.status,
        body,
        ...(saved.headers ? { headers: saved.headers } : {}),
      };
    }

    this.session.spendLiveCall(`${this.service} ${method}`);
    const started = Date.now();
    try {
      const live = await executeLive();
      const sanitizedBody = this.sanitizeMethodPayload(method, live.body);
      const scrubbedHeaders = live.headers ? this.scrubber.scrubHeaders(live.headers) : undefined;
      await this.persistPayload(cassettePath, method, sanitizedBody, live.status, scrubbedHeaders, {
        durationMs: Date.now() - started,
      });
      return {
        status: live.status,
        body: sanitizedBody,
        ...(scrubbedHeaders ? { headers: scrubbedHeaders } : {}),
      };
    } catch (error) {
      const message = this.scrubber.scrubText(
        error instanceof Error ? error.message : String(error),
      );
      await this.storeCassette(
        cassettePath,
        { transport: 'capture', status: 500, body: message },
        { durationMs: Date.now() - started },
      );
      throw error;
    }
  }

  async execute<TRequest, TResponse>(
    method: string,
    transport: VcrTransport<TRequest, TResponse>,
    request: TRequest,
  ): Promise<VcrResponse<TResponse>> {
    const cassettePath = this.popCassettePath(method);
    const scrubbedRequest = transport.scrubRequest(request, this.scrubber);
    const incomingKey = transport.canonicalKey(scrubbedRequest);

    if (this.shouldReplay(cassettePath)) {
      const saved = this.fetchCassette<TRequest, TResponse>(cassettePath);
      if (saved.request !== undefined) {
        const mismatch = transport.matchRequest
          ? transport.matchRequest(saved.request, scrubbedRequest)
          : saved.key !== undefined && saved.key !== incomingKey
            ? `expected "${saved.key}", received "${incomingKey}"`
            : undefined;
        if (mismatch) {
          throw new VcrError('request_mismatch', `VCR replay (${transport.name}): ${mismatch}`, {
            cassette: cassettePath,
            details: { transport: transport.name, recordedKey: saved.key, incomingKey },
          });
        }
      } else if (saved.key !== undefined && saved.key !== incomingKey) {
        throw new VcrError(
          'request_mismatch',
          `VCR replay (${transport.name}): expected "${saved.key}", received "${incomingKey}"`,
          {
            cassette: cassettePath,
            details: { transport: transport.name, recordedKey: saved.key, incomingKey },
          },
        );
      }

      const resolvedPath = this.session.written.get(cassettePath) ?? cassettePath;
      const body = saved.bodyFile
        ? (readFileSync(join(dirname(resolvedPath), saved.bodyFile)) as unknown as TResponse)
        : (saved.body as TResponse);
      return {
        status: saved.status,
        body,
        ...(saved.headers ? { headers: saved.headers } : {}),
      };
    }

    this.session.spendLiveCall(`${this.service} ${transport.name}:${method}`);
    const started = Date.now();
    const live = await transport.executeLive(request);
    const scrubbedBody = transport.scrubResponse(
      this.sanitizeMethodPayload(method, live.body),
      this.scrubber,
    );
    const scrubbedHeaders = live.headers ? this.scrubber.scrubHeaders(live.headers) : undefined;
    await this.storeCassette(
      cassettePath,
      {
        transport: transport.name,
        key: incomingKey,
        request: scrubbedRequest,
        status: live.status,
        body: scrubbedBody,
        ...(scrubbedHeaders ? { headers: scrubbedHeaders } : {}),
      },
      {
        transport: transport.name,
        durationMs: Date.now() - started,
        ...(live.metadata ? { metadata: live.metadata } : {}),
      },
    );
    return {
      status: live.status,
      body: scrubbedBody,
      ...(scrubbedHeaders ? { headers: scrubbedHeaders } : {}),
    };
  }

  /** Records a test's live conclusion on record and returns the recorded conclusion on replay. */
  async recordOutcome<T>(method: string, value: T): Promise<T> {
    const cassettePath = this.popCassettePath(method);
    if (this.shouldReplay(cassettePath)) {
      return this.fetchCassette<unknown, T>(cassettePath).body as T;
    }
    const scrubbed = this.scrubber.scrubValue(JSON.parse(JSON.stringify(value)) as T);
    await this.storeCassette(cassettePath, { transport: 'outcome', status: 200, body: scrubbed });
    return scrubbed;
  }

  /** Stamps, asserts secret-safety, checks drift, and writes a cassette to disk. */
  storeCassette<TRequest = unknown, TResponse = unknown>(
    cassettePath: string,
    cassette: StoreCassetteInput<TRequest, TResponse>,
    stampExtra: Partial<VcrRecordingStamp> = {},
  ): Promise<string> {
    const saving = (async () => {
      const version = await this.fetchServiceVersion();
      const mergedMetadata =
        this.metadata || stampExtra.metadata
          ? { ...this.metadata, ...stampExtra.metadata }
          : undefined;
      const recorded: VcrRecordingStamp = {
        service: this.service,
        transport: stampExtra.transport ?? cassette.transport ?? 'capture',
        recordedAt: new Date().toISOString(),
        environment: this.environment ?? process.env.VCR_ENVIRONMENT ?? 'terminal',
        ...(this.cli ? { cli: this.cli } : {}),
        ...(this.model ? { model: this.model } : {}),
        ...stampExtra,
        ...(mergedMetadata ? { metadata: mergedMetadata } : {}),
      };
      const next: VcrCassette<TRequest, TResponse> = {
        version,
        ...cassette,
        recorded,
      };

      if (this.verifyScrubbed) {
        this.scrubber.assertScrubbed(next, basename(cassettePath));
      }

      const { target, driftFinding } = this.resolveTargetPath(cassettePath, next);
      if (!this.drifted && !this.undriftedWrites.has(cassettePath)) {
        this.undriftedWrites.set(cassettePath, {
          target,
          previous: existsSync(target) ? readFileSync(target, 'utf8') : undefined,
        });
      }
      writeCassetteJson(target, next);
      this.session.written.set(cassettePath, target);

      if (driftFinding && this.throwOnDrift) {
        throw new VcrError(
          'drift_detected',
          `VCR: structural drift in "${basename(cassettePath)}": ${driftFinding.differences.join('; ')}`,
          { cassette: cassettePath, details: { finding: driftFinding } },
        );
      }
      return target;
    })();
    this.trackPendingWrite(saving);
    return saving;
  }

  /** Tracks an asynchronous cassette write so `waitUntilSettled()` awaits completion. */
  trackPendingWrite<T>(work: Promise<T>): Promise<T> {
    this.pendingWrites.add(work);
    void work.finally(() => this.pendingWrites.delete(work)).catch(() => {});
    return work;
  }

  /** Resolves once every tracked recording started on this recorder has finished writing. */
  async waitUntilSettled(): Promise<void> {
    while (this.pendingWrites.size > 0) {
      await Promise.allSettled([...this.pendingWrites]);
    }
  }

  isQueueEmpty(): boolean {
    for (const queue of this.queues.values()) {
      if (queue.length > 0) return false;
    }
    return true;
  }

  clearQueues(): void {
    this.queues.clear();
  }

  private resolveTargetPath(
    cassettePath: string,
    next: VcrCassette,
  ): { readonly target: string; readonly driftFinding?: DriftFinding } {
    const outputRoot = this.outputDir ?? process.env.VCR_OUT;
    const out = outputRoot
      ? join(outputRoot, relative(this.fixturesDir, cassettePath))
      : cassettePath;
    const pendingPath = out.replace(/\.json$/, '.pending.json');
    if (this.drifted) return { target: pendingPath };
    if (!existsSync(cassettePath)) return { target: out };

    const committed = JSON.parse(readFileSync(cassettePath, 'utf8')) as VcrCassette;
    const differences = compareSignatures(
      signatureForCassette(committed, this.signatureOptions),
      signatureForCassette(next, this.signatureOptions),
      this.signatureOptions,
    );
    if (differences.length === 0) return { target: out };

    this.drifted = true;
    this.holdBackUndriftedWrites();
    const finding: DriftFinding = { cassette: cassettePath, pending: pendingPath, differences };
    this.session.drift.push(finding);
    this.onDrift?.(finding);
    return { target: pendingPath, driftFinding: finding };
  }

  // why: all cassettes from one test run must come from the same live run, so earlier writes move to pending too.
  private holdBackUndriftedWrites(): void {
    for (const [cassettePath, { target, previous }] of this.undriftedWrites) {
      if (!existsSync(target)) continue;
      const pending = target.replace(/\.json$/, '.pending.json');
      writeFileSync(pending, readFileSync(target, 'utf8'));
      if (previous === undefined) rmSync(target);
      else writeFileSync(target, previous);
      this.session.written.set(cassettePath, pending);
    }
    this.undriftedWrites.clear();
  }

  private async persistPayload<T>(
    cassettePath: string,
    method: string,
    body: T,
    status: number,
    headers?: Readonly<Record<string, string>>,
    stampExtra?: Partial<VcrRecordingStamp>,
  ): Promise<void> {
    if (body instanceof Uint8Array) {
      const ext = this.sanitizers[method]?.binaryExtension ?? '.bin';
      const baseName = basename(cassettePath, extname(cassettePath));
      const sidecarName = `${baseName}${ext}`;
      const targetPath = await this.storeCassette(
        cassettePath,
        {
          transport: 'capture',
          status,
          bodyFile: sidecarName,
          ...(headers ? { headers } : {}),
        },
        stampExtra,
      );
      const sidecarPath = join(dirname(targetPath), sidecarName);
      mkdirSync(dirname(sidecarPath), { recursive: true });
      writeFileSync(sidecarPath, body);
      return;
    }

    await this.storeCassette(
      cassettePath,
      {
        transport: 'capture',
        status,
        body,
        ...(headers ? { headers } : {}),
      },
      stampExtra,
    );
  }

  private sanitizeMethodPayload<T>(method: string, data: T): T {
    if (data instanceof Uint8Array) return data;
    const rule = this.sanitizers[method];
    let transformed: unknown = data;
    if (rule) {
      if (rule.isArray && Array.isArray(data)) {
        transformed = data.map((item) => this.applyMethodSanitizer(rule, item));
      } else {
        transformed = this.applyMethodSanitizer(rule, data);
      }
    }
    return this.scrubber.scrubValue(transformed) as T;
  }

  private applyMethodSanitizer<T>(rule: VcrMethodSanitizer, data: T): T {
    const transformed = rule.transform ? (rule.transform(data) as T) : data;
    if (rule.keys?.length) return maskValuesAtKeyPaths(transformed, rule.keys);
    return transformed;
  }
}

/** Creates a new `VcrRecorder` bound to `fixturesDir` and the given service/scrubber configuration. */
export const createVcrRecorder = (fixturesDir: string, options: VcrRecorderOptions): VcrRecorder =>
  new VcrRecorder(fixturesDir, options);
