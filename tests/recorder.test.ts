import { afterEach, beforeEach, describe, expect, mock, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  clearVcrVersionCache,
  createVcrRecorder,
  createVcrSession,
  defineVcrTransport,
  isVcrError,
  resetDefaultVcrSession,
  resolveVcrMode,
  seedVcrServiceVersion,
  type VcrCassette,
} from '../src/core/index';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vcr-core-'));
  resetDefaultVcrSession();
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const readCassette = (name: string): VcrCassette =>
  JSON.parse(readFileSync(join(dir, name), 'utf8')) as VcrCassette;

describe('VcrRecorder core, modes, sessions, errors, custom transports, and drift hold-back', () => {
  test('resolves VCR mode from explicit option, env var, or defaults to replay', () => {
    expect(resolveVcrMode({ env: {} })).toBe('replay');
    expect(resolveVcrMode({ env: { VCR_MODE: 'auto' } })).toBe('auto');
    expect(resolveVcrMode({ env: { VCR_MODE: 'record' } })).toBe('record');
    expect(resolveVcrMode({ env: { CUSTOM_VCR: 'record' }, envVar: 'CUSTOM_VCR' })).toBe('record');
    expect(resolveVcrMode({ mode: 'replay', env: { VCR_MODE: 'record' } })).toBe('replay');
    expect(() => resolveVcrMode({ env: { VCR_MODE: 'invalid' } })).toThrow('invalid mode');
  });

  test('supports replay, auto (record-if-missing), and record modes with typed VcrError codes', async () => {
    const session = createVcrSession();
    const liveFn = mock(async () => ({ secret: 'sk-ant-api03-abcdefghijklmnop', value: 42 }));

    // Strict replay fails with cassette_missing when absent.
    const replayMissing = createVcrRecorder(dir, {
      service: 'svc',
      version: '1.0.0',
      mode: 'replay',
      session,
    }).queue('fetch', 'item');
    await expect(replayMissing.capture('fetch', liveFn)).rejects.toMatchObject({
      code: 'cassette_missing',
    });
    expect(liveFn).not.toHaveBeenCalled();

    // Auto mode records on first call (missing), then replays on second call (present).
    const auto1 = createVcrRecorder(dir, {
      service: 'svc',
      version: '1.0.0',
      mode: 'auto',
      session,
    }).queue('fetch', 'item');
    const first = await auto1.capture('fetch', liveFn);
    expect(first).toEqual({ secret: '<REDACTED:SECRET>', value: 42 });
    expect(liveFn).toHaveBeenCalledTimes(1);

    const auto2 = createVcrRecorder(dir, {
      service: 'svc',
      version: '1.0.0',
      mode: 'auto',
      session,
    }).queue('fetch', 'item');
    const second = await auto2.capture('fetch', liveFn);
    expect(second).toEqual(first);
    expect(liveFn).toHaveBeenCalledTimes(1);

    // Exhausted queue fails with cassette_exhausted.
    await expect(auto2.capture('fetch', liveFn)).rejects.toMatchObject({
      code: 'cassette_exhausted',
    });

    // Malformed cassette fails with invalid_cassette.
    writeFileSync(join(dir, 'fetch.broken.json'), '{not-json');
    const broken = createVcrRecorder(dir, {
      service: 'svc',
      version: '1.0.0',
      mode: 'replay',
      session,
    }).queue('fetch', 'broken');
    await expect(broken.capture('fetch', liveFn)).rejects.toMatchObject({
      code: 'invalid_cassette',
    });
  });

  test('writes binary sidecars and replays identical bytes, and supports per-method sanitizers', async () => {
    const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]);
    const session = createVcrSession();

    const recorder = createVcrRecorder(dir, {
      service: 'assets',
      version: '2.0.0',
      mode: 'record',
      session,
      sanitizers: {
        download: { binaryExtension: '.png' },
        list: {
          isArray: true,
          transform: (item) => ({ ...(item as object), tagged: true }),
          keys: ['nested.pin'],
        },
      },
    })
      .queue('download', 'logo')
      .queue('list', 'rows');

    await recorder.capture('download', async () => bytes);
    expect(readCassette('download.logo.json').bodyFile).toBe('download.logo.png');

    const rows: unknown = await recorder.capture('list', async () => [
      { nested: { pin: '1234' }, ok: true },
    ]);
    expect(rows).toEqual([{ nested: { pin: '<REDACTED:SECRET>' }, ok: true, tagged: true }]);

    const replayer = createVcrRecorder(dir, {
      service: 'assets',
      version: '2.0.0',
      mode: 'replay',
      session,
    }).queue('download', 'logo');
    const replayed = await replayer.capture('download', async () => new Uint8Array([0]));
    expect(Buffer.from(replayed).equals(Buffer.from(bytes))).toBe(true);
  });

  test('shares service version cache and enforces live call budget', async () => {
    const versionFn = mock(async () => '3.1.0');
    await createVcrRecorder(dir, { service: 'shared-svc', version: versionFn, mode: 'record' })
      .queue('a', '1')
      .capture('a', async () => 1);
    await createVcrRecorder(dir, { service: 'shared-svc', version: versionFn, mode: 'record' })
      .queue('b', '2')
      .capture('b', async () => 2);
    expect(versionFn).toHaveBeenCalledTimes(1);

    clearVcrVersionCache();
    seedVcrServiceVersion('preseeded', '9.9.9');
    const neverCalled = mock(async () => 'nope');
    await createVcrRecorder(dir, { service: 'preseeded', version: neverCalled, mode: 'record' })
      .queue('c', '1')
      .capture('c', async () => 3);
    expect(neverCalled).not.toHaveBeenCalled();
    expect(readCassette('c.1.json').version).toBe('9.9.9');

    const tightSession = createVcrSession({ maxLiveCalls: 1 });
    const limited = createVcrRecorder(dir, {
      service: 'budget',
      version: '1.0.0',
      mode: 'record',
      session: tightSession,
    }).queueMany('call', ['one', 'two']);
    await limited.capture('call', async () => 'first');
    await expect(limited.capture('call', async () => 'second')).rejects.toMatchObject({
      code: 'live_budget_exceeded',
    });
  });

  test('blocks persisting cassettes when an unscrubbed secret survives into storeCassette', async () => {
    const session = createVcrSession();
    const recorder = createVcrRecorder(dir, {
      service: 'guard',
      version: '1.0.0',
      mode: 'record',
      session,
      scrubber: { knownSecrets: ['ultra-classified-token'] },
    }).queue('raw', 'leak');

    const path = recorder.popCassettePath('raw');
    await expect(
      recorder.storeCassette(path, {
        status: 200,
        body: { leaked: 'ultra-classified-token' },
      }),
    ).rejects.toMatchObject({ code: 'unscrubbed_secret' });
    expect(existsSync(path)).toBe(false);
  });

  test('holds back drifted recordings AND earlier undrifted recordings to .pending.json', async () => {
    const session = createVcrSession();
    const onDrift = mock(() => {});

    const baseline = createVcrRecorder(dir, {
      service: 'svc',
      version: '1.0.0',
      mode: 'record',
      session,
    })
      .queue('stepA', 'x')
      .queue('stepB', 'x')
      .queue('outcome', 'x');
    await baseline.capture('stepA', async () => ({ count: 1 }));
    await baseline.capture('stepB', async () => ({ count: 1 }));
    await baseline.recordOutcome('outcome', { ok: true });

    const originalStepA = readFileSync(join(dir, 'stepA.x.json'), 'utf8');

    const nextRun = createVcrRecorder(dir, {
      service: 'svc',
      version: '1.0.0',
      mode: 'record',
      session,
      onDrift,
    })
      .queue('stepA', 'x')
      .queue('stepB', 'x')
      .queue('outcome', 'x');

    await nextRun.capture('stepA', async () => ({ count: 2 }));
    expect(readCassette('stepA.x.json').body).toEqual({ count: 2 });

    // stepB changes structure (number -> string + new boolean), triggering hold-back for stepA, stepB, and outcome!
    await nextRun.capture('stepB', async () => ({ count: 'drifted', extra: true }));
    await nextRun.recordOutcome('outcome', { ok: false });

    expect(onDrift).toHaveBeenCalledTimes(1);
    expect(session.drift).toHaveLength(1);
    expect(session.drift[0]?.differences).toEqual([
      'body added count:string, extra:boolean',
      'body removed count:number',
    ]);

    expect(readFileSync(join(dir, 'stepA.x.json'), 'utf8')).toBe(originalStepA);
    expect(readCassette('stepA.x.pending.json').body).toEqual({ count: 2 });
    expect(readCassette('stepB.x.json').body).toEqual({ count: 1 });
    expect(readCassette('stepB.x.pending.json').body).toEqual({ count: 'drifted', extra: true });
    expect(readCassette('outcome.x.json').body).toEqual({ ok: true });
    expect(readCassette('outcome.x.pending.json').body).toEqual({ ok: false });

    // throwOnDrift option also raises typed VcrError('drift_detected') after holding back.
    const strictDrift = createVcrRecorder(dir, {
      service: 'svc',
      version: '1.0.0',
      mode: 'record',
      session: createVcrSession(),
      throwOnDrift: true,
    }).queue('stepB', 'x');
    await expect(
      strictDrift.capture('stepB', async () => ({ completely: 'different' })),
    ).rejects.toMatchObject({ code: 'drift_detected' });
  });

  test('executes a custom SQL VcrTransport end-to-end with scrubbing, canonical keys, and strict replay', async () => {
    interface SqlQuery {
      readonly sql: string;
      readonly params: readonly unknown[];
    }
    const dbMock = mock(async (req: SqlQuery) => ({
      status: 200,
      body: [{ id: 1, email: 'owner@company.com', query: req.sql }],
    }));

    const sqlTransport = defineVcrTransport<SqlQuery, Array<Record<string, unknown>>>({
      name: 'sql',
      canonicalKey: (req) => `${req.sql}::${JSON.stringify(req.params)}`,
      scrubRequest: (req, scrubber) => scrubber.scrubValue(req),
      scrubResponse: (rows, scrubber) => scrubber.scrubValue(rows),
      executeLive: dbMock,
    });

    const session = createVcrSession();
    const recordVcr = createVcrRecorder(dir, {
      service: 'postgres',
      version: '16.4',
      mode: 'record',
      session,
    }).queue('sql', 'find-user');

    const liveRes = await recordVcr.execute('sql', sqlTransport, {
      sql: 'SELECT id, email FROM users WHERE email = $1',
      params: ['owner@company.com'],
    });
    expect(liveRes.status).toBe(200);
    expect(liveRes.body).toEqual([
      {
        id: 1,
        email: 'redacted@example.invalid',
        query: 'SELECT id, email FROM users WHERE email = $1',
      },
    ]);
    expect(readFileSync(join(dir, 'sql.find-user.json'), 'utf8')).not.toContain('company.com');

    // Replay with matching scrubbed canonical key succeeds without touching dbMock.
    const replayVcr = createVcrRecorder(dir, {
      service: 'postgres',
      version: '16.4',
      mode: 'replay',
      session,
    }).queueMany('sql', ['find-user', 'find-user']);

    const replayed = await replayVcr.execute('sql', sqlTransport, {
      sql: 'SELECT id, email FROM users WHERE email = $1',
      params: ['different@other.org'],
    });
    expect(replayed.body).toEqual(liveRes.body);
    expect(dbMock).toHaveBeenCalledTimes(1);

    // Replay with a different SQL statement fails with VcrError('request_mismatch').
    let mismatchError: unknown;
    try {
      await replayVcr.execute('sql', sqlTransport, {
        sql: 'DELETE FROM users',
        params: [],
      });
    } catch (error) {
      mismatchError = error;
    }
    expect(isVcrError(mismatchError, 'request_mismatch')).toBe(true);
  });
});
