import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  acceptPendingCassettes,
  assertCassettesFresh,
  blessFreshnessPolicy,
  checkCassetteFreshness,
  compareSignatures,
  compareVersions,
  compareVolatileSignatures,
  diffCassetteDrift,
  diffVolatileCassetteNotices,
  discardPendingCassettes,
  eventKindOf,
  fetchCassettePaths,
  fetchCliVersion,
  fetchFreshnessPolicy,
  fetchHttpVersion,
  fetchInstalledVersions,
  fetchPendingCassettes,
  signatureOfCassette,
  validateCassette,
  writeFreshnessPolicy,
} from '../src/freshness/index';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vcr-freshness-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('signatures, drift, pending workflow, versions, and freshness policy', () => {
  test('computes structural signatures, collapses ID-keyed maps, and separates volatile notices from drift', () => {
    const transcript = (...events: object[]) =>
      signatureOfCassette(0, {
        kind: 'process',
        argv: ['tool', '--json'],
        frames: events.map((event) => ({ stream: 'stdout', data: JSON.stringify(event) })),
        exit: { code: 0 },
      });

    const init = { type: 'system', subtype: 'init', model: 'm' };
    const result = { type: 'result', subtype: 'success', text: 'ok' };
    const volatileOpts = {
      volatileKinds: [/^stderr$/, /^stdout:rate_limit_event$/],
      volatilePaths: [/^diagnostics\b/],
    };

    const withId = (id: string) =>
      transcript(init, {
        type: 'assistant',
        message: { content: [{ type: 'tool_use', id }] },
        wire_inputs: { [id]: { cmd: 'ls' } },
      });
    expect(
      compareSignatures(
        withId('toolu_01PChqq8ejtgM2e7a96gxR2P'),
        withId('toolu_01VrTGy4P6VX3bVfh1CH9ATv'),
      ),
    ).toEqual([]);

    const clean = transcript(init, { ...result, diagnostics: null });
    const noisy = transcript(
      init,
      { type: 'rate_limit_event', retryAfter: 5 },
      { ...result, diagnostics: { reason: 'ttl' } },
    );

    expect(compareSignatures(clean, noisy, volatileOpts)).toEqual([]);
    expect(compareVolatileSignatures(clean, noisy, volatileOpts)).toEqual([
      'new stdout:rate_limit_event',
      'stdout:result:success added diagnostics.reason:string',
      'stdout:result:success removed diagnostics:null',
    ]);

    expect(eventKindOf({ id: 1, result: { ok: true } })).toBe('rpc:result');
    expect(eventKindOf({ id: 1, error: { code: -1 } })).toBe('rpc:error');
  });

  test('manages .pending.json acceptance, discard, and diffs', () => {
    const committed = join(dir, 'api.user.json');
    const pending = join(dir, 'api.user.pending.json');

    writeFileSync(committed, JSON.stringify({ status: 200, body: { id: 1 } }));
    writeFileSync(pending, JSON.stringify({ status: 200, body: { id: '1', role: 'admin' } }));

    expect(fetchCassettePaths(dir, { includePending: false })).toEqual([committed]);
    expect(fetchPendingCassettes(dir)).toEqual([pending]);
    expect(diffCassetteDrift(committed, pending)).toEqual([
      'body added id:string, role:string',
      'body removed id:number',
    ]);

    const notices = diffVolatileCassetteNotices(
      JSON.stringify({ status: 0, body: { kind: 'process', frames: [], exit: { code: 0 } } }),
      JSON.stringify({
        status: 0,
        body: { kind: 'process', frames: [{ stream: 'stderr', data: 'warn' }], exit: { code: 0 } },
      }),
    );
    expect(notices).toEqual(['new stderr']);

    const accepted = acceptPendingCassettes(dir);
    expect(accepted).toHaveLength(1);
    expect(existsSync(pending)).toBe(false);
    expect(JSON.parse(readFileSync(committed, 'utf8')).body).toEqual({ id: '1', role: 'admin' });

    writeFileSync(pending, JSON.stringify({ status: 200, body: { discarded: true } }));
    expect(discardPendingCassettes(dir)).toEqual([pending]);
    expect(existsSync(pending)).toBe(false);
  });

  test('resolves CLI versions, HTTP versions (header, extract, sha256), and compares semvers', async () => {
    expect(compareVersions('2.1.10', '2.1.2')).toBe(1);
    expect(compareVersions('1.0', '1.0.0')).toBe(0);
    expect(compareVersions('0.9.9', '1.0.0')).toBe(-1);

    const bunVersion = await fetchCliVersion(process.execPath);
    expect(bunVersion).toMatch(/^\d+\.\d+\.\d+/);

    const installed = await fetchInstalledVersions([
      process.execPath,
      'definitely-missing-cli-xyz',
    ]);
    expect(installed[process.execPath]).toBe(bunVersion);
    expect(installed['definitely-missing-cli-xyz']).toBeUndefined();

    const server = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      fetch() {
        return new Response('openapi: 3.1.0\ninfo:\n  version: 2.0.0\n', {
          headers: { etag: '"v2-etag"', 'x-api-version': '2026-11-01' },
        });
      },
    });
    try {
      const baseUrl = `http://127.0.0.1:${server.port}/spec`;
      expect(await fetchHttpVersion(baseUrl, { header: 'etag' })).toBe('v2-etag');
      expect(
        await fetchHttpVersion(baseUrl, {
          extract: async (res) => (await res.text()).match(/version: (\S+)/)?.[1] ?? '',
        }),
      ).toBe('2.0.0');
      const digest = await fetchHttpVersion(baseUrl);
      expect(digest).toMatch(/^[0-9a-f]{12}$/);
    } finally {
      server.stop(true);
    }
  });

  test('validates cassettes, checks freshness policy, blesses versions, and throws stale_cassette on assertion', () => {
    expect(
      validateCassette({
        status: 'bad',
        headers: [],
        recorded: { recordedAt: 'nope', service: '' },
      }),
    ).toEqual({
      ok: false,
      errors: [
        'missing or non-numeric "status" field',
        '"headers" must be an object when present',
        '"recorded.recordedAt" must be a valid ISO timestamp',
        '"recorded.service" must be a non-empty string',
      ],
    });

    const now = Date.parse('2026-11-21T00:00:00Z');
    writeFreshnessPolicy(dir, {
      maxAgeDays: 14,
      blessed: { mycli: '2.0.0', '@scope/sdk': '1.2.0' },
    });
    expect(fetchFreshnessPolicy(dir).maxAgeDays).toBe(14);

    const writeFixture = (
      name: string,
      recordedAt: string,
      version: string,
      sdkVersion = '1.2.0',
      extra: Record<string, unknown> = {},
    ) => {
      writeFileSync(
        join(dir, name),
        JSON.stringify({
          version,
          status: 200,
          body: { ok: true },
          recorded: {
            service: 'mycli',
            transport: 'process',
            cli: 'mycli',
            recordedAt,
            environment: 'terminal',
            metadata: { '@scope/sdk': sdkVersion },
          },
          ...extra,
        }),
      );
    };

    writeFixture('fresh.json', '2026-11-18T00:00:00Z', '2.1.0', '1.3.0');
    writeFixture('old.json', '2026-10-01T00:00:00Z', '2.1.0');
    writeFixture('under-blessed.json', '2026-11-18T00:00:00Z', '1.9.0');
    writeFixture('old-sdk.json', '2026-11-18T00:00:00Z', '2.1.0', '1.1.0');
    writeFixture('leaking.json', '2026-11-18T00:00:00Z', '2.1.0', '1.2.0', {
      body: { path: '/Users/alice/secret' },
    });
    writeFixture('drifted.pending.json', '2026-11-18T00:00:00Z', '2.1.0');

    const findings = checkCassetteFreshness(dir, {
      now,
      installed: { mycli: '2.2.0' },
      packageVersions: { '@scope/sdk': '1.3.0' },
    });

    const codesFor = (name: string) =>
      findings.filter((f) => f.cassette === name).map((f) => f.code);
    expect(codesFor('old.json')).toContain('expired_cassette');
    expect(codesFor('under-blessed.json')).toContain('below_blessed_version');
    expect(codesFor('old-sdk.json')).toContain('below_blessed_version');
    expect(codesFor('old-sdk.json')).toContain('below_installed_version');
    expect(codesFor('fresh.json')).toEqual(['below_installed_version']);
    expect(codesFor('leaking.json')).toContain('unscrubbed_secret');
    expect(codesFor('drifted.pending.json')).toEqual(['pending_drift']);

    expect(() => assertCassettesFresh(dir, { now })).toThrow('cassette freshness check failed');

    // Verify blessFreshnessPolicy raises versions from committed cassettes.
    const blessed = blessFreshnessPolicy(dir, { metadataVersions: { '@scope/sdk': '1.4.0' } });
    expect(blessed.blessed.mycli).toBe('2.1.0');
    expect(blessed.blessed['@scope/sdk']).toBe('1.4.0');
  });
});
