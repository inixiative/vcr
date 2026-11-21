import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createVcrRecorder, createVcrSession, isVcrError } from '../src/core/index';
import {
  acceptPendingCassettes,
  compareSignatures,
  compareVersions,
  discardPendingCassettes,
  fetchCassettePaths,
  fetchCliVersion,
  fetchFreshnessPolicy,
  signatureOfCassette,
} from '../src/freshness/index';
import { createHttpTransport, createVcrFetch } from '../src/http/index';
import { createVcrProcessSpawner } from '../src/process/index';
import {
  assertScrubbed,
  createScrubber,
  findUnscrubbedSecrets,
  rehydratePlaceholders,
  scrubHeaders,
  scrubText,
  scrubUrl,
  scrubValue,
} from '../src/scrub/index';
import { createVcrWebSocketFactory } from '../src/websocket/index';

let dir: string;
let outsideDir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vcr-reg-'));
  outsideDir = mkdtempSync(join(tmpdir(), 'vcr-outside-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  rmSync(outsideDir, { recursive: true, force: true });
});

describe('HIGH regressions (H1–H13)', () => {
  test('H1: rejects path traversal in method, cassetteName, bodyFile, and binaryExtension', async () => {
    const recorder = createVcrRecorder(dir, {
      service: 'sec',
      version: '1.0.0',
      mode: 'record',
      session: createVcrSession(),
    });

    expect(() => recorder.queue('../escape', 'ok')).toThrow('invalid method');
    expect(() => recorder.queue('ok', '../escape')).toThrow('invalid cassetteName');
    expect(() => recorder.queue('a/b', 'ok')).toThrow('invalid method');
    expect(() => recorder.queue('ok', 'a\\b')).toThrow('invalid cassetteName');

    // Malicious bodyFile traversal on replay
    writeFileSync(join(outsideDir, 'secret.txt'), 'TOP_SECRET');
    writeFileSync(
      join(dir, 'read.evil.json'),
      JSON.stringify({ version: '1', status: 200, bodyFile: '../secret.txt' }),
    );
    const replayer = createVcrRecorder(dir, {
      service: 'sec',
      version: '1.0.0',
      mode: 'replay',
      session: createVcrSession(),
    }).queue('read', 'evil');
    await expect(replayer.capture('read', async () => 'x')).rejects.toMatchObject({
      code: 'invalid_cassette',
    });

    // Malicious binaryExtension
    const badExt = createVcrRecorder(dir, {
      service: 'sec',
      version: '1.0.0',
      mode: 'record',
      session: createVcrSession(),
      sanitizers: { bin: { binaryExtension: '/../../evil.bin' } },
    }).queue('bin', 'x');
    await expect(
      badExt.capture('bin', async () => new Uint8Array([1, 2, 3])),
    ).rejects.toMatchObject({
      code: 'invalid_cassette',
    });
  });

  test('H2 + L3: fetchCliVersion uses execFile (no shell injection), respects timeoutMs, and supports non-capturing regex', async () => {
    const marker = join(dir, 'injected.txt');
    await expect(
      fetchCliVersion(`${process.execPath} --version; touch ${marker}`),
    ).rejects.toMatchObject({ code: 'version_resolution_failed' });
    expect(existsSync(marker)).toBe(false);

    // Non-capturing regex (L3)
    const noGroup = await fetchCliVersion(process.execPath, {
      args: ['--version'],
      regex: /\d+\.\d+\.\d+/,
    });
    expect(noGroup).toMatch(/^\d+\.\d+\.\d+$/);

    // Timeout enforcement
    await expect(
      fetchCliVersion(process.execPath, {
        args: ['-e', 'await Bun.sleep(5000)'],
        timeoutMs: 100,
      }),
    ).rejects.toMatchObject({ code: 'version_resolution_failed' });
  });

  test('H3: waitUntilSettled rethrows background write failures instead of swallowing them', async () => {
    const recorder = createVcrRecorder(dir, {
      service: 'bg',
      version: '1.0.0',
      mode: 'record',
      session: createVcrSession(),
    });

    const failing = Promise.reject(new Error('disk full'));
    recorder.trackPendingWrite(failing);
    // Attach no-op handler to local reference so Bun does not treat it as unhandled before waitUntilSettled
    failing.catch(() => {});

    await expect(recorder.waitUntilSettled()).rejects.toThrow('disk full');
    // Subsequent waitUntilSettled clears previous errors
    await expect(recorder.waitUntilSettled()).resolves.toBeUndefined();
  });

  test('H4: capture/captureResponse do not catch storeCassette drift_detected or unscrubbed_secret and overwrite with status 500', async () => {
    const session = createVcrSession();
    const base = createVcrRecorder(dir, {
      service: 'svc',
      version: '1.0.0',
      mode: 'record',
      session,
    }).queue('call', 'x');
    await base.capture('call', async () => ({ count: 1 }));

    const strict = createVcrRecorder(dir, {
      service: 'svc',
      version: '1.0.0',
      mode: 'record',
      session,
      throwOnDrift: true,
    }).queue('call', 'x');
    await expect(strict.capture('call', async () => ({ count: 'drifted' }))).rejects.toMatchObject({
      code: 'drift_detected',
    });

    // Pending cassette must retain status 200 and drifted body, NOT status 500!
    const pending = JSON.parse(readFileSync(join(dir, 'call.x.pending.json'), 'utf8')) as {
      status: number;
      body: unknown;
    };
    expect(pending.status).toBe(200);
    expect(pending.body).toEqual({ count: 'drifted' });
  });

  test('H5: pending binary sidecars are isolated on drift and promoted/discarded cleanly', async () => {
    const png1 = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x01]);
    const png2 = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x02]);
    const session = createVcrSession();

    const base = createVcrRecorder(dir, {
      service: 'bin',
      version: '1.0.0',
      mode: 'record',
      session,
      sanitizers: { img: { binaryExtension: '.png' } },
    })
      .queue('img', 'logo')
      .queue('meta', 'info');
    await base.capture('img', async () => png1);
    await base.capture('meta', async () => ({ v: 1 }));

    // Next run: img matches shape (writes png2), THEN meta drifts -> img's binary sidecar must revert to png1 and move png2 to img.logo.pending.png!
    const next = createVcrRecorder(dir, {
      service: 'bin',
      version: '1.0.0',
      mode: 'record',
      session,
      sanitizers: { img: { binaryExtension: '.png' } },
    })
      .queue('img', 'logo')
      .queue('meta', 'info');
    await next.capture('img', async () => png2);
    await next.capture('meta', async () => ({ v: 'drifted' }));

    expect(Buffer.from(readFileSync(join(dir, 'img.logo.png'))).equals(Buffer.from(png1))).toBe(
      true,
    );
    expect(
      Buffer.from(readFileSync(join(dir, 'img.logo.pending.png'))).equals(Buffer.from(png2)),
    ).toBe(true);
    expect(JSON.parse(readFileSync(join(dir, 'img.logo.pending.json'), 'utf8')).bodyFile).toBe(
      'img.logo.pending.png',
    );

    // Accept promotes both JSON and pending binary sidecar!
    acceptPendingCassettes(dir);
    expect(existsSync(join(dir, 'img.logo.pending.png'))).toBe(false);
    expect(Buffer.from(readFileSync(join(dir, 'img.logo.png'))).equals(Buffer.from(png2))).toBe(
      true,
    );
    expect(JSON.parse(readFileSync(join(dir, 'img.logo.json'), 'utf8')).bodyFile).toBe(
      'img.logo.png',
    );

    // Discard removes pending sidecars too
    writeFileSync(join(dir, 'x.pending.png'), png1);
    writeFileSync(
      join(dir, 'x.pending.json'),
      JSON.stringify({ status: 200, bodyFile: 'x.pending.png' }),
    );
    discardPendingCassettes(dir);
    expect(existsSync(join(dir, 'x.pending.png'))).toBe(false);
  });

  test("H6: literal replacement values containing $&, $$, or $' are never corrupted", () => {
    const cwd = '/tmp/dir-$&-$$-test';
    expect(rehydratePlaceholders('path={{cwd}}/a', { cwd })).toBe(`path=${cwd}/a`);
    const scrubber = createScrubber({
      knownSecrets: ['my-secret-value'],
      placeholderFor: () => '$&-$$-SAFE',
    });
    expect(scrubber.scrubText('x=my-secret-value')).toBe('x=$&-$$-SAFE');
  });

  test('H7: url_basic_auth never eats across JSON fields into a later email address', () => {
    const json = '{"url":"https://api.example.com:8443/v1","email":"user@company.com"}';
    const scrubbed = scrubText(json);
    expect(scrubbed).toBe(
      '{"url":"https://api.example.com:8443/v1","email":"redacted@example.invalid"}',
    );
    expect(() => JSON.parse(scrubbed)).not.toThrow();
  });

  test('H8 + L6: scrubValue and findUnscrubbedSecrets inspect Error, URL, Uint8Array, and object/Map keys without echoing raw secrets', () => {
    const rawKey = 'sk-ant-api03-RAWKEYINMAP123456';
    const causeErr = new Error(`inner ${rawKey}`);
    const err = new Error('outer', { cause: causeErr });
    const url = new URL('https://api.example.com/v1?api_key=leakedQuery123');
    const bytes = new TextEncoder().encode(`binary buffer with ${rawKey}`);
    const map = new Map<string, string>([[rawKey, 'val']]);
    const obj: Record<string, string> = { [rawKey]: 'val' };

    expect(findUnscrubbedSecrets(err).length).toBeGreaterThan(0);
    expect(findUnscrubbedSecrets(url).length).toBeGreaterThan(0);
    expect(findUnscrubbedSecrets(bytes).length).toBeGreaterThan(0);
    expect(findUnscrubbedSecrets(map).length).toBeGreaterThan(0);
    expect(findUnscrubbedSecrets(obj).length).toBeGreaterThan(0);

    // L6: assertScrubbed error message must NOT echo raw secret key!
    let caught: unknown;
    try {
      assertScrubbed(obj, { label: 'key-leak.json' });
    } catch (e) {
      caught = e;
    }
    expect(isVcrError(caught, 'unscrubbed_secret')).toBe(true);
    expect((caught as Error).message).not.toContain(rawKey);
    expect((caught as Error).message).toContain('<secret-key>');

    // scrubValue scrubs Error cause + stack + own props
    const scrubbedErr: unknown = scrubValue(err);
    expect(findUnscrubbedSecrets(scrubbedErr)).toEqual([]);
  });

  test('H9 + L5: scrubs URL fragments, bare/lowercase inline secrets, PGP keys, stateful user regexes, and single-pass knownSecrets', () => {
    expect(scrubUrl('https://app.example.com/cb#access_token=oauth12345&state=ok')).toBe(
      'https://app.example.com/cb#access_token=<REDACTED:QUERY_SECRET>&state=ok',
    );
    expect(scrubText('PASSWORD=supersecret123 password="anothersecret123"')).toBe(
      'PASSWORD=<REDACTED:SECRET> password="<REDACTED:SECRET>"',
    );
    const pgp =
      '-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc123\n-----END PGP PRIVATE KEY BLOCK-----';
    expect(scrubText(pgp)).toBe('<REDACTED:PRIVATE_KEY>');
    expect(scrubValue({ apiSecret: 'a', webhookSecret: 'b', oauthToken: 'c' })).toEqual({
      apiSecret: '<REDACTED:SECRET>',
      webhookSecret: '<REDACTED:SECRET>',
      oauthToken: '<REDACTED:SECRET>',
    });

    // Stateful /g user regex must not flake on alternating calls
    const stateful = createScrubber({ extraSecretKeyPatterns: [/^custom_tok$/g] });
    expect(stateful.scrubValue({ custom_tok: 'v1' })).toEqual({ custom_tok: '<REDACTED:SECRET>' });
    expect(stateful.scrubValue({ custom_tok: 'v2' })).toEqual({ custom_tok: '<REDACTED:SECRET>' });

    // Single-pass knownSecrets with minKnownSecretLength guard + custom placeholderFor + assertScrubbed
    const custom = createScrubber({
      knownSecrets: ['a', 'REDACTED', 'long-secret-xyz'],
      placeholderFor: (kind) => `<MASK:${kind}>`,
    });
    const out = custom.scrubText('a long-secret-xyz PASSWORD=mysecret123 ?token=tok99999');
    expect(out).toBe('a <MASK:secret> PASSWORD=<MASK:secret> ?token=<MASK:query_secret>');
    expect(() => custom.assertScrubbed(out)).not.toThrow();
  });

  test('H10: EMAIL_PATTERN and INLINE_ENV_SECRET_PATTERN execute in < 25ms on 20KB adversarial inputs (no ReDoS)', () => {
    const bigEmailInput = `${'a'.repeat(20_000)}!`;
    const bigEnvInput = `${'A_'.repeat(10_000)}!`;
    const start = performance.now();
    expect(scrubText(bigEmailInput)).toBe(bigEmailInput);
    expect(scrubText(bigEnvInput)).toBe(bigEnvInput);
    expect(performance.now() - start).toBeLessThan(25);
  });

  test('H11: HTTP transport preserves binary response bytes via sidecar on record and replay', async () => {
    const rawPng = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe]);
    const server = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      fetch() {
        return new Response(rawPng, { status: 200, headers: { 'content-type': 'image/png' } });
      },
    });
    try {
      const session = createVcrSession();
      const rec = createVcrRecorder(dir, {
        service: 'img',
        version: '1.0.0',
        mode: 'record',
        session,
      }).queue('get', 'icon');
      const liveRes = await createVcrFetch(rec, 'get')(`http://127.0.0.1:${server.port}/icon.png`);
      expect(Buffer.from(await liveRes.arrayBuffer()).equals(Buffer.from(rawPng))).toBe(true);
      expect(existsSync(join(dir, 'get.icon.png'))).toBe(true);

      const rep = createVcrRecorder(dir, {
        service: 'img',
        version: '1.0.0',
        mode: 'replay',
        session,
      }).queue('get', 'icon');
      const replayRes = await createVcrFetch(rep, 'get')('http://unused.invalid/icon.png');
      expect(Buffer.from(await replayRes.arrayBuffer()).equals(Buffer.from(rawPng))).toBe(true);
    } finally {
      server.stop(true);
    }
  });

  test('H12: Process stdin handles chunked UTF-8 writes and multi-line single writes identically', async () => {
    const script = `for await (const c of Bun.stdin.stream()) {
      for (const line of new TextDecoder().decode(c).split("\\n").filter(Boolean)) {
        const m = JSON.parse(line);
        console.log(JSON.stringify({ id: m.id, echo: m.text }));
      }
    }`;
    const session = createVcrSession();
    const rec = createVcrRecorder(dir, {
      service: 'utf8',
      version: '1.0.0',
      mode: 'record',
      session,
    }).queue('p', 'chunked');

    const child = createVcrProcessSpawner(rec, 'p').spawn([process.execPath, '-e', script], {
      cwd: dir,
      env: { PATH: process.env.PATH },
    });
    const outPromise = new Response(child.stdout).text();
    const twoLines = new TextEncoder().encode(
      '{"id":1,"method":"echo","text":"héllo 🌍"}\n{"id":2,"method":"echo","text":"wörld"}\n',
    );
    // Split mid-UTF-8 multibyte character across chunks!
    child.stdin.write(twoLines.slice(0, 34));
    child.stdin.write(twoLines.slice(34));
    child.stdin.end();
    await child.exited;
    const liveLines = (await outPromise)
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l));
    await rec.waitUntilSettled();

    // Replay writing both lines in one call with different JSON-RPC IDs
    const rep = createVcrRecorder(dir, {
      service: 'utf8',
      version: '1.0.0',
      mode: 'replay',
      session,
    }).queue('p', 'chunked');
    const replayChild = createVcrProcessSpawner(rep, 'p').spawn(['x'], { cwd: dir, env: {} });
    const replayOut = new Response(replayChild.stdout).text();
    replayChild.stdin.write(
      '{"id":10,"method":"echo","text":"héllo 🌍"}\n{"id":11,"method":"echo","text":"wörld"}\n',
    );
    replayChild.stdin.end();
    await replayChild.exited;
    const replayedLines = (await replayOut)
      .trim()
      .split('\n')
      .map((l) => JSON.parse(l));
    expect(replayedLines).toEqual([
      { id: 10, echo: liveLines[0].echo },
      { id: 11, echo: liveLines[1].echo },
    ]);
  });

  test('H13: WebSocket supports binary frames, RFC 6455 close validation, and replay path mismatch', async () => {
    const serverBytes = new Uint8Array([1, 2, 3, 4]);
    const clientBytes = new Uint8Array([9, 8, 7]);
    const server = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      fetch(req, srv) {
        return srv.upgrade(req) ? undefined : new Response('no', { status: 426 });
      },
      websocket: {
        message(ws, data) {
          if (data instanceof Uint8Array) ws.send(serverBytes);
        },
      },
    });
    try {
      const session = createVcrSession();
      const rec = createVcrRecorder(dir, {
        service: 'wsbin',
        version: '1.0.0',
        mode: 'record',
        session,
      }).queue('ws', 'bin');

      const wsLive = createVcrWebSocketFactory(rec, 'ws')(`ws://127.0.0.1:${server.port}/bin`);
      const liveReceived = await new Promise<ArrayBuffer>((resolve) => {
        wsLive.onopen = () => wsLive.send(clientBytes);
        wsLive.onmessage = (ev) => {
          resolve(ev.data as ArrayBuffer);
          wsLive.close(1000, 'ok');
        };
      });
      expect(Buffer.from(new Uint8Array(liveReceived)).equals(Buffer.from(serverBytes))).toBe(true);
      await Bun.sleep(40);
      await rec.waitUntilSettled();

      // Replay checks path mismatch
      const rep = createVcrRecorder(dir, {
        service: 'wsbin',
        version: '1.0.0',
        mode: 'replay',
        session,
      }).queueMany('ws', ['bin', 'bin']);
      const wsFactory = createVcrWebSocketFactory(rep, 'ws');
      expect(() => wsFactory('ws://unused.invalid/wrong-path')).toThrow('was recorded as "/bin"');

      // Replay returns exact binary ArrayBuffer and validates close codes
      const wsReplay = wsFactory('ws://unused.invalid/bin');
      const replayedBytes = await new Promise<ArrayBuffer>((resolve) => {
        wsReplay.onopen = () => wsReplay.send(clientBytes);
        wsReplay.onmessage = (ev) => {
          resolve(ev.data as ArrayBuffer);
        };
      });
      expect(Buffer.from(new Uint8Array(replayedBytes)).equals(Buffer.from(serverBytes))).toBe(
        true,
      );
      expect(() => wsReplay.close(1006)).toThrow('Invalid WebSocket close code');
      wsReplay.close(1000, 'clean');
    } finally {
      server.stop(true);
    }
  });
});

describe('MEDIUM & LOW regressions (M1–M8, L1–L4)', () => {
  test('M1 + M8: signatureOfCassette ignores undefined properties and strips stateful regex flags', () => {
    const a = signatureOfCassette(200, { ok: true, extra: undefined });
    const b = signatureOfCassette(200, { ok: true });
    expect(compareSignatures(a, b, { volatileKinds: [/^stderr$/g] })).toEqual([]);
  });

  test('M2: compareVersions handles SemVer 2.0.0 pre-releases, ISO dates, and opaque digests', () => {
    expect(compareVersions('1.0.0-alpha.1', '1.0.0-alpha.2')).toBe(-1);
    expect(compareVersions('1.0.0-alpha.1', '1.0.0-beta.1')).toBe(-1);
    expect(compareVersions('1.0.0-beta.1', '1.0.0')).toBe(-1);
    expect(compareVersions('2026-11-20', '2026-11-21')).toBe(-1);
    expect(compareVersions('abcdef123456', 'fedcba654321')).toBe(-1);
  });

  test('M3 + L4: scrubUrl handles malformed %, protocol-relative URLs, username-only creds, and scrubHeaders joins duplicates', () => {
    const s = createScrubber({ knownSecrets: ['mySecretToken'] });
    expect(s.scrubUrl('https://mySecretToken@github.com/org/repo')).toBe(
      'https://<REDACTED:URL_CREDENTIAL>@github.com/org/repo',
    );
    expect(s.scrubUrl('//cdn.example.com/a?token=abc&x=mySecretToken')).toBe(
      '//cdn.example.com/a?token=<REDACTED:QUERY_SECRET>&x=<REDACTED:SECRET>',
    );
    expect(s.scrubUrl('https://example.com/%ZZ?token=abc')).toContain('<REDACTED:QUERY_SECRET>');
    expect(
      scrubHeaders([
        ['X-Custom', 'one'],
        ['x-custom', 'two'],
      ]),
    ).toEqual({ 'x-custom': 'one, two' });
  });

  test('M4: fetchCassettePaths rejects escaping symlinks and acceptPendingCassettes is atomic across invalid files', () => {
    writeFileSync(join(outsideDir, 'escape.json'), '{}');
    symlinkSync(join(outsideDir, 'escape.json'), join(dir, 'link.json'));
    expect(() => fetchCassettePaths(dir)).toThrow('escapes root directory');
    rmSync(join(dir, 'link.json'));

    writeFileSync(join(dir, 'a.json'), JSON.stringify({ status: 200, body: { a: 1 } }));
    writeFileSync(join(dir, 'a.pending.json'), JSON.stringify({ status: 200, body: { a: 'new' } }));
    writeFileSync(join(dir, 'b.pending.json'), '{broken-json');

    expect(() => acceptPendingCassettes(dir)).toThrow('invalid JSON');
    // Pass 1 failed on b.pending.json, so a.json MUST remain untouched!
    expect(JSON.parse(readFileSync(join(dir, 'a.json'), 'utf8')).body).toEqual({ a: 1 });
    expect(existsSync(join(dir, 'a.pending.json'))).toBe(true);
  });

  test('M5: HTTP replay honors aborted AbortSignal, canonical JSON matchBody, and ArrayBuffer request bodies', async () => {
    const session = createVcrSession();
    const rec = createVcrRecorder(dir, {
      service: 'http-m5',
      version: '1.0.0',
      mode: 'record',
      session,
    }).queue('post', 'canon');

    const fakeFetch = (async () => Response.json({ ok: true })) as unknown as typeof fetch;
    await createVcrFetch(rec, 'post', { fetchImpl: fakeFetch, matchBody: true })(
      'https://api.example.com/items',
      {
        method: 'POST',
        body: new TextEncoder().encode('{"b":2,"a":1}'),
      },
    );

    const rep = createVcrRecorder(dir, {
      service: 'http-m5',
      version: '1.0.0',
      mode: 'replay',
      session,
    }).queueMany('post', ['canon', 'canon']);
    const replayFetch = createVcrFetch(rep, 'post', { matchBody: true });

    // Reordered JSON keys match canonically!
    const okRes = await replayFetch('https://unused.invalid/items', {
      method: 'POST',
      body: '{"a":1,"b":2}',
    });
    expect(okRes.status).toBe(200);

    // Aborted signal rejects immediately!
    const ac = new AbortController();
    ac.abort(new Error('cancelled'));
    await expect(
      replayFetch('https://unused.invalid/items', { method: 'POST', signal: ac.signal }),
    ).rejects.toThrow('cancelled');

    // createHttpTransport scrubs ArrayBuffer bodies too
    const transport = createHttpTransport();
    const scrubbed = transport.scrubRequest(
      {
        url: 'https://api.example.com/x',
        init: { method: 'POST', body: new TextEncoder().encode('{"token":"secret123"}') },
      },
      createScrubber(),
    );
    expect(scrubbed.init?.body).toBe('{"token":"<REDACTED:SECRET>"}');
  });

  test('M6: concurrent recordOnce process probes share one live execution', async () => {
    const script = join(dir, 'slow-probe.ts');
    writeFileSync(
      script,
      'await Bun.sleep(60); console.log(JSON.stringify({ id: Math.random() }));',
    );
    const session = createVcrSession();
    const rec = createVcrRecorder(dir, {
      service: 'once',
      version: '1.0.0',
      mode: 'record',
      session,
    }).queueMany('probe', ['shared', 'shared']);
    const spawner = createVcrProcessSpawner(rec, 'probe', {
      argv: [process.execPath, script],
      recordOnce: true,
    });

    const p1 = spawner.spawnProbe();
    const p2 = spawner.spawnProbe();
    const [out1, out2] = await Promise.all([
      new Response(p1.stdout).text(),
      new Response(p2.stdout).text(),
    ]);
    await rec.waitUntilSettled();
    expect(session.liveCalls).toBe(1);
    expect(JSON.parse(out1).id).toBe(JSON.parse(out2).id);
  });

  test('M7 + L1 + L2: VCR_OUT scopes by service subdir, session.maxLiveCalls is mutable, and policy validates finite maxAgeDays', async () => {
    const prevOut = process.env.VCR_OUT;
    process.env.VCR_OUT = outsideDir;
    try {
      const s = createVcrSession({ maxLiveCalls: 1 });
      s.maxLiveCalls = 2; // L1: mutating maxLiveCalls takes effect!
      const recA = createVcrRecorder(dir, {
        service: 'svc-a',
        version: '1',
        mode: 'record',
        session: s,
      }).queue('m', '1');
      const recB = createVcrRecorder(dir, {
        service: 'svc-b',
        version: '1',
        mode: 'record',
        session: s,
      }).queue('m', '1');
      await recA.capture('m', async () => ({ from: 'a' }));
      await recB.capture('m', async () => ({ from: 'b' }));
      expect(existsSync(join(outsideDir, 'svc-a', 'm.1.json'))).toBe(true);
      expect(existsSync(join(outsideDir, 'svc-b', 'm.1.json'))).toBe(true);
    } finally {
      if (prevOut === undefined) delete process.env.VCR_OUT;
      else process.env.VCR_OUT = prevOut;
    }

    // L2: reject negative maxAgeDays and array blessed
    writeFileSync(join(dir, 'policy.json'), JSON.stringify({ maxAgeDays: -5, blessed: {} }));
    expect(() => fetchFreshnessPolicy(dir)).toThrow('finite non-negative');
    writeFileSync(join(dir, 'policy.json'), JSON.stringify({ maxAgeDays: 7, blessed: [] }));
    expect(() => fetchFreshnessPolicy(dir)).toThrow('plain object');
  });
});
