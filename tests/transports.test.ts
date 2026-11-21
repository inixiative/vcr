import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createVcrRecorder, createVcrSession } from '../src/core/index';
import { createHttpTransport, createVcrFetch } from '../src/http/index';
import {
  createVcrProcessSpawner,
  type ProcessLineProtocol,
  type ProcessTranscript,
} from '../src/process/index';
import { accountHomeDirectory } from '../src/scrub/index';
import { createVcrWebSocketFactory } from '../src/websocket/index';

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vcr-transports-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('HTTP transport (live 127.0.0.1:0 loopback)', () => {
  test('records and replays HTTP requests, scrubs auth headers & query secrets, handles 204, and enforces mismatch', async () => {
    const server = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      async fetch(request) {
        const url = new URL(request.url);
        if (url.pathname === '/empty') {
          return new Response(null, { status: 204 });
        }
        return Response.json(
          {
            sawAuth: Boolean(request.headers.get('authorization')),
            queryPage: url.searchParams.get('page'),
            body: await request.json(),
          },
          { status: 201 },
        );
      },
    });

    try {
      const session = createVcrSession();
      const recorder = createVcrRecorder(dir, {
        service: 'loopback-api',
        version: '1.0.0',
        mode: 'record',
        session,
      }).queueMany('api', ['create', 'empty']);

      const vcrFetch = createVcrFetch(recorder, 'api', { matchBody: true });

      const live = await vcrFetch(
        `http://127.0.0.1:${server.port}/v1/items?api_key=raw-secret-999&page=2`,
        {
          method: 'POST',
          headers: {
            Authorization: 'Bearer kingdom_run_abcdefghijklmnopqrstuvwxyz0123456789ABC',
            'X-Api-Key': 'sk-ant-api03-1234567890abcdef',
          },
          body: JSON.stringify({ name: 'widget', email: 'buyer@acme.com' }),
        },
      );
      expect(live.status).toBe(201);
      const liveJson = await live.json();

      const emptyRes = await vcrFetch(`http://127.0.0.1:${server.port}/empty`, {
        method: 'DELETE',
      });
      expect(emptyRes.status).toBe(204);

      const diskText = readFileSync(join(dir, 'api.create.json'), 'utf8');
      expect(diskText).not.toContain('raw-secret-999');
      expect(diskText).not.toContain('kingdom_run_');
      expect(diskText).not.toContain('sk-ant-api03');
      expect(diskText).not.toContain('buyer@acme.com');

      // Replay with different query param order and different secret values still matches canonically!
      const replayer = createVcrRecorder(dir, {
        service: 'loopback-api',
        version: '1.0.0',
        mode: 'replay',
        session,
      }).queueMany('api', ['create', 'empty', 'create']);
      const replayFetch = createVcrFetch(replayer, 'api', { matchBody: true });

      const replayed = await replayFetch(
        'http://unused.invalid/v1/items?page=2&api_key=another-secret',
        {
          method: 'POST',
          body: JSON.stringify({ name: 'widget', email: 'other@example.org' }),
        },
      );
      expect(replayed.status).toBe(201);
      expect(liveJson).toEqual({
        sawAuth: true,
        queryPage: '2',
        body: { name: 'widget', email: 'buyer@acme.com' },
      });
      expect(await replayed.json()).toEqual({
        sawAuth: true,
        queryPage: '2',
        body: { name: 'widget', email: 'redacted@example.invalid' },
      });

      const replayedEmpty = await replayFetch('http://unused.invalid/empty', { method: 'DELETE' });
      expect(replayedEmpty.status).toBe(204);

      await expect(
        replayFetch('http://unused.invalid/v1/other', { method: 'POST', body: '{}' }),
      ).rejects.toMatchObject({ code: 'request_mismatch' });

      // Also verify generic createHttpTransport through recorder.execute
      const transport = createHttpTransport();
      const execRecorder = createVcrRecorder(dir, {
        service: 'loopback-api',
        version: '1.0.0',
        mode: 'auto',
        session,
      }).queue('exec', 'delete');
      const execLive = await execRecorder.execute('exec', transport, {
        url: `http://127.0.0.1:${server.port}/empty`,
        init: { method: 'DELETE' },
      });
      expect(execLive.status).toBe(204);
      const execReplay = await execRecorder.queue('exec', 'delete').execute('exec', transport, {
        url: 'http://unused.invalid/empty',
        init: { method: 'DELETE' },
      });
      expect(execReplay.status).toBe(204);
    } finally {
      server.stop(true);
    }
  });
});

describe('WebSocket transport (live 127.0.0.1:0 loopback)', () => {
  test('records and replays frames in causal order, scrubs secrets, and rejects mismatched sends', async () => {
    const server = Bun.serve({
      hostname: '127.0.0.1',
      port: 0,
      fetch(request, srv) {
        return srv.upgrade(request) ? undefined : new Response('upgrade required', { status: 426 });
      },
      websocket: {
        open(ws) {
          ws.send(JSON.stringify({ type: 'welcome', email: 'server@internal.org' }));
        },
        message(ws, raw) {
          const msg = JSON.parse(String(raw)) as { action?: string };
          if (msg.action === 'ping') {
            ws.send(JSON.stringify({ type: 'pong', ok: true }));
          }
        },
      },
    });

    const runSession = async (socket: ReturnType<ReturnType<typeof createVcrWebSocketFactory>>) => {
      const received: Array<{ type: string }> = [];
      await new Promise<void>((resolve) => {
        socket.onmessage = (event) => {
          const frame = JSON.parse(String(event.data)) as { type: string };
          received.push(frame);
          if (received.length === 1) {
            socket.send(JSON.stringify({ action: 'ping', token: 'Bearer live-secret-12345678' }));
          } else {
            socket.close(1000, 'done');
            resolve();
          }
        };
      });
      return received;
    };

    try {
      const session = createVcrSession();
      const recorder = createVcrRecorder(dir, {
        service: 'ws-svc',
        version: '1.0.0',
        mode: 'record',
        session,
      }).queue('ws', 'handshake');

      const liveReceived = await runSession(
        createVcrWebSocketFactory(
          recorder,
          'ws',
        )(`ws://127.0.0.1:${server.port}/stream?token=ws-secret-999`),
      );
      await Bun.sleep(40);
      await recorder.waitUntilSettled();
      expect(liveReceived.map((m) => m.type)).toEqual(['welcome', 'pong']);

      const diskText = readFileSync(join(dir, 'ws.handshake.json'), 'utf8');
      expect(diskText).not.toContain('ws-secret-999');
      expect(diskText).not.toContain('live-secret-12345678');
      expect(diskText).not.toContain('server@internal.org');

      const replayer = createVcrRecorder(dir, {
        service: 'ws-svc',
        version: '1.0.0',
        mode: 'replay',
        session,
      }).queueMany('ws', ['handshake', 'handshake']);
      const wsFactory = createVcrWebSocketFactory(replayer, 'ws');

      const replayedReceived = await runSession(
        wsFactory('ws://unused.invalid/stream?token=replay'),
      );
      expect(replayedReceived.map((m) => m.type)).toEqual(['welcome', 'pong']);

      // Sending a different message fails with VcrError('request_mismatch').
      const mismatchSocket = wsFactory('ws://unused.invalid/stream?token=replay');
      await new Promise<void>((resolve) => {
        mismatchSocket.onopen = () => resolve();
      });
      expect(() => mismatchSocket.send(JSON.stringify({ action: 'wrong' }))).toThrow(
        'differs from the recording',
      );
    } finally {
      server.stop(true);
    }
  });
});

describe('Process transport (real Bun child process)', () => {
  const echoScript = `for await (const chunk of Bun.stdin.stream()) {
  for (const line of new TextDecoder().decode(chunk).split("\\n").filter(Boolean)) {
    const msg = JSON.parse(line);
    if (msg.method === "bye") process.exit(3);
    console.log(JSON.stringify({ id: msg.id, result: { echo: msg.params, cwd: process.cwd(), home: process.env.HOME } }));
  }
}`;

  test('records and replays stdin/stdout ordering, remaps JSON-RPC ids, rehydrates cwd, and catches mismatches', async () => {
    const cwd1 = mkdtempSync(join(tmpdir(), 'vcr-proc-1-'));
    const cwd2 = mkdtempSync(join(tmpdir(), 'vcr-proc-2-'));

    const drive = async (
      spawner: ReturnType<typeof createVcrProcessSpawner>,
      startId: number,
      cwd: string,
    ) => {
      const child = spawner.spawn([process.execPath, '-e', echoScript], {
        cwd,
        env: { PATH: process.env.PATH, HOME: accountHomeDirectory() },
      });
      const reading = new Response(child.stdout).text();
      child.stdin.write(`${JSON.stringify({ id: startId, method: 'ping', params: 'one' })}\n`);
      await Bun.sleep(100);
      child.stdin.write(`${JSON.stringify({ id: startId + 1, method: 'ping', params: 'two' })}\n`);
      await Bun.sleep(100);
      child.stdin.write(`${JSON.stringify({ method: 'bye' })}\n`);
      const code = await child.exited;
      const lines = (await reading)
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line) as { id: number; result: { echo: string; cwd: string } });
      return { code, lines };
    };

    try {
      const session = createVcrSession();
      const recorder = createVcrRecorder(dir, {
        service: 'echo-cli',
        version: '1.0.0',
        mode: 'record',
        session,
      }).queue('session', 'rpc');

      const live = await drive(createVcrProcessSpawner(recorder, 'session'), 1, cwd1);
      await recorder.waitUntilSettled();

      expect(live.code).toBe(3);
      expect(live.lines.map((l) => l.id)).toEqual([1, 2]);
      const rawCassette = readFileSync(join(dir, 'session.rpc.json'), 'utf8');
      expect(rawCassette).not.toContain(accountHomeDirectory());
      expect(rawCassette).toContain('{{cwd}}');

      const parsed = JSON.parse(rawCassette) as { body: ProcessTranscript };
      expect(parsed.body.frames.map((frame) => frame.after)).toEqual([1, 2]);
      expect(parsed.body.exit).toEqual({ after: 3, code: 3, killed: false });

      const replayer = createVcrRecorder(dir, {
        service: 'echo-cli',
        version: '1.0.0',
        mode: 'replay',
        session,
      }).queueMany('session', ['rpc', 'rpc', 'rpc']);
      const spawner = createVcrProcessSpawner(replayer, 'session');

      const replayed = await drive(spawner, 50, cwd2);
      expect(replayed.code).toBe(3);
      expect(replayed.lines.map((l) => l.id)).toEqual([50, 51]);
      expect(replayed.lines.map((l) => l.result.echo)).toEqual(['one', 'two']);
      expect(replayed.lines[0]?.result.cwd).toContain(cwd2.split('/').at(-1) ?? '');

      // Wrong stdin request fails with request_mismatch.
      const wrong = spawner.spawn(['echo'], { cwd: cwd2, env: {} });
      expect(() =>
        wrong.stdin.write(`${JSON.stringify({ id: 1, method: 'other', params: 'one' })}\n`),
      ).toThrow('differs from the recording');

      // Ending stdin before all recorded lines were written fails with request_mismatch.
      const short = spawner.spawn(['echo'], { cwd: cwd2, env: {} });
      short.stdin.write(`${JSON.stringify({ id: 9, method: 'ping', params: 'one' })}\n`);
      expect(() => short.stdin.end()).toThrow('stdin ended after 1 of 3 recorded lines');
    } finally {
      rmSync(cwd1, { recursive: true, force: true });
      rmSync(cwd2, { recursive: true, force: true });
    }
  });

  test('supports spawnProbe, recordOnce, sanitizeFrames, and custom ProcessLineProtocol', async () => {
    const probeScript = join(dir, 'probe.ts');
    writeFileSync(
      probeScript,
      'console.log(JSON.stringify({ ok: true, nonce: Math.random(), email: "u@corp.io" }))',
    );

    const session = createVcrSession();
    const recorder = createVcrRecorder(dir, {
      service: 'probe',
      version: '1.0.0',
      mode: 'record',
      session,
    }).queueMany('probe', ['status', 'status']);

    const spawner = createVcrProcessSpawner(recorder, 'probe', {
      argv: [process.execPath, probeScript],
      recordOnce: true,
      sanitizeFrames: (frames) => {
        const parsed = JSON.parse(frames.map((f) => f.data).join('\n')) as {
          ok: boolean;
          nonce: number;
        };
        return [
          {
            after: 0,
            stream: 'stdout',
            data: JSON.stringify({ ok: parsed.ok, nonce: parsed.nonce }),
          },
        ];
      },
    });

    const firstOut = await new Response(spawner.spawnProbe().stdout).text();
    await recorder.waitUntilSettled();
    const secondOut = await new Response(spawner.spawnProbe().stdout).text();
    expect(JSON.parse(secondOut).nonce).toBe(JSON.parse(firstOut).nonce);
    expect(session.liveCalls).toBe(1);
    expect(readFileSync(join(dir, 'probe.status.json'), 'utf8')).not.toContain('u@corp.io');

    // Verify custom ProcessLineProtocol remaps custom correlation tokens.
    const customProtocol: ProcessLineProtocol = {
      createSession() {
        const tokens = new Map<string, string>();
        return {
          comparableStdinLine(line) {
            const obj = JSON.parse(line) as { corr?: string; cmd: string };
            return JSON.stringify({ cmd: obj.cmd });
          },
          observeStdinPair(rec, live) {
            const r = JSON.parse(rec) as { corr?: string };
            const l = JSON.parse(live) as { corr?: string };
            if (r.corr && l.corr) tokens.set(r.corr, l.corr);
          },
          remapOutputLine(line) {
            const obj = JSON.parse(line) as { corr?: string; reply: string };
            if (obj.corr && tokens.has(obj.corr)) {
              return JSON.stringify({ ...obj, corr: tokens.get(obj.corr) });
            }
            return line;
          },
        };
      },
    };

    writeFileSync(
      join(dir, 'proto.custom.json'),
      JSON.stringify({
        version: '1.0.0',
        status: 0,
        body: {
          kind: 'process',
          argv: ['custom'],
          cwd: '{{cwd}}',
          stdin: ['{"corr":"rec-1","cmd":"hello"}'],
          stdinEnded: true,
          frames: [{ after: 1, stream: 'stdout', data: '{"corr":"rec-1","reply":"world"}' }],
          exit: { after: 2, code: 0, killed: false },
        },
      }),
    );

    const customVcr = createVcrRecorder(dir, {
      service: 'custom',
      version: '1.0.0',
      mode: 'replay',
      session,
    }).queue('proto', 'custom');
    const customChild = createVcrProcessSpawner(customVcr, 'proto', {
      lineProtocol: customProtocol,
    }).spawn(['custom'], { cwd: dir, env: {} });
    customChild.stdin.write('{"corr":"live-99","cmd":"hello"}\n');
    customChild.stdin.end();
    const reply = JSON.parse((await new Response(customChild.stdout).text()).trim()) as {
      corr: string;
      reply: string;
    };
    expect(reply).toEqual({ corr: 'live-99', reply: 'world' });
  });
});
