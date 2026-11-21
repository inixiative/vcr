import { spawn as nodeSpawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { Readable } from 'node:stream';
import { VcrError } from '../core/errors';
import type { VcrRecorder } from '../core/recorder';
import type { VcrCassette } from '../core/types';
import type { ScrubContext } from '../scrub/types';

export interface ProcessFrame {
  readonly after: number;
  readonly stream: 'stdout' | 'stderr';
  readonly data: string;
  readonly eol?: false;
  readonly kept?: true;
}

export interface ProcessTranscript {
  readonly kind: 'process';
  readonly argv: readonly string[];
  readonly cwd: string;
  readonly stdin: string[];
  stdinEnded: boolean;
  frames: ProcessFrame[];
  exit: { readonly after: number; readonly code: number | null; readonly killed: boolean };
}

export interface ProcessSpawnOptions {
  readonly cwd: string;
  readonly env: Record<string, string | undefined>;
}

export interface RecordedProcess {
  readonly stdin: {
    write(data: string | Uint8Array): void;
    flush(): void;
    end(): void;
  };
  readonly stdout: ReadableStream<Uint8Array>;
  readonly stderr: ReadableStream<Uint8Array>;
  readonly exited: Promise<number>;
  kill(): void;
}

export interface ProcessLaunch {
  readonly argv: readonly string[];
  readonly env: Record<string, string | undefined>;
  readonly cwd: string;
  stdin: string;
  exited: boolean;
}

export interface ProcessLineProtocolSession {
  /** Returns a normalized representation of a scrubbed stdin line for replay comparison. */
  comparableStdinLine(line: string): string;
  /** Observes a matched `(recordedLine, liveLine)` pair so output frames can remap client IDs. */
  observeStdinPair(recordedLine: string, liveLine: string): void;
  /** Remaps dynamic client IDs in a replayed stdout/stderr line before delivering to the caller. */
  remapOutputLine(line: string): string;
}

export interface ProcessLineProtocol {
  createSession(): ProcessLineProtocolSession;
}

export interface ProcessCassetteOptions {
  /** Fixed argv used by `spawnProbe()` or overriding live command arguments. */
  readonly argv?: readonly string[];
  /** Optional filter/sanitizer reducing raw frames before generic scrubbing. */
  readonly sanitizeFrames?: (frames: ProcessFrame[]) => ProcessFrame[];
  /** Environment builder for `spawnProbe()`. */
  readonly probeEnv?: () => Record<string, string | undefined>;
  /** Transform applied to `options.env` before spawning a live process. */
  readonly transformLiveEnv?: (
    env: Record<string, string | undefined>,
  ) => Record<string, string | undefined>;
  /** Record at most once per session and replay that recording on subsequent spawns. */
  readonly recordOnce?: boolean;
  /** Optional model identifier or extractor stamped onto the recorded cassette. */
  readonly model?: string | ((transcript: ProcessTranscript) => string | undefined);
  /** Protocol hook normalizing stdin matching and remapping client IDs on replay. Defaults to `jsonRpcLineProtocol`. */
  readonly lineProtocol?: ProcessLineProtocol;
  /** Custom live process spawner (defaults to Bun.spawn or Node child_process.spawn). */
  readonly spawnImpl?: (argv: readonly string[], options: ProcessSpawnOptions) => RecordedProcess;
}

export interface VcrProcessSpawner {
  readonly launches: ProcessLaunch[];
  writes: number;
  spawn(argv: readonly string[], options: ProcessSpawnOptions): RecordedProcess;
  spawnProbe(): RecordedProcess;
}

const encoder = new TextEncoder();

const decodeChunk = (data: string | Uint8Array): string =>
  typeof data === 'string' ? data : new TextDecoder().decode(data);

interface JsonRpcLike {
  readonly id?: string | number;
  readonly method?: string;
}

const parseJsonObject = (line: string): Record<string, unknown> | undefined => {
  try {
    const parsed = JSON.parse(line) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
};

const jsonRpcRequestId = (
  value: Record<string, unknown> | undefined,
): string | number | undefined => {
  if (!value) return undefined;
  const candidate = value as JsonRpcLike;
  if (
    candidate.method !== undefined &&
    (typeof candidate.id === 'string' || typeof candidate.id === 'number')
  ) {
    return candidate.id;
  }
  return undefined;
};

/** Default line protocol supporting JSON-RPC client request ID normalization and response remapping. */
export const jsonRpcLineProtocol: ProcessLineProtocol = {
  createSession(): ProcessLineProtocolSession {
    const idMap = new Map<string, string | number>();

    return {
      comparableStdinLine(line: string): string {
        const parsed = parseJsonObject(line);
        if (!parsed || jsonRpcRequestId(parsed) === undefined) return line.trim();
        const { id: _ignored, ...rest } = parsed;
        return JSON.stringify(rest);
      },
      observeStdinPair(recordedLine: string, liveLine: string): void {
        const recordedId = jsonRpcRequestId(parseJsonObject(recordedLine));
        const liveId = jsonRpcRequestId(parseJsonObject(liveLine));
        if (recordedId !== undefined && liveId !== undefined) {
          idMap.set(String(recordedId), liveId);
        }
      },
      remapOutputLine(line: string): string {
        const parsed = parseJsonObject(line);
        if (!parsed || parsed.method !== undefined || parsed.id === undefined) return line;
        const mapped = idMap.get(String(parsed.id));
        if (mapped === undefined) return line;
        return JSON.stringify({ ...parsed, id: mapped });
      },
    };
  },
};

const spawnDefaultLiveProcess = (
  argv: readonly string[],
  options: ProcessSpawnOptions,
): RecordedProcess => {
  const [command, ...args] = argv;
  if (!command) {
    throw new VcrError('invalid_cassette', 'VCR process: argv must contain at least one element');
  }

  if (typeof Bun !== 'undefined' && typeof Bun.spawn === 'function') {
    const child = Bun.spawn([...argv], {
      cwd: options.cwd,
      env: options.env,
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'pipe',
    });
    return {
      stdin: {
        write(data) {
          child.stdin.write(data);
        },
        flush() {
          child.stdin.flush();
        },
        end() {
          child.stdin.end();
        },
      },
      stdout: child.stdout,
      stderr: child.stderr,
      exited: child.exited,
      kill() {
        child.kill();
      },
    };
  }

  const child = nodeSpawn(command, args, {
    cwd: options.cwd,
    env: options.env,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  const exited = new Promise<number>((resolve) => {
    child.on('exit', (code) => resolve(code ?? 1));
    child.on('error', () => resolve(1));
  });
  const stdout = Readable.toWeb(child.stdout) as unknown as ReadableStream<Uint8Array>;
  const stderr = Readable.toWeb(child.stderr) as unknown as ReadableStream<Uint8Array>;

  return {
    stdin: {
      write(data) {
        child.stdin.write(data);
      },
      flush() {},
      end() {
        child.stdin.end();
      },
    },
    stdout,
    stderr,
    exited,
    kill() {
      child.kill();
    },
  };
};

const recordProcess = (
  recorder: VcrRecorder,
  cassettePath: string,
  argv: readonly string[],
  spawnOptions: ProcessSpawnOptions,
  config: ProcessCassetteOptions,
  onWrite: (data: string) => void,
  onExit: () => void,
): RecordedProcess => {
  recorder.session.spendLiveCall(argv.slice(0, 2).join(' '));
  const started = Date.now();
  const liveEnv = config.transformLiveEnv
    ? config.transformLiveEnv(spawnOptions.env)
    : spawnOptions.env;
  const spawnImpl = config.spawnImpl ?? spawnDefaultLiveProcess;
  const child = spawnImpl(argv, { cwd: spawnOptions.cwd, env: liveEnv });

  const context: ScrubContext = { cwd: spawnOptions.cwd };
  const transcript: ProcessTranscript = {
    kind: 'process',
    argv: argv.map((arg) => recorder.scrubber.scrubText(arg, context)),
    cwd: '{{cwd}}',
    stdin: [],
    stdinEnded: false,
    frames: [],
    exit: { after: 0, code: null, killed: false },
  };

  let events = 0;
  let killed = false;
  const rawFrames: ProcessFrame[] = [];

  const teeStream = (source: ReadableStream<Uint8Array>, stream: 'stdout' | 'stderr') => {
    let controller: ReadableStreamDefaultController<Uint8Array> | undefined;
    const readable = new ReadableStream<Uint8Array>({
      start(ctrl) {
        controller = ctrl;
      },
    });
    const done = (async () => {
      const decoder = new TextDecoder();
      let buffer = '';
      const pushFrame = (data: string, eol: boolean): void => {
        rawFrames.push({
          after: events,
          stream,
          data,
          ...(eol ? {} : { eol: false as const }),
        });
      };
      try {
        for await (const chunk of source) {
          try {
            controller?.enqueue(chunk);
          } catch {
            /* Downstream reader cancelled; continue recording stream. */
          }
          buffer += decoder.decode(chunk, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() ?? '';
          for (const line of lines) pushFrame(line, true);
        }
      } catch {
        /* Stream interrupted when process was killed. */
      }
      buffer += decoder.decode();
      if (buffer) pushFrame(buffer, false);
      try {
        controller?.close();
      } catch {
        /* Already closed. */
      }
    })();
    return { readable, done };
  };

  const stdout = teeStream(child.stdout, 'stdout');
  const stderr = teeStream(child.stderr, 'stderr');

  const exited = child.exited.then((code) => {
    onExit();
    transcript.exit = { after: events, code: killed ? null : code, killed };
    return code;
  });

  recorder.trackPendingWrite(
    Promise.all([exited, stdout.done, stderr.done]).then(([code]) => {
      const durationMs = Date.now() - started;
      const filteredFrames = config.sanitizeFrames
        ? config.sanitizeFrames(rawFrames).map((frame) => ({ ...frame, kept: true as const }))
        : rawFrames;
      transcript.frames = filteredFrames.map((frame) => ({
        ...frame,
        data: recorder.scrubber.scrubLine(frame.data, context),
      }));
      const model = typeof config.model === 'function' ? config.model(transcript) : config.model;
      return recorder.storeCassette(
        cassettePath,
        { transport: 'process', status: killed ? 0 : code, body: transcript },
        { transport: 'process', durationMs, ...(model ? { model } : {}) },
      );
    }),
  );

  return {
    stdout: stdout.readable,
    stderr: stderr.readable,
    exited,
    stdin: {
      write(data) {
        const value = decodeChunk(data);
        onWrite(value);
        transcript.stdin.push(recorder.scrubber.scrubLine(value, context));
        events++;
        child.stdin.write(data);
      },
      flush() {
        child.stdin.flush();
      },
      end() {
        if (!transcript.stdinEnded) {
          transcript.stdinEnded = true;
          events++;
        }
        child.stdin.end();
      },
    },
    kill() {
      killed = true;
      child.kill();
    },
  };
};

const replayProcess = (
  recorder: VcrRecorder,
  cassettePath: string,
  cassette: VcrCassette<unknown, ProcessTranscript>,
  spawnOptions: ProcessSpawnOptions,
  config: ProcessCassetteOptions,
  onWrite: (data: string) => void,
  onExit: () => void,
): RecordedProcess => {
  const transcript = cassette.body;
  if (transcript?.kind !== 'process') {
    throw new VcrError(
      'invalid_cassette',
      `VCR replay (process): cassette "${cassettePath}" does not contain a process transcript`,
      { cassette: cassettePath },
    );
  }

  const context: ScrubContext = { cwd: spawnOptions.cwd };
  const protocolSession = (config.lineProtocol ?? jsonRpcLineProtocol).createSession();

  const controllers: Partial<
    Record<'stdout' | 'stderr', ReadableStreamDefaultController<Uint8Array>>
  > = {};
  const createStream = (name: 'stdout' | 'stderr'): ReadableStream<Uint8Array> =>
    new ReadableStream<Uint8Array>({
      start(controller) {
        controllers[name] = controller;
      },
    });
  const stdout = createStream('stdout');
  const stderr = createStream('stderr');

  let resolveExit: ((code: number) => void) | undefined;
  const exited = new Promise<number>((resolve) => {
    resolveExit = resolve;
  });

  let events = 0;
  let nextFrame = 0;
  let closed = false;
  let stdinLineIndex = 0;
  let stdinEnded = false;

  const closeProcess = (code: number): void => {
    if (closed) return;
    closed = true;
    onExit();
    for (const controller of Object.values(controllers)) {
      try {
        controller?.close();
      } catch {
        /* Stream already closed. */
      }
    }
    resolveExit?.(code);
  };

  const releaseDueFrames = (): void => {
    queueMicrotask(() => {
      while (!closed && nextFrame < transcript.frames.length) {
        const frame = transcript.frames[nextFrame];
        if (!frame || frame.after > events) break;
        nextFrame++;
        const rehydrated = recorder.scrubber.rehydratePlaceholders(frame.data, context);
        const remapped = protocolSession.remapOutputLine(rehydrated);
        const output = remapped + (frame.eol === false ? '' : '\n');
        try {
          controllers[frame.stream]?.enqueue(encoder.encode(output));
        } catch {
          /* Reader cancelled. */
        }
      }
      if (
        !closed &&
        !transcript.exit.killed &&
        nextFrame >= transcript.frames.length &&
        events >= transcript.exit.after
      ) {
        closeProcess(transcript.exit.code ?? 1);
      }
    });
  };

  const recordedStdinLines = transcript.stdin.flatMap((chunk) => chunk.split('\n').filter(Boolean));
  const failMismatch = (detail: string): never => {
    throw new VcrError(
      'request_mismatch',
      `VCR replay (process ${transcript.argv.slice(0, 2).join(' ')}): ${detail}`,
      { cassette: cassettePath },
    );
  };

  releaseDueFrames();

  return {
    stdout,
    stderr,
    exited,
    stdin: {
      write(data) {
        if (closed) failMismatch('write after process exit');
        const value = decodeChunk(data);
        onWrite(value);
        for (const line of value.split('\n').filter(Boolean)) {
          const recorded = recordedStdinLines[stdinLineIndex++];
          if (recorded === undefined) {
            failMismatch(`stdin line ${stdinLineIndex} was not recorded`);
          }
          const scrubbedIncoming = recorder.scrubber.scrubLine(line, context);
          if (
            protocolSession.comparableStdinLine(scrubbedIncoming) !==
            protocolSession.comparableStdinLine(recorded)
          ) {
            failMismatch(`stdin line ${stdinLineIndex} differs from the recording`);
          }
          protocolSession.observeStdinPair(recorded, line);
        }
        events++;
        releaseDueFrames();
      },
      flush() {},
      end() {
        if (stdinEnded) return;
        if (stdinLineIndex < recordedStdinLines.length) {
          failMismatch(
            `stdin ended after ${stdinLineIndex} of ${recordedStdinLines.length} recorded lines`,
          );
        }
        stdinEnded = true;
        events++;
        releaseDueFrames();
      },
    },
    kill() {
      closeProcess(transcript.exit.killed ? (transcript.exit.code ?? 143) : 143);
    },
  };
};

/** Creates a child-process spawner backed by queued cassettes on `recorder`. */
export const createVcrProcessSpawner = (
  recorder: VcrRecorder,
  method: string,
  options: ProcessCassetteOptions = {},
): VcrProcessSpawner => {
  const launches: ProcessLaunch[] = [];
  const spawner: VcrProcessSpawner = {
    launches,
    writes: 0,
    spawn(argv, spawnOptions) {
      const cassettePath = recorder.popCassettePath(method);
      const launch: ProcessLaunch = {
        argv,
        env: spawnOptions.env,
        cwd: spawnOptions.cwd,
        stdin: '',
        exited: false,
      };
      launches.push(launch);

      const onWrite = (data: string): void => {
        launch.stdin += data;
        spawner.writes++;
      };
      const onExit = (): void => {
        launch.exited = true;
      };

      if (recorder.shouldReplay(cassettePath, options.recordOnce === true)) {
        return replayProcess(
          recorder,
          cassettePath,
          recorder.fetchCassette<unknown, ProcessTranscript>(cassettePath),
          spawnOptions,
          options,
          onWrite,
          onExit,
        );
      }

      return recordProcess(
        recorder,
        cassettePath,
        options.argv ?? argv,
        spawnOptions,
        options,
        onWrite,
        onExit,
      );
    },
    spawnProbe() {
      if (!options.argv?.length) {
        throw new VcrError('invalid_cassette', 'VCR process: spawnProbe requires options.argv');
      }
      return spawner.spawn(options.argv, {
        cwd: tmpdir(),
        env: options.probeEnv?.() ?? { PATH: process.env.PATH },
      });
    },
  };
  return spawner;
};
