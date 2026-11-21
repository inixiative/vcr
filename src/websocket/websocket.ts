import { VcrError } from '../core/errors';
import type { VcrRecorder } from '../core/recorder';

export interface SocketFrame {
  readonly after: number;
  readonly stream: 'in';
  readonly data: string;
  readonly encoding?: 'utf8' | 'base64';
}

export interface SocketBinaryPayload {
  readonly encoding: 'base64';
  readonly data: string;
}

export type SocketSentPayload = string | SocketBinaryPayload;

export interface SocketTranscript {
  readonly kind: 'websocket';
  readonly path: string;
  readonly sent: SocketSentPayload[];
  readonly frames: SocketFrame[];
  exit: {
    readonly after: number;
    readonly code: number;
    readonly reason: string;
    readonly by: 'client' | 'server';
    readonly wasClean?: boolean;
  };
}

export type SocketSendData = string | ArrayBuffer | ArrayBufferView<ArrayBuffer>;

export type SocketLike = Pick<WebSocket, 'addEventListener' | 'removeEventListener'> & {
  readonly readyState: number;
  send(data: SocketSendData): void;
  close(code?: number, reason?: string): void;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
};

export type VcrSocketFactory = (url: string | URL, protocols?: string | string[]) => SocketLike;

export interface WebSocketCassetteOptions {
  /** Custom underlying WebSocket factory used when recording live. */
  readonly socketImpl?: VcrSocketFactory;
  /** Optional normalizer applied to scrubbed outbound text frames before replay comparison. */
  readonly normalizeSentFrame?: (frame: string) => string;
}

const isValidClientCloseCode = (code: number): boolean =>
  code === 1000 || (code >= 3000 && code <= 4999);

const assertValidCloseCode = (code: number | undefined): void => {
  if (code !== undefined && !isValidClientCloseCode(code)) {
    throw new RangeError(
      `Invalid WebSocket close code ${code}: must be 1000 or in the range 3000–4999`,
    );
  }
};

const createCloseEvent = (code: number, reason: string, wasClean: boolean): CloseEvent => {
  if (typeof CloseEvent !== 'undefined') {
    return new CloseEvent('close', { code, reason, wasClean });
  }
  return Object.assign(new Event('close'), { code, reason, wasClean }) as CloseEvent;
};

const toBytes = (data: ArrayBuffer | ArrayBufferView): Uint8Array =>
  data instanceof ArrayBuffer
    ? new Uint8Array(data)
    : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);

const encodeBinaryBase64 = (data: ArrayBuffer | ArrayBufferView): string =>
  Buffer.from(toBytes(data)).toString('base64');

const decodeBinaryBase64 = (encoded: string): ArrayBuffer => {
  const buf = Buffer.from(encoded, 'base64');
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
};

const serializeSentPayload = (data: SocketSendData, recorder: VcrRecorder): SocketSentPayload => {
  if (typeof data === 'string') return recorder.scrubber.scrubLine(data);
  return { encoding: 'base64', data: encodeBinaryBase64(data) };
};

const defaultSocketImpl: VcrSocketFactory = (url, protocols) => new WebSocket(url, protocols);

const recordWebSocket = (
  recorder: VcrRecorder,
  method: string,
  cassettePath: string,
  url: string | URL,
  protocols: string | string[] | undefined,
  options: WebSocketCassetteOptions,
): SocketLike => {
  recorder.session.spendLiveCall(`${recorder.service} websocket:${method}`);
  const started = Date.now();
  const socketFactory = options.socketImpl ?? defaultSocketImpl;
  const socket = socketFactory(url, protocols);
  const parsedUrl = new URL(String(url));
  const transcript: SocketTranscript = {
    kind: 'websocket',
    path: recorder.scrubber.scrubUrl(`${parsedUrl.pathname}${parsedUrl.search}`),
    sent: [],
    frames: [],
    exit: { after: 0, code: 1005, reason: '', by: 'server', wasClean: false },
  };
  let closingByClient = false;
  const pendingFrameReads: Promise<void>[] = [];

  const onMessage = (event: Event): void => {
    const messageEvent = event as MessageEvent;
    const raw = messageEvent.data;
    if (typeof raw === 'string') {
      transcript.frames.push({
        after: transcript.sent.length,
        stream: 'in',
        data: recorder.scrubber.scrubLine(raw),
      });
      return;
    }
    if (raw instanceof ArrayBuffer || ArrayBuffer.isView(raw)) {
      transcript.frames.push({
        after: transcript.sent.length,
        stream: 'in',
        encoding: 'base64',
        data: encodeBinaryBase64(raw),
      });
      return;
    }
    if (typeof Blob !== 'undefined' && raw instanceof Blob) {
      const frame: {
        readonly after: number;
        readonly stream: 'in';
        readonly encoding: 'base64';
        data: string;
      } = {
        after: transcript.sent.length,
        stream: 'in',
        encoding: 'base64',
        data: '',
      };
      transcript.frames.push(frame);
      pendingFrameReads.push(
        raw.arrayBuffer().then((buf) => {
          frame.data = encodeBinaryBase64(buf);
        }),
      );
      return;
    }
    transcript.frames.push({
      after: transcript.sent.length,
      stream: 'in',
      data: recorder.scrubber.scrubLine(String(raw)),
    });
  };

  socket.addEventListener('message', onMessage);

  recorder.trackPendingWrite(
    new Promise<void>((resolve) => {
      const onClose = (event: Event): void => {
        socket.removeEventListener('message', onMessage);
        socket.removeEventListener('close', onClose);
        const closeEvent = event as CloseEvent;
        transcript.exit = {
          after: transcript.sent.length,
          code: closeEvent.code,
          reason: recorder.scrubber.scrubText(closeEvent.reason),
          by: closingByClient ? 'client' : 'server',
          wasClean: Boolean(closeEvent.wasClean),
        };
        resolve();
      };
      socket.addEventListener('close', onClose);
    }).then(async () => {
      await Promise.all(pendingFrameReads);
      return recorder.storeCassette(
        cassettePath,
        { transport: 'websocket', status: 101, body: transcript },
        { transport: 'websocket', durationMs: Date.now() - started },
      );
    }),
  );

  const originalSend = socket.send.bind(socket);
  const originalClose = socket.close.bind(socket);

  return Object.assign(socket, {
    send(data: SocketSendData): void {
      transcript.sent.push(serializeSentPayload(data, recorder));
      originalSend(data);
    },
    close(code?: number, reason?: string): void {
      assertValidCloseCode(code);
      closingByClient = true;
      if (code === undefined) originalClose();
      else if (reason === undefined) originalClose(code);
      else originalClose(code, reason);
    },
  });
};

class ReplayWebSocket extends EventTarget implements SocketLike {
  readyState: number = WebSocket.CONNECTING;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;

  private nextFrame = 0;
  private sentCount = 0;

  constructor(
    private readonly recorder: VcrRecorder,
    private readonly cassettePath: string,
    private readonly transcript: SocketTranscript,
    private readonly normalizeSentFrame?: (frame: string) => string,
  ) {
    super();
    queueMicrotask(() => {
      if (this.readyState !== WebSocket.CONNECTING) return;
      this.readyState = WebSocket.OPEN;
      this.fireEvent('open', new Event('open'));
      this.releaseDueFrames();
    });
  }

  send(data: SocketSendData): void {
    if (this.readyState !== WebSocket.OPEN) {
      throw new VcrError(
        'request_mismatch',
        'VCR replay (websocket): send called on a socket that is not open',
        { cassette: this.cassettePath },
      );
    }
    const recorded = this.transcript.sent[this.sentCount];
    if (recorded === undefined) {
      throw new VcrError(
        'request_mismatch',
        `VCR replay (websocket): send #${this.sentCount + 1} was not recorded`,
        { cassette: this.cassettePath },
      );
    }
    const incoming = serializeSentPayload(data, this.recorder);
    if (typeof recorded === 'string' && typeof incoming === 'string') {
      const normalize = this.normalizeSentFrame ?? ((value: string) => value);
      if (normalize(incoming) !== normalize(recorded)) {
        throw new VcrError(
          'request_mismatch',
          `VCR replay (websocket): send #${this.sentCount + 1} differs from the recording`,
          { cassette: this.cassettePath },
        );
      }
    } else if (
      typeof recorded === 'object' &&
      typeof incoming === 'object' &&
      recorded.encoding === 'base64' &&
      incoming.encoding === 'base64'
    ) {
      if (recorded.data !== incoming.data) {
        throw new VcrError(
          'request_mismatch',
          `VCR replay (websocket): binary send #${this.sentCount + 1} differs from the recording`,
          { cassette: this.cassettePath },
        );
      }
    } else {
      throw new VcrError(
        'request_mismatch',
        `VCR replay (websocket): send #${this.sentCount + 1} frame type differs from the recording`,
        { cassette: this.cassettePath },
      );
    }
    this.sentCount++;
    this.releaseDueFrames();
  }

  close(code?: number, reason = ''): void {
    assertValidCloseCode(code);
    if (this.readyState >= WebSocket.CLOSING) return;
    this.finish(code ?? 1000, reason, true);
  }

  private releaseDueFrames(): void {
    queueMicrotask(() => {
      while (this.readyState === WebSocket.OPEN && this.nextFrame < this.transcript.frames.length) {
        const frame = this.transcript.frames[this.nextFrame];
        if (!frame || frame.after > this.sentCount) break;
        this.nextFrame++;
        const payload: string | ArrayBuffer =
          frame.encoding === 'base64' ? decodeBinaryBase64(frame.data) : frame.data;
        this.fireEvent('message', new MessageEvent('message', { data: payload }));
      }
      const exit = this.transcript.exit;
      if (
        this.readyState === WebSocket.OPEN &&
        exit.by === 'server' &&
        this.nextFrame >= this.transcript.frames.length &&
        this.sentCount >= exit.after
      ) {
        this.finish(exit.code, exit.reason, exit.wasClean ?? true);
      }
    });
  }

  private finish(code: number, reason: string, wasClean: boolean): void {
    this.readyState = WebSocket.CLOSED;
    this.fireEvent('close', createCloseEvent(code, reason, wasClean));
  }

  private fireEvent(type: 'open' | 'message' | 'close', event: Event): void {
    this.dispatchEvent(event);
    const handler = this[`on${type}`] as ((ev: Event) => void) | null;
    handler?.call(this, event);
  }
}

/** Creates a WebSocket factory backed by queued cassettes on `recorder`. */
export const createVcrWebSocketFactory = (
  recorder: VcrRecorder,
  method: string,
  options: WebSocketCassetteOptions = {},
): VcrSocketFactory => {
  return (url, protocols) => {
    const cassettePath = recorder.popCassettePath(method);
    if (recorder.shouldReplay(cassettePath)) {
      const saved = recorder.fetchCassette<unknown, SocketTranscript>(cassettePath);
      if (saved.body?.kind !== 'websocket') {
        throw new VcrError(
          'invalid_cassette',
          `VCR replay (websocket): cassette "${cassettePath}" does not contain a websocket transcript`,
          { cassette: cassettePath },
        );
      }
      const parsedUrl = new URL(String(url));
      const incomingPath = recorder.scrubber.scrubUrl(`${parsedUrl.pathname}${parsedUrl.search}`);
      if (saved.body.path !== incomingPath) {
        throw new VcrError(
          'request_mismatch',
          `VCR replay (websocket): path "${incomingPath}" was recorded as "${saved.body.path}"`,
          { cassette: cassettePath, details: { recordedPath: saved.body.path, incomingPath } },
        );
      }
      return new ReplayWebSocket(recorder, cassettePath, saved.body, options.normalizeSentFrame);
    }
    return recordWebSocket(recorder, method, cassettePath, url, protocols, options);
  };
};
