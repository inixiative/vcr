import { VcrError } from '../core/errors';
import type { VcrRecorder } from '../core/recorder';

export interface SocketFrame {
  readonly after: number;
  readonly stream: 'in';
  readonly data: string;
}

export interface SocketTranscript {
  readonly kind: 'websocket';
  readonly path: string;
  readonly sent: string[];
  readonly frames: SocketFrame[];
  exit: {
    readonly after: number;
    readonly code: number;
    readonly reason: string;
    readonly by: 'client' | 'server';
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
  /** Optional normalizer applied to scrubbed outbound frames before replay comparison. */
  readonly normalizeSentFrame?: (frame: string) => string;
}

const decodePayload = (data: unknown): string => {
  if (typeof data === 'string') return data;
  if (data instanceof ArrayBuffer) return new TextDecoder().decode(data);
  if (ArrayBuffer.isView(data)) return new TextDecoder().decode(data);
  return String(data);
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
    exit: { after: 0, code: 1005, reason: '', by: 'server' },
  };
  let closingByClient = false;

  socket.addEventListener('message', (event) => {
    const messageEvent = event as MessageEvent;
    transcript.frames.push({
      after: transcript.sent.length,
      stream: 'in',
      data: recorder.scrubber.scrubLine(decodePayload(messageEvent.data)),
    });
  });

  recorder.trackPendingWrite(
    new Promise<void>((resolve) => {
      socket.addEventListener('close', (event) => {
        const closeEvent = event as CloseEvent;
        transcript.exit = {
          after: transcript.sent.length,
          code: closeEvent.code,
          reason: recorder.scrubber.scrubText(closeEvent.reason),
          by: closingByClient ? 'client' : 'server',
        };
        resolve();
      });
    }).then(() =>
      recorder.storeCassette(
        cassettePath,
        { transport: 'websocket', status: 101, body: transcript },
        { transport: 'websocket', durationMs: Date.now() - started },
      ),
    ),
  );

  const originalSend = socket.send.bind(socket);
  const originalClose = socket.close.bind(socket);

  return Object.assign(socket, {
    send(data: SocketSendData): void {
      transcript.sent.push(recorder.scrubber.scrubLine(decodePayload(data)));
      originalSend(data);
    },
    close(code?: number, reason?: string): void {
      closingByClient = true;
      originalClose(code, reason);
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
    const normalize = this.normalizeSentFrame ?? ((value: string) => value);
    const incoming = this.recorder.scrubber.scrubLine(decodePayload(data));
    if (normalize(incoming) !== normalize(recorded)) {
      throw new VcrError(
        'request_mismatch',
        `VCR replay (websocket): send #${this.sentCount + 1} differs from the recording`,
        { cassette: this.cassettePath },
      );
    }
    this.sentCount++;
    this.releaseDueFrames();
  }

  close(code = 1000, reason = ''): void {
    if (this.readyState >= WebSocket.CLOSING) return;
    this.finish(code, reason);
  }

  private releaseDueFrames(): void {
    queueMicrotask(() => {
      while (this.readyState === WebSocket.OPEN && this.nextFrame < this.transcript.frames.length) {
        const frame = this.transcript.frames[this.nextFrame];
        if (!frame || frame.after > this.sentCount) break;
        this.nextFrame++;
        this.fireEvent('message', new MessageEvent('message', { data: frame.data }));
      }
      const exit = this.transcript.exit;
      if (
        this.readyState === WebSocket.OPEN &&
        exit.by === 'server' &&
        this.nextFrame >= this.transcript.frames.length &&
        this.sentCount >= exit.after
      ) {
        this.finish(exit.code, exit.reason);
      }
    });
  }

  private finish(code: number, reason: string): void {
    this.readyState = WebSocket.CLOSED;
    this.fireEvent('close', new CloseEvent('close', { code, reason, wasClean: true }));
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
      return new ReplayWebSocket(recorder, cassettePath, saved.body, options.normalizeSentFrame);
    }
    return recordWebSocket(recorder, method, cassettePath, url, protocols, options);
  };
};
