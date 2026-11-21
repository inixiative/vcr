import { VcrError } from '../core/errors';
import { readCassetteBody } from '../core/fs-utils';
import type { VcrRecorder } from '../core/recorder';
import { defineVcrTransport } from '../core/transport';
import type { VcrCassette, VcrTransport } from '../core/types';
import type { Scrubber } from '../scrub/types';

export const DEFAULT_KEPT_RESPONSE_HEADERS: readonly string[] = ['content-type'];

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

const BINARY_CONTENT_TYPE_PREFIXES = ['image/', 'audio/', 'video/', 'font/'];
const BINARY_CONTENT_TYPES = new Set([
  'application/octet-stream',
  'application/pdf',
  'application/zip',
  'application/gzip',
  'application/x-gzip',
  'application/wasm',
  'application/protobuf',
  'application/x-protobuf',
  'application/grpc',
]);

const CONTENT_TYPE_EXTENSIONS: Readonly<Record<string, string>> = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/gif': '.gif',
  'image/webp': '.webp',
  'application/pdf': '.pdf',
  'application/zip': '.zip',
  'application/gzip': '.gz',
  'application/wasm': '.wasm',
};

export interface RecordedHttpRequest {
  readonly method: string;
  readonly path: string;
  readonly origin?: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: unknown;
}

export type HttpCassette<TResponse = unknown> = VcrCassette<RecordedHttpRequest, TResponse>;

export interface HttpCassetteOptions {
  /** Custom underlying fetch implementation used when recording live. Defaults to `globalThis.fetch`. */
  readonly fetchImpl?: typeof fetch;
  /** Response headers retained in recorded cassettes (case-insensitive). Defaults to `['content-type']`. */
  readonly keptResponseHeaders?: readonly string[];
  /** Require URL origin to match during replay. Defaults to false. */
  readonly matchOrigin?: boolean;
  /** Require canonical scrubbed request body to match during replay. Defaults to false. */
  readonly matchBody?: boolean;
  /** Specific scrubbed request header names that must match during replay. */
  readonly matchHeaders?: readonly string[];
  /** Custom request matcher returning a mismatch description or undefined when matched. */
  readonly matchRequest?: (
    recorded: RecordedHttpRequest,
    incoming: RecordedHttpRequest,
  ) => string | undefined;
}

export interface HttpTransportRequest {
  readonly url: string | URL;
  readonly init?: RequestInit;
}

const parseBodyText = (text: string): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

const canonicalJson = (value: unknown): string => {
  const sort = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(sort);
    if (node && typeof node === 'object') {
      return Object.fromEntries(
        Object.entries(node as Record<string, unknown>)
          .filter(([, v]) => v !== undefined)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([k, v]) => [k, sort(v)]),
      );
    }
    return node;
  };
  return JSON.stringify(sort(value));
};

const mimeTypeOf = (contentType: string | null): string =>
  (contentType ?? '').split(';')[0]?.trim().toLowerCase() ?? '';

const isBinaryContentType = (contentType: string | null): boolean => {
  const mime = mimeTypeOf(contentType);
  if (!mime) return false;
  if (BINARY_CONTENT_TYPES.has(mime)) return true;
  return BINARY_CONTENT_TYPE_PREFIXES.some((prefix) => mime.startsWith(prefix));
};

const extensionForContentType = (contentType: string | null): string =>
  CONTENT_TYPE_EXTENSIONS[mimeTypeOf(contentType)] ?? '.bin';

const decodeBodyBytes = (
  bytes: Uint8Array,
  contentType: string | null,
):
  | { readonly binary: true; readonly bytes: Uint8Array; readonly extension: string }
  | { readonly binary: false; readonly text: string } => {
  if (bytes.length === 0) return { binary: false, text: '' };
  if (isBinaryContentType(contentType)) {
    return { binary: true, bytes, extension: extensionForContentType(contentType) };
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    return { binary: false, text };
  } catch {
    return { binary: true, bytes, extension: extensionForContentType(contentType) };
  }
};

const decodeBodySource = (body: BodyInit | null | undefined): string | undefined => {
  if (body === undefined || body === null) return undefined;
  if (typeof body === 'string') return body;
  if (body instanceof URLSearchParams) return body.toString();
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(new Uint8Array(body));
  if (ArrayBuffer.isView(body)) {
    return new TextDecoder().decode(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
  }
  return undefined;
};

const extractBodyText = async (
  input: string | URL | Request,
  init?: RequestInit,
): Promise<string | undefined> => {
  const fromInit = decodeBodySource(init?.body);
  if (fromInit !== undefined) return fromInit;
  if (input instanceof Request && input.body !== null) {
    try {
      const text = await input.clone().text();
      return text.length > 0 ? text : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
};

const extractKeptResponseHeaders = (
  responseHeaders: Headers,
  keptNames: readonly string[],
): Record<string, string> => {
  const raw: Record<string, string> = {};
  for (const name of keptNames) {
    const value = responseHeaders.get(name);
    if (value !== null) raw[name.toLowerCase()] = value;
  }
  return raw;
};

const pickKeptHeaders = (
  responseHeaders: Headers,
  keptNames: readonly string[],
  scrubber: Scrubber,
): Record<string, string> =>
  scrubber.scrubHeaders(extractKeptResponseHeaders(responseHeaders, keptNames));

const checkAborted = (signal: AbortSignal | null | undefined): void => {
  if (!signal?.aborted) return;
  throw signal.reason ?? new DOMException('The operation was aborted.', 'AbortError');
};

const scrubUrlSearchParams = (params: URLSearchParams, scrubber: Scrubber): string => {
  const query = params.toString();
  if (!query) return '';
  const scrubbed = scrubber.scrubUrl(`/?${query}`);
  return scrubbed.startsWith('/?') ? scrubbed.slice(2) : scrubbed.slice(1);
};

/** Normalizes and scrubs an HTTP fetch input + init pair into a deterministic `RecordedHttpRequest`. */
export const describeHttpRequest = async (
  input: string | URL | Request,
  init: RequestInit | undefined,
  scrubber: Scrubber,
  includeOrigin = false,
): Promise<RecordedHttpRequest> => {
  const request = input instanceof Request ? input : undefined;
  const rawUrl = request ? request.url : String(input);
  const url = new URL(rawUrl);
  const headers = scrubber.scrubHeaders(new Headers(init?.headers ?? request?.headers));
  const rawBodyText = await extractBodyText(input, init);
  const parsedBody =
    init?.body instanceof URLSearchParams
      ? scrubUrlSearchParams(init.body, scrubber)
      : rawBodyText !== undefined
        ? scrubber.scrubValue(parseBodyText(rawBodyText))
        : undefined;
  const scrubbedPath = scrubber.scrubUrl(`${url.pathname}${url.search}`);
  return {
    method: (init?.method ?? request?.method ?? 'GET').toUpperCase(),
    path: scrubbedPath,
    ...(includeOrigin ? { origin: url.origin } : {}),
    headers,
    ...(parsedBody === undefined ? {} : { body: parsedBody }),
  };
};

const defaultMatchHttpRequest = (
  recorded: RecordedHttpRequest,
  incoming: RecordedHttpRequest,
  options: HttpCassetteOptions,
): string | undefined => {
  if (options.matchRequest) return options.matchRequest(recorded, incoming);
  if (recorded.method !== incoming.method || recorded.path !== incoming.path) {
    return `${incoming.method} ${incoming.path} was recorded as ${recorded.method} ${recorded.path}`;
  }
  if (options.matchOrigin && recorded.origin && recorded.origin !== incoming.origin) {
    return `origin ${incoming.origin ?? '<none>'} was recorded as ${recorded.origin}`;
  }
  if (options.matchHeaders?.length) {
    for (const rawHeader of options.matchHeaders) {
      const header = rawHeader.toLowerCase();
      if (recorded.headers[header] !== incoming.headers[header]) {
        return `header "${header}" differs from the recording`;
      }
    }
  }
  if (options.matchBody && canonicalJson(recorded.body) !== canonicalJson(incoming.body)) {
    return `request body for ${incoming.method} ${incoming.path} differs from the recording`;
  }
  return undefined;
};

/** Creates a drop-in `fetch` function backed by queued cassettes on `recorder`. */
export const createVcrFetch = (
  recorder: VcrRecorder,
  method: string,
  options: HttpCassetteOptions = {},
): typeof fetch => {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const keptResponseHeaders = options.keptResponseHeaders ?? DEFAULT_KEPT_RESPONSE_HEADERS;

  const recordedFetch = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const signal = init?.signal ?? (input instanceof Request ? input.signal : undefined);
    checkAborted(signal);

    const cassettePath = recorder.popCassettePath(method);
    const incoming = await describeHttpRequest(input, init, recorder.scrubber, options.matchOrigin);

    if (recorder.shouldReplay(cassettePath)) {
      checkAborted(signal);
      const saved = recorder.fetchCassette<RecordedHttpRequest, unknown>(cassettePath);
      if (saved.request) {
        const mismatch = defaultMatchHttpRequest(saved.request, incoming, options);
        if (mismatch) {
          throw new VcrError('request_mismatch', `VCR replay (http): ${mismatch}`, {
            cassette: cassettePath,
            details: { recorded: saved.request, incoming },
          });
        }
      }
      const resolvedPath = recorder.session.written.get(cassettePath) ?? cassettePath;
      const body = readCassetteBody(saved, resolvedPath);
      const responseBody: BodyInit | null = NULL_BODY_STATUSES.has(saved.status)
        ? null
        : body instanceof Uint8Array
          ? new Uint8Array(body)
          : body === undefined || body === null
            ? null
            : typeof body === 'string'
              ? body
              : JSON.stringify(body);
      return new Response(responseBody, {
        status: saved.status,
        headers: saved.headers ? { ...saved.headers } : undefined,
      });
    }

    recorder.session.spendLiveCall(`${recorder.service} http:${method}`);
    const started = Date.now();
    const response = await fetchImpl(input, init);
    const rawBuffer = await response.arrayBuffer();
    const bytes = new Uint8Array(rawBuffer);
    const decoded = decodeBodyBytes(bytes, response.headers.get('content-type'));
    const headers = pickKeptHeaders(response.headers, keptResponseHeaders, recorder.scrubber);

    if (decoded.binary) {
      await recorder.storeCassette<RecordedHttpRequest, unknown>(
        cassettePath,
        {
          transport: 'http',
          key: `${incoming.method} ${incoming.path}`,
          request: incoming,
          status: response.status,
          headers,
          binarySidecar: { data: decoded.bytes, extension: decoded.extension },
        },
        { transport: 'http', durationMs: Date.now() - started },
      );
      return new Response(NULL_BODY_STATUSES.has(response.status) ? null : rawBuffer, {
        status: response.status,
        headers: response.headers,
      });
    }

    const parsedBody =
      decoded.text.length === 0 ? null : recorder.scrubber.scrubValue(parseBodyText(decoded.text));

    await recorder.storeCassette<RecordedHttpRequest, unknown>(
      cassettePath,
      {
        transport: 'http',
        key: `${incoming.method} ${incoming.path}`,
        request: incoming,
        status: response.status,
        headers,
        body: parsedBody,
      },
      { transport: 'http', durationMs: Date.now() - started },
    );

    return new Response(NULL_BODY_STATUSES.has(response.status) ? null : decoded.text, {
      status: response.status,
      headers: response.headers,
    });
  };

  return Object.assign(recordedFetch, {
    preconnect: fetchImpl.preconnect,
  }) as typeof fetch;
};

/** Creates a generic `VcrTransport` for structured HTTP calls through `recorder.execute(...)`. */
export const createHttpTransport = (
  options: HttpCassetteOptions = {},
): VcrTransport<HttpTransportRequest, unknown> => {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const keptResponseHeaders = options.keptResponseHeaders ?? DEFAULT_KEPT_RESPONSE_HEADERS;

  const toRecordedShape = (request: HttpTransportRequest): RecordedHttpRequest => {
    const parsed = new URL(String(request.url));
    const headers: Record<string, string> = {};
    new Headers(request.init?.headers).forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    const rawBody = decodeBodySource(request.init?.body);
    const body = rawBody !== undefined ? parseBodyText(rawBody) : undefined;
    return {
      method: (request.init?.method ?? 'GET').toUpperCase(),
      path: `${parsed.pathname}${parsed.search}`,
      ...(options.matchOrigin ? { origin: parsed.origin } : {}),
      headers,
      ...(body === undefined ? {} : { body }),
    };
  };

  return defineVcrTransport<HttpTransportRequest, unknown>({
    name: 'http',
    canonicalKey(request) {
      const parsed = new URL(String(request.url));
      const verb = (request.init?.method ?? 'GET').toUpperCase();
      return `${verb} ${parsed.pathname}${parsed.search}`;
    },
    scrubRequest(request, scrubber) {
      const scrubbedUrl = scrubber.scrubUrl(String(request.url));
      const scrubbedHeaders = request.init?.headers
        ? scrubber.scrubHeaders(new Headers(request.init.headers))
        : undefined;
      const decodedBody = decodeBodySource(request.init?.body);
      const scrubbedBody =
        request.init?.body instanceof URLSearchParams
          ? scrubUrlSearchParams(request.init.body, scrubber)
          : decodedBody !== undefined
            ? scrubber.scrubLine(decodedBody)
            : request.init?.body;
      return {
        url: scrubbedUrl,
        ...(request.init
          ? {
              init: {
                method: (request.init.method ?? 'GET').toUpperCase(),
                ...(scrubbedHeaders ? { headers: scrubbedHeaders } : {}),
                ...(scrubbedBody !== undefined ? { body: scrubbedBody } : {}),
              },
            }
          : {}),
      };
    },
    scrubResponse(response, scrubber) {
      return response instanceof Uint8Array ? response : scrubber.scrubValue(response);
    },
    matchRequest(recorded, incoming) {
      return defaultMatchHttpRequest(toRecordedShape(recorded), toRecordedShape(incoming), options);
    },
    async executeLive(request) {
      checkAborted(request.init?.signal);
      const response = await fetchImpl(request.url, request.init);
      const rawBuffer = await response.arrayBuffer();
      const bytes = new Uint8Array(rawBuffer);
      const decoded = decodeBodyBytes(bytes, response.headers.get('content-type'));
      const headers = extractKeptResponseHeaders(response.headers, keptResponseHeaders);
      if (decoded.binary) {
        return { status: response.status, headers, body: decoded.bytes };
      }
      const body = decoded.text.length === 0 ? null : parseBodyText(decoded.text);
      return { status: response.status, headers, body };
    },
  });
};
