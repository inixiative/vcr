import { VcrError } from '../core/errors';
import type { VcrRecorder } from '../core/recorder';
import { defineVcrTransport } from '../core/transport';
import type { VcrCassette, VcrTransport } from '../core/types';
import type { Scrubber } from '../scrub/types';

export const DEFAULT_KEPT_RESPONSE_HEADERS: readonly string[] = ['content-type'];

const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

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
  /** Require scrubbed request body to match during replay. Defaults to false. */
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

const extractBodyText = async (
  input: string | URL | Request,
  init?: RequestInit,
): Promise<string | undefined> => {
  if (init?.body !== undefined && init.body !== null) {
    if (typeof init.body === 'string') return init.body;
    if (init.body instanceof URLSearchParams) return init.body.toString();
    if (init.body instanceof Uint8Array) return new TextDecoder().decode(init.body);
    return undefined;
  }
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
    rawBodyText !== undefined ? scrubber.scrubValue(parseBodyText(rawBodyText)) : undefined;
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
  if (options.matchBody && JSON.stringify(recorded.body) !== JSON.stringify(incoming.body)) {
    return `request body for ${incoming.method} ${incoming.path} differs from the recording`;
  }
  return undefined;
};

const pickKeptHeaders = (
  responseHeaders: Headers,
  keptNames: readonly string[],
  scrubber: Scrubber,
): Record<string, string> => {
  const raw: Record<string, string> = {};
  for (const name of keptNames) {
    const value = responseHeaders.get(name);
    if (value !== null) raw[name.toLowerCase()] = value;
  }
  return scrubber.scrubHeaders(raw);
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
    const cassettePath = recorder.popCassettePath(method);
    const incoming = await describeHttpRequest(input, init, recorder.scrubber, options.matchOrigin);

    if (recorder.shouldReplay(cassettePath)) {
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
      const responseBody =
        NULL_BODY_STATUSES.has(saved.status) || saved.body === undefined || saved.body === null
          ? null
          : typeof saved.body === 'string'
            ? saved.body
            : JSON.stringify(saved.body);
      return new Response(responseBody, {
        status: saved.status,
        headers: saved.headers ? { ...saved.headers } : undefined,
      });
    }

    recorder.session.spendLiveCall(`${recorder.service} http:${method}`);
    const started = Date.now();
    const response = await fetchImpl(input, init);
    const text = await response.text();
    const headers = pickKeptHeaders(response.headers, keptResponseHeaders, recorder.scrubber);
    const parsedBody = text.length === 0 ? null : recorder.scrubber.scrubValue(parseBodyText(text));

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

    return new Response(NULL_BODY_STATUSES.has(response.status) ? null : text, {
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
    const body =
      typeof request.init?.body === 'string' ? parseBodyText(request.init.body) : undefined;
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
      const scrubbedBody =
        typeof request.init?.body === 'string'
          ? scrubber.scrubLine(request.init.body)
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
      return scrubber.scrubValue(response);
    },
    matchRequest(recorded, incoming) {
      return defaultMatchHttpRequest(toRecordedShape(recorded), toRecordedShape(incoming), options);
    },
    async executeLive(request) {
      const response = await fetchImpl(request.url, request.init);
      const text = await response.text();
      const headers: Record<string, string> = {};
      for (const name of keptResponseHeaders) {
        const value = response.headers.get(name);
        if (value !== null) headers[name.toLowerCase()] = value;
      }
      const body = text.length === 0 ? null : parseBodyText(text);
      return { status: response.status, headers, body };
    },
  });
};
