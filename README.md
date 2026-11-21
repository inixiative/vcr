# `@inixiative/vcr`

Zero-dependency deterministic cassette recorder, replayer, secret scrubber, structural drift guard, and freshness verifier for HTTP, WebSocket, child processes, and custom transports.

## Subpath exports

- `@inixiative/vcr` — root barrel re-exporting all modules
- `@inixiative/vcr/scrub` — standalone secret/identity/path/URL/header sanitizer and `assertScrubbed` gate
- `@inixiative/vcr/http` — drop-in `fetch` cassette interceptor and generic HTTP `VcrTransport`
- `@inixiative/vcr/process` — child-process stdio and exit-code transcript record & replay
- `@inixiative/vcr/websocket` — WebSocket frame transcript record & replay
- `@inixiative/vcr/freshness` — structural cassette signatures, `.pending.json` drift hold-back workflow, version probes, and freshness policy verification

## Quick start

### Standalone sanitization (`@inixiative/vcr/scrub`)

```ts
import { assertScrubbed, createScrubber } from '@inixiative/vcr/scrub';

const scrubber = createScrubber({
  knownSecrets: [process.env.MY_API_SECRET ?? ''].filter(Boolean),
  scrubIps: true,
});

const safeHeaders = scrubber.scrubHeaders({
  Authorization: 'Bearer super-secret-token-value',
  'X-Api-Key': 'sk-ant-api03-1234567890abcdef',
  'Content-Type': 'application/json',
});

const safeUrl = scrubber.scrubUrl('postgres://admin:topsecret@db.internal:5432/app?api_key=abc123');
const safePayload = scrubber.scrubValue({
  email: 'person@example.com',
  url: safeUrl,
  headers: safeHeaders,
});

// Fails loudly with VcrError('unscrubbed_secret') if any secret or identity field survived
assertScrubbed(safePayload);
```

### HTTP recording & replay (`@inixiative/vcr/http`)

```ts
import { createVcrRecorder } from '@inixiative/vcr';
import { createVcrFetch } from '@inixiative/vcr/http';

const recorder = createVcrRecorder('./tests/fixtures/vcr', {
  service: 'github',
  version: '2026-01-01',
  mode: 'auto', // 'replay' | 'auto' | 'record'
}).queue('repo', 'fetch-main');

const vcrFetch = createVcrFetch(recorder, 'repo');
const response = await vcrFetch('https://api.github.com/repos/inixiative/vcr');
```

### Custom transports (`defineVcrTransport`)

Any protocol (SQL/ORM queries, GraphQL, RPC, SDKs) can plug into the same cassette envelope, scrubber, canonical key matcher, drift hold-back, and freshness policy:

```ts
import { createVcrRecorder, defineVcrTransport } from '@inixiative/vcr';

const sqlTransport = defineVcrTransport<{ query: string; params: unknown[] }, unknown[]>({
  name: 'sql',
  canonicalKey: (req) => `${req.query}::${JSON.stringify(req.params)}`,
  scrubRequest: (req, scrubber) => scrubber.scrubValue(req),
  scrubResponse: (rows, scrubber) => scrubber.scrubValue(rows),
  executeLive: async (req) => ({ status: 200, body: await runQuery(req) }),
});

const recorder = createVcrRecorder('./tests/fixtures/vcr', {
  service: 'postgres',
  version: '16.4',
}).queue('query', 'list-users');

const result = await recorder.execute('query', sqlTransport, {
  query: 'SELECT id, name FROM users WHERE active = $1',
  params: [true],
});
```

### Drift hold-back & freshness policy (`@inixiative/vcr/freshness`)

In `record` mode, structural changes compared to an existing committed cassette are never silently overwritten. Instead, the new recording (and any earlier matching recordings from the same recorder) are written beside the committed cassettes as `*.pending.json` for human review:

```ts
import { acceptPendingCassettes, assertCassettesFresh } from '@inixiative/vcr/freshness';

// In CI / unit tests: fails if any cassette is pending review, leaking secrets, expired, or below blessed version
assertCassettesFresh('./tests/fixtures/vcr');

// After reviewing drift: promote *.pending.json over committed cassettes
acceptPendingCassettes('./tests/fixtures/vcr');
```

## Vocabulary

Every exported function, constant, and type across all six entry points is documented in [docs/VERBS.md](docs/VERBS.md) and verified by `tests/verbs.test.ts`.

## License

MIT
