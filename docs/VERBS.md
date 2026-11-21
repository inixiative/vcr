# Verbs

Every operation `@inixiative/vcr` performs has one verb, one public name per resource it acts on,
and one implementation. `tests/verbs.test.ts` enforces that every exported symbol across all six
entry points (`src/index.ts`, `src/scrub/index.ts`, `src/http/index.ts`, `src/process/index.ts`,
`src/websocket/index.ts`, `src/freshness/index.ts`) is documented here, no stale symbols remain in
this file, no public export uses the banned `get*` prefix (`R-2026-11-17-07`), and no closed-product
names appear in public source or docs.

## Core recorder, session, transport, and errors (`src/core/`)

| Verb | Name | What it does |
| --- | --- | --- |
| construct | `VcrError` | Typed VCR error carrying a snake_case `VcrErrorCode`, optional cassette path, details, and cause. |
| narrow | `isVcrError` | Type guard checking whether an unknown error is a `VcrError` (optionally matching a specific `VcrErrorCode`). |
| resolve | `resolveVcrMode` | Resolves the active `VcrMode` (`replay`, `auto`, or `record`) by precedence from options, environment variable, or default `replay`. |
| create | `createVcrSession` | Creates an isolated `VcrSession` holding version cache, live call budget, written cassette paths, and drift findings. |
| seed | `seedVcrServiceVersion` | Pre-seeds the default VCR session's version cache for a service so recorders skip live version probes. |
| clear | `clearVcrVersionCache` | Clears cached service versions in the default VCR session. |
| reset | `resetDefaultVcrSession` | Resets version cache, live call budget counter, written paths, and drift log in the default VCR session. |
| construct | `VcrRecorder` | Stateful cassette recorder and replayer coordinating queueing, scrubbing, secret assertions, binary sidecars, and drift hold-back. |
| create | `createVcrRecorder` | Creates a `VcrRecorder` bound to a fixtures directory and service configuration. |
| define | `defineVcrTransport` | Declares a typed `VcrTransport` adapter for plugging any protocol (SQL, RPC, HTTP, SDK) into `VcrRecorder.execute`. |

Constants and registries: `VCR_MODES`, `DEFAULT_MAX_LIVE_CALLS`, `DEFAULT_MODE_ENV_VAR`,
`defaultVcrSession`.

## Sanitization and secret detection (`src/scrub/`)

| Verb | Name | What it does |
| --- | --- | --- |
| look up | `accountHomeDirectory` | Returns the OS user's real home directory independent of temporary `HOME` overrides. |
| look up | `defaultPlaceholderFor` | Returns the default deterministic redaction placeholder string for a `ScrubPlaceholderKind`. |
| create | `createScrubber` | Creates a configured `Scrubber` handle with custom `knownSecrets`, regex rules, headers, query params, and normalizers. |
| scrub | `scrubText` | Scrubs explicit known secrets, local paths, credentials, tokens, JWTs, PEM keys, URL credentials, and optional normalizers from a string. |
| scrub | `scrubValue` | Recursively and cycle-safely scrubs strings, objects, arrays, URLs, Headers, Maps, Sets, and Errors. |
| scrub | `scrubLine` | Scrubs a single line of text, preserving valid JSON formatting when the line is a JSON object or array. |
| scrub | `scrubUrl` | Scrubs embedded credentials, secret query parameters, and paths in an absolute or relative URL with deterministic query ordering. |
| scrub | `scrubHeaders` | Normalizes header names to lowercase sorted order and scrubs secret headers and credential values. |
| rehydrate | `rehydratePlaceholders` | Restores `{{tmp}}`, `{{cwd}}`, and custom path placeholders in a replayed string for the current run's directories. |
| find | `findUnscrubbedSecrets` | Scans a string or structured value for surviving known secrets, secret patterns, or unredacted sensitive/identity fields. |
| assert | `assertScrubbed` | Throws `VcrError('unscrubbed_secret')` listing every finding if any secret or identity value survived scrubbing. |

Constants and registries: `REDACTED_UUID`, `REDACTED_EMAIL`, `REDACTED_IP`, `DEFAULT_PLACEHOLDERS`,
`DEFAULT_SECRET_HEADERS`, `DEFAULT_SECRET_QUERY_PARAMS`, `DEFAULT_SECRET_KEY_PATTERN`,
`DEFAULT_IDENTITY_KEY_PATTERN`, `BUILT_IN_SECRET_DETECTORS`.

## HTTP transport (`src/http/`)

| Verb | Name | What it does |
| --- | --- | --- |
| describe | `describeHttpRequest` | Normalizes and scrubs a `fetch` input and `RequestInit` into a deterministic `RecordedHttpRequest`. |
| create | `createVcrFetch` | Creates a drop-in `fetch` implementation backed by queued cassettes on a `VcrRecorder`. |
| create | `createHttpTransport` | Creates a generic HTTP `VcrTransport` for structured request execution via `VcrRecorder.execute`. |

Constants: `DEFAULT_KEPT_RESPONSE_HEADERS`.

## Process transport (`src/process/`)

| Verb | Name | What it does |
| --- | --- | --- |
| create | `createVcrProcessSpawner` | Creates a child-process spawner recording and deterministically replaying stdin/stdout/stderr frames and exit codes. |

Constants: `jsonRpcLineProtocol`.

## WebSocket transport (`src/websocket/`)

| Verb | Name | What it does |
| --- | --- | --- |
| create | `createVcrWebSocketFactory` | Creates a WebSocket factory recording and replaying client sends, server frames, and close events in causal order. |

## Freshness, signatures, drift, and versions (`src/freshness/`)

| Verb | Name | What it does |
| --- | --- | --- |
| look up | `eventKindOf` | Extracts a structural protocol discriminator string for a transcript event or JSON-RPC message. |
| compute | `signatureOfCassette` | Computes a value-independent structural `CassetteSignature` from a cassette status and body or transcript. |
| compare | `compareSignatures` | Returns human-readable non-volatile structural differences between two `CassetteSignature` values. |
| compare | `compareVolatileSignatures` | Returns differences restricted to volatile kinds and paths for non-blocking notices. |
| fetch | `fetchCassettePaths` | Lists sorted cassette JSON file paths under a fixtures directory, excluding `policy.json`. |
| fetch | `fetchPendingCassettes` | Lists all unreviewed `.pending.json` drift cassette paths under a fixtures directory. |
| compare | `diffCassetteDrift` | Computes structural drift between a committed cassette file and a candidate recording file. |
| compare | `diffVolatileCassetteNotices` | Computes non-blocking volatile notice differences between two cassette JSON strings. |
| accept | `acceptPendingCassettes` | Promotes every `.pending.json` drift file under a fixtures directory over its committed cassette and returns the accepted diffs. |
| discard | `discardPendingCassettes` | Deletes every `.pending.json` drift file under a fixtures directory without altering committed cassettes. |
| fetch | `fetchCliVersion` | Invokes a CLI binary to resolve its installed version string matching a semver or custom regex. |
| fetch | `fetchHttpVersion` | Resolves an upstream service version from a URL via custom extractor, response header, or SHA-256 body digest. |
| fetch | `fetchInstalledVersions` | Resolves installed versions for a list of CLI binaries, omitting those not installed in the current environment. |
| compare | `compareVersions` | Compares two numeric dotted version strings (`-1`, `0`, or `1`). |
| look up | `policyPathForDirectory` | Returns the path to `policy.json` inside a fixtures directory. |
| fetch | `fetchFreshnessPolicy` | Reads and validates `policy.json` from a fixtures directory. |
| write | `writeFreshnessPolicy` | Writes a `FreshnessPolicy` JSON file into a fixtures directory. |
| update | `blessFreshnessPolicy` | Raises `policy.blessed` versions to match the newest committed cassettes and optional metadata versions. |
| validate | `validateCassette` | Validates a parsed cassette object structure, returning `{ ok, errors }` with every structural error found. |
| check | `checkCassetteFreshness` | Audits every cassette under a fixtures directory for pending drift, secret leaks, invalid structure, expiry, and stale versions. |
| assert | `assertCassettesFresh` | Throws `VcrError('stale_cassette')` listing all findings if any cassette under a fixtures directory fails freshness checks. |

Constants: `DEFAULT_SIGNATURE_MAX_DEPTH`, `DEFAULT_ID_KEY_PATTERN`, `DEFAULT_VOLATILE_KINDS`,
`DEFAULT_VOLATILE_PATHS`, `DEFAULT_SEMVER_PATTERN`, `PENDING_CASSETTE_SUFFIX`, `POLICY_FILENAME`.

## Exported Types

`VcrErrorCode`, `VcrErrorDetails`, `VcrMode`, `VcrRecordingStamp`, `VcrEntry`, `VcrCassette`,
`VcrResponse`, `VcrMethodSanitizer`, `VcrVersionResolver`, `DriftFinding`, `VcrLiveResult`,
`VcrTransport`, `VcrSessionOptions`, `VcrRecorderOptions`, `ResolveModeOptions`,
`StoreCassetteInput`, `VcrSession`, `ScrubPlaceholderKind`, `ScrubPlaceholderResolver`, `ScrubRule`,
`ScrubContext`, `ScrubOptions`, `LeakFinding`, `HeaderInput`, `Scrubber`, `BuiltInSecretDetector`,
`RecordedHttpRequest`, `HttpCassette`, `HttpCassetteOptions`, `HttpTransportRequest`,
`ProcessFrame`, `ProcessTranscript`, `ProcessSpawnOptions`, `RecordedProcess`, `ProcessLaunch`,
`ProcessLineProtocolSession`, `ProcessLineProtocol`, `ProcessCassetteOptions`, `VcrProcessSpawner`,
`SocketFrame`, `SocketTranscript`, `SocketLike`, `SocketSendData`, `VcrSocketFactory`, `WebSocketCassetteOptions`,
`CassetteSignature`, `SignatureOptions`, `AcceptedDrift`, `FetchCassettePathsOptions`,
`CliVersionOptions`, `HttpVersionOptions`, `FreshnessPolicy`, `FreshnessFindingCode`,
`FreshnessFinding`, `CassetteValidationResult`, `CheckFreshnessOptions`, `BlessPolicyOptions`.
