import { describe, expect, test } from 'bun:test';
import { tmpdir } from 'node:os';
import { isVcrError } from '../src/core/errors';
import {
  accountHomeDirectory,
  assertScrubbed,
  createScrubber,
  findUnscrubbedSecrets,
  REDACTED_EMAIL,
  REDACTED_IP,
  REDACTED_UUID,
  rehydratePlaceholders,
  scrubHeaders,
  scrubLine,
  scrubText,
  scrubUrl,
  scrubValue,
} from '../src/scrub/index';

describe('standalone @inixiative/vcr/scrub', () => {
  test('scrubs all built-in provider token prefixes, JWTs, PEM keys, auth schemes, and DB URLs', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const pem = [
      '-----BEGIN RSA PRIVATE KEY-----',
      'MIIEowIBAAKCAQEAt0xFakeKeyBody1234567890',
      '-----END RSA PRIVATE KEY-----',
    ].join('\n');

    const samples = [
      ['anthropic', 'sk-ant-api03-abcdefghijklmnop', '<REDACTED:ANTHROPIC_KEY>'],
      ['openai proj', 'sk-proj-abcdefghijklmnopqrstuvwxyz', '<REDACTED:OPENAI_KEY>'],
      ['openai', 'sk-abcdefghijklmnopqrstuvwxyz1234', '<REDACTED:OPENAI_KEY>'],
      ['ghp', 'ghp_1234567890abcdefghijklmnop', '<REDACTED:GITHUB_TOKEN>'],
      ['gho', 'gho_1234567890abcdefghijklmnop', '<REDACTED:GITHUB_TOKEN>'],
      ['ghu', 'ghu_1234567890abcdefghijklmnop', '<REDACTED:GITHUB_TOKEN>'],
      ['ghs', 'ghs_1234567890abcdefghijklmnop', '<REDACTED:GITHUB_TOKEN>'],
      ['ghr', 'ghr_1234567890abcdefghijklmnop', '<REDACTED:GITHUB_TOKEN>'],
      ['github_pat', 'github_pat_11AAABBBCCC_0123456789abcdef', '<REDACTED:GITHUB_TOKEN>'],
      ['google', 'AIzaSyA1234567890abcdefghijklmnopqrstuv', '<REDACTED:GOOGLE_KEY>'],
      ['slack bot', 'xoxb-1234567890-abcdefghijkl', '<REDACTED:SLACK_TOKEN>'],
      ['slack user', 'xoxp-1234567890-abcdefghijkl', '<REDACTED:SLACK_TOKEN>'],
      ['slack enterprise', 'xoxe-1234567890-abcdefghijkl', '<REDACTED:SLACK_TOKEN>'],
      ['render', 'rnd_1234567890abcdefghij', '<REDACTED:RENDER_TOKEN>'],
      ['fly fo1', 'fo1_1234567890abcdefghij', '<REDACTED:FLY_TOKEN>'],
      ['fly v1', 'FlyV1 fm2_lJPECAAAAAA1234567890', 'FlyV1 <REDACTED:FLY_TOKEN>'],
      [
        'kingdom run',
        'kingdom_run_abcdefghijklmnopqrstuvwxyz0123456789ABC',
        '<REDACTED:KINGDOM_TOKEN>',
      ],
      [
        'kingdom plain',
        'kingdom_abcdefghijklmnopqrstuvwxyz0123456789ABC',
        '<REDACTED:KINGDOM_TOKEN>',
      ],
      ['aws akia', 'AKIAIOSFODNN7EXAMPLE', '<REDACTED:AWS_KEY>'],
      ['aws asia', 'ASIAIOSFODNN7EXAMPLE', '<REDACTED:AWS_KEY>'],
      ['bearer', 'Bearer mySecretToken1234567890', 'Bearer <REDACTED:BEARER>'],
      ['basic', 'Basic dXNlcjpwYXNzd29yZA==', 'Basic <REDACTED:BASIC>'],
      ['jwt', jwt, '<REDACTED:JWT>'],
      ['pem', pem, '<REDACTED:PRIVATE_KEY>'],
      [
        'postgres url',
        'postgres://appuser:s3cr3tP@ss@db.internal:5432/prod',
        'postgres://appuser:<REDACTED:URL_CREDENTIAL>@db.internal:5432/prod',
      ],
      [
        'redis url',
        'redis://:redisSecret123@cache.internal:6379/0',
        'redis://:<REDACTED:URL_CREDENTIAL>@cache.internal:6379/0',
      ],
      [
        'amqp url',
        'amqp://broker:amqpPass99@mq.internal:5672/vhost',
        'amqp://broker:<REDACTED:URL_CREDENTIAL>@mq.internal:5672/vhost',
      ],
    ] as const;

    for (const [label, raw, expected] of samples) {
      const scrubbed = scrubText(`prefix ${raw} suffix`);
      expect(scrubbed, label).toBe(`prefix ${expected} suffix`);
      expect(findUnscrubbedSecrets(scrubbed), label).toEqual([]);
      // Idempotency: scrubbing twice yields the exact same deterministic output.
      expect(scrubText(scrubbed), `${label} idempotent`).toBe(scrubbed);
    }
  });

  test('scrubs sensitive HTTP headers case-insensitively and sorts keys deterministically', () => {
    const scrubbed = scrubHeaders({
      'X-Goog-Api-Key': 'AIzaSyA1234567890abcdefghijklmnopqrstuv',
      Authorization: 'Bearer live-token-9876543210',
      'Proxy-Authorization': 'Basic dXNlcjpwYXNz',
      Cookie: 'session=abc123; theme=dark',
      'Set-Cookie': 'session=xyz789; HttpOnly',
      'X-Api-Key': 'plain-key',
      'X-Amz-Security-Token': 'IQoJb3JpZ2luX2Vj',
      'Stripe-Signature': 't=12345,v1=deadbeef',
      'Content-Type': 'application/json',
    });

    expect(Object.keys(scrubbed)).toEqual([
      'authorization',
      'content-type',
      'cookie',
      'proxy-authorization',
      'set-cookie',
      'stripe-signature',
      'x-amz-security-token',
      'x-api-key',
      'x-goog-api-key',
    ]);
    expect(scrubbed).toEqual({
      authorization: 'Bearer <REDACTED:BEARER>',
      'content-type': 'application/json',
      cookie: '<REDACTED:HEADER_SECRET>',
      'proxy-authorization': 'Basic <REDACTED:BASIC>',
      'set-cookie': '<REDACTED:HEADER_SECRET>',
      'stripe-signature': '<REDACTED:HEADER_SECRET>',
      'x-amz-security-token': '<REDACTED:HEADER_SECRET>',
      'x-api-key': '<REDACTED:HEADER_SECRET>',
      'x-goog-api-key': '<REDACTED:HEADER_SECRET>',
    });
    expect(findUnscrubbedSecrets(scrubbed)).toEqual([]);
  });

  test('scrubs secret URL query params, sorts params deterministically, and preserves non-secret params', () => {
    const scrubbed = scrubUrl(
      'https://api.example.com/v1/items?z=last&api_key=rawkey&token=tok1&access_token=at1&refresh_token=rt1&secret=s1&password=p1&sig=sg1&signature=sg2&x-amz-signature=amz1&client_secret=cs1&key=k1&apikey=ak1&a=first',
    );
    expect(scrubbed).toBe(
      'https://api.example.com/v1/items?a=first&access_token=<REDACTED:QUERY_SECRET>&api_key=<REDACTED:QUERY_SECRET>&apikey=<REDACTED:QUERY_SECRET>&client_secret=<REDACTED:QUERY_SECRET>&key=<REDACTED:QUERY_SECRET>&password=<REDACTED:QUERY_SECRET>&refresh_token=<REDACTED:QUERY_SECRET>&secret=<REDACTED:QUERY_SECRET>&sig=<REDACTED:QUERY_SECRET>&signature=<REDACTED:QUERY_SECRET>&token=<REDACTED:QUERY_SECRET>&x-amz-signature=<REDACTED:QUERY_SECRET>&z=last',
    );
    expect(findUnscrubbedSecrets(scrubbed)).toEqual([]);
  });

  test('replaces explicit knownSecrets BEFORE regexes, including malformed and URL-encoded literals', () => {
    const weirdSecret = 'my!weird/secret=42';
    const scrubber = createScrubber({ knownSecrets: [weirdSecret, 'tiny'] });

    const text = `raw=${weirdSecret} encoded=${encodeURIComponent(weirdSecret)} short=tiny`;
    const scrubbed = scrubber.scrubText(text);
    expect(scrubbed).toBe(
      'raw=<REDACTED:SECRET> encoded=<REDACTED:SECRET> short=<REDACTED:SECRET>',
    );
    expect(scrubber.findUnscrubbedSecrets(scrubbed)).toEqual([]);

    // Leak detector catches surviving raw or URL-encoded knownSecrets.
    expect(scrubber.findUnscrubbedSecrets(`leaked ${weirdSecret}`)).toEqual([
      expect.objectContaining({ kind: 'known_secret' }),
    ]);
    expect(scrubber.findUnscrubbedSecrets(`leaked ${encodeURIComponent(weirdSecret)}`)).toEqual([
      expect.objectContaining({ kind: 'known_secret' }),
    ]);
  });

  test('handles recursive, cycle-safe objects, arrays, Maps, Sets, URLs, Headers, and Errors', () => {
    const node: Record<string, unknown> = {
      name: 'public',
      email: 'alice@company.com',
      account: {
        uuid: '0f8fad5b-d9cb-469f-a165-70867728950e',
        name: 'Alice',
        nested: { display: 'Secret Corp' },
      },
      headers: new Headers({ authorization: 'Bearer secret12345678', accept: 'application/json' }),
      dbUrl: new URL('postgres://admin:pass123@db.local:5432/app'),
      map: new Map([
        ['password', 'topsecret'],
        ['safe', 'ok'],
      ]),
      set: new Set(['sk-ant-api03-abcdefghijklmnop', 'clean']),
      err: new Error('failed with ghp_1234567890abcdefghijklmnop'),
    };
    node.self = node;

    const scrubbed = scrubValue(node) as Record<string, unknown>;
    expect(scrubbed.self).toBe('<CIRCULAR>');
    expect(scrubbed.email).toBe(REDACTED_EMAIL);
    expect(scrubbed.account).toEqual({
      uuid: REDACTED_UUID,
      name: '<REDACTED:SECRET>',
      nested: { display: '<REDACTED:SECRET>' },
    });
    expect(scrubbed.headers).toEqual({
      accept: 'application/json',
      authorization: 'Bearer <REDACTED:BEARER>',
    });
    expect(scrubbed.dbUrl).toBe('postgres://admin:<REDACTED:URL_CREDENTIAL>@db.local:5432/app');
    expect((scrubbed.map as Map<string, string>).get('password')).toBe('<REDACTED:SECRET>');
    expect((scrubbed.map as Map<string, string>).get('safe')).toBe('ok');
    expect([...(scrubbed.set as Set<string>)]).toEqual(['<REDACTED:ANTHROPIC_KEY>', 'clean']);
    expect((scrubbed.err as { message: string }).message).toBe(
      'failed with <REDACTED:GITHUB_TOKEN>',
    );
    expect(findUnscrubbedSecrets(scrubbed)).toEqual([]);
  });

  test('supports optional email, IP, UUID normalizers, custom placeholders, and custom ScrubRules', () => {
    const scrubber = createScrubber({
      scrubEmails: true,
      scrubIps: true,
      scrubUuids: true,
      placeholderFor: (kind) =>
        kind === 'bearer' ? 'CUSTOM_BEARER' : `<MASK:${kind.toUpperCase()}>`,
      rules: [
        {
          id: 'internal_ticket',
          pattern: /\bTICKET-\d{4,}\b/g,
          placeholder: '<REDACTED:TICKET>',
        },
      ],
    });

    const out = scrubber.scrubText(
      'from 192.168.1.42 id 0f8fad5b-d9cb-469f-a165-70867728950e auth Bearer abcdefgh1234 ref TICKET-9981',
    );
    expect(out).toBe(
      'from <MASK:IP> id <MASK:UUID> auth Bearer CUSTOM_BEARER ref <REDACTED:TICKET>',
    );
    expect(scrubber.findUnscrubbedSecrets(out)).toEqual([]);
    expect(scrubber.findUnscrubbedSecrets('leaked TICKET-4242')).toEqual([
      expect.objectContaining({ kind: 'internal_ticket' }),
    ]);

    const ipScrubber = createScrubber({ scrubIps: true, scrubUuids: true });
    expect(ipScrubber.scrubText('ip 10.0.0.5 uuid 0f8fad5b-d9cb-469f-a165-70867728950e')).toBe(
      `ip ${REDACTED_IP} uuid ${REDACTED_UUID}`,
    );
  });

  test('normalizes local paths and rehydrates placeholders deterministically', () => {
    const home = accountHomeDirectory();
    const cwd = '/tmp/my-test-project';
    const line = scrubLine(
      JSON.stringify({ homePath: `${home}/repo`, cwdPath: `${cwd}/src`, tmpPath: `${tmpdir()}/x` }),
      { context: { cwd } },
    );
    expect(JSON.parse(line)).toEqual({
      homePath: '~/repo',
      cwdPath: '{{cwd}}/src',
      tmpPath: '{{tmp}}/x',
    });
    expect(rehydratePlaceholders(line, { cwd: '/var/replay-dir' })).toContain(
      '/var/replay-dir/src',
    );
  });

  test('assertScrubbed throws VcrError(unscrubbed_secret) listing all findings without echoing raw secret values', () => {
    const rawSecret = 'sk-ant-api03-SUPERSECRETVALUE9999';
    let caught: unknown;
    try {
      assertScrubbed(
        {
          note: `key ${rawSecret}`,
          nested: { orgName: 'Secret Corp', email: 'bob@secret.org' },
        },
        { label: 'example.json' },
      );
    } catch (error) {
      caught = error;
    }

    expect(isVcrError(caught, 'unscrubbed_secret')).toBe(true);
    const err = caught as Error;
    expect(err.message).toContain('example.json');
    expect(err.message).not.toContain(rawSecret);
    expect(err.message).not.toContain('Secret Corp');
    expect(err.message).not.toContain('bob@secret.org');
  });
});
