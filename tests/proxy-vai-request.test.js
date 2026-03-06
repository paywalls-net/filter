/**
 * Tests for proxyVAIRequest() signal extraction pipeline (§7).
 *
 * Verifies that VAI proxy requests emit compact SF headers (v2 protocol)
 * instead of raw header passthrough.
 *
 * Issue: paywalls-site-qiw
 * Spec: specs/vai-privacy-v2.spec.md §7, §8.1.2
 */
import { init } from '../src/index.js';

// ── Test helpers ───────────────────────────────────────────────────────────

/** Captured headers from the last fetch call */
let capturedFetchArgs = null;

/** Mock Response returned by fetch */
const MOCK_RESPONSE = {
  ok: true,
  status: 200,
  statusText: 'OK',
  body: 'mock-body',
  headers: new Headers({ 'content-type': 'application/json' }),
};

/**
 * Build a minimal Request-like object that proxyVAIRequest expects.
 * Mimics Cloudflare Workers Request shape.
 */
function makeRequest(url, headerMap = {}, cf = {}) {
  const headers = new Headers(headerMap);
  return {
    url,
    method: 'GET',
    headers,
    cf,
  };
}

// ── Setup/teardown ─────────────────────────────────────────────────────────

const originalFetch = globalThis.fetch;

beforeEach(() => {
  capturedFetchArgs = null;
  globalThis.fetch = async (url, opts) => {
    capturedFetchArgs = { url, ...opts };
    return MOCK_RESPONSE;
  };
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

// ── Env config ─────────────────────────────────────────────────────────────

const ENV = {
  PAYWALLS_CLOUD_API_HOST: 'https://test-cloud-api.example.com',
  PAYWALLS_CLOUD_API_KEY: 'test-key-123',
  PAYWALLS_PUBLISHER_ID: 'pub-123',
  VAI_UA_HMAC_KEY: 'test-hmac-secret',
};

const CTX = { waitUntil: () => {} };

// Chrome on Mac — typical browser request
const CHROME_MAC_HEADERS = {
  'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
  'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'accept-encoding': 'gzip, deflate, br, zstd',
  'accept-language': 'en-US,en;q=0.9,fr;q=0.8',
  'sec-ch-ua': '"Google Chrome";v="134", "Chromium";v="134", "Not:A-Brand";v="24"',
  'sec-fetch-dest': 'empty',
  'sec-fetch-mode': 'cors',
  'sec-fetch-site': 'same-origin',
  'host': 'publisher.example.com',
  'origin': 'https://publisher.example.com',
  'cookie': 'session=abc123',
};

const CF_PROPS = {
  tlsVersion: 'TLSv1.3',
  httpProtocol: 'HTTP/2',
  asn: 7922, // Comcast — consumer
};

// ── Tests ──────────────────────────────────────────────────────────────────

describe('proxyVAIRequest — signal extraction pipeline', () => {
  let handler;

  beforeAll(async () => {
    handler = await init('cloudflare');
  });

  async function proxyVAI(url, headerMap, cf) {
    const request = makeRequest(url, headerMap, cf);
    await handler(request, ENV, CTX);
    return capturedFetchArgs;
  }

  // ── Protocol version ─────────────────────────────────────────────────

  test('emits X-PW-V: 2', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-V']).toBe('2');
  });

  // ── User-Agent replacement ───────────────────────────────────────────

  test('User-Agent is SDK identifier, not browser UA', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['User-Agent']).toMatch(/^pw-filter-sdk\//);
    expect(args.headers['User-Agent']).not.toContain('Chrome');
  });

  // ── Tier 1: raw headers ──────────────────────────────────────────────

  test('Tier 1: Sec-Fetch headers forwarded raw', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-Sec-Fetch-Dest']).toBe('empty');
    expect(args.headers['X-PW-Sec-Fetch-Mode']).toBe('cors');
    expect(args.headers['X-PW-Sec-Fetch-Site']).toBe('same-origin');
  });

  test('Tier 1: TLS and HTTP protocol from cf object', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-TLS-Version']).toBe('TLSv1.3');
    expect(args.headers['X-PW-HTTP-Protocol']).toBe('HTTP/2');
  });

  // ── Tier 2: extracted features ───────────────────────────────────────

  test('X-PW-Accept is SF-Dictionary (not raw Accept header)', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-Accept']).toBe('html, wildcard');
  });

  test('X-PW-Enc is SF-Dictionary', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-Enc']).toBe('br, gzip, modern');
  });

  test('X-PW-Lang is SF-Dictionary', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-Lang']).toBe('present, primary=en, count=3');
  });

  test('X-PW-Net classifies consumer ASN', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-Net']).toBe('asn=consumer');
  });

  test('X-PW-Net classifies cloud ASN (AWS)', async () => {
    const cloudCf = { ...CF_PROPS, asn: 16509 };
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, cloudCf);
    expect(args.headers['X-PW-Net']).toBe('asn=cloud');
  });

  test('X-PW-CH is SF-Dictionary with consistency check', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-CH']).toBe('present, brands=3, grease, consistent');
  });

  // ── Tier 3: UA features + HMAC ──────────────────────────────────────

  test('X-PW-UA is SF-Dictionary', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-UA']).toBe('dpf=desktop/mac/chrome, ver=120-139, browser, entropy=medium');
  });

  test('X-PW-UA-HMAC is RFC 8941 Byte Sequence', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-UA-HMAC']).toMatch(/^:[A-Za-z0-9+/]+=*:$/);
  });

  test('X-PW-CT-FP is 8-char hex confidence token', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-PW-CT-FP']).toMatch(/^[0-9a-f]{8}$/);
  });

  // ── Old headers NOT present ──────────────────────────────────────────

  test('old raw headers are NOT forwarded', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    // v1 header names that should no longer appear
    expect(args.headers['X-PW-Accept-Language']).toBeUndefined();
    expect(args.headers['X-PW-Accept-Encoding']).toBeUndefined();
    expect(args.headers['X-PW-Sec-CH-UA']).toBeUndefined();
    expect(args.headers['X-PW-ASN']).toBeUndefined();
  });

  // ── Operational headers still present ────────────────────────────────

  test('operational headers forwarded (Host, Origin, Cookie)', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['X-Original-Host']).toBe('publisher.example.com');
    expect(args.headers['X-Forwarded-Origin']).toBe('https://publisher.example.com');
    expect(args.headers['Cookie']).toBe('session=abc123');
  });

  test('Authorization header present', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.headers['Authorization']).toBe('Bearer test-key-123');
  });

  // ── Absent inputs → headers omitted ──────────────────────────────────

  test('missing Accept-Language → X-PW-Lang omitted', async () => {
    const { 'accept-language': _, ...noLang } = CHROME_MAC_HEADERS;
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', noLang, CF_PROPS);
    expect(args.headers['X-PW-Lang']).toBeUndefined();
  });

  test('missing Sec-CH-UA → X-PW-CH omitted', async () => {
    const { 'sec-ch-ua': _, ...noCH } = CHROME_MAC_HEADERS;
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', noCH, CF_PROPS);
    expect(args.headers['X-PW-CH']).toBeUndefined();
  });

  test('missing cf.asn → X-PW-Net omitted', async () => {
    const noCf = {};
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, noCf);
    expect(args.headers['X-PW-Net']).toBeUndefined();
  });

  test('no HMAC key → X-PW-UA-HMAC omitted', async () => {
    // Temporarily override ENV to remove HMAC key
    const noHmacEnv = { ...ENV, VAI_UA_HMAC_KEY: undefined };
    const noHmacHandler = await init('cloudflare');
    const request = makeRequest('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    await noHmacHandler(request, noHmacEnv, CTX);
    expect(capturedFetchArgs.headers['X-PW-UA-HMAC']).toBeUndefined();
  });

  // ── curl (minimal headers) ──────────────────────────────────────────

  test('curl request — minimal headers, automation detected', async () => {
    const curlHeaders = {
      'user-agent': 'curl/7.88.1',
      'accept': '*/*',
      'host': 'publisher.example.com',
    };
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', curlHeaders, {});
    expect(args.headers['X-PW-V']).toBe('2');
    expect(args.headers['X-PW-Accept']).toBe('wildcard');
    expect(args.headers['X-PW-UA']).toMatch(/automation/);
    expect(args.headers['X-PW-UA']).toMatch(/entropy=low/);
    // No language, encoding, CH, net
    expect(args.headers['X-PW-Lang']).toBeUndefined();
    expect(args.headers['X-PW-Enc']).toBeUndefined();
    expect(args.headers['X-PW-CH']).toBeUndefined();
    expect(args.headers['X-PW-Net']).toBeUndefined();
  });

  // ── Proxies to correct URL ──────────────────────────────────────────

  test('proxies to cloud-api host with original path', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json?v=2', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args.url).toBe('https://test-cloud-api.example.com/pw/vai.json?v=2');
  });

  // ── Deterministic HMAC and CT ────────────────────────────────────────

  test('HMAC is deterministic for same UA + key', async () => {
    const args1 = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    const args2 = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args1.headers['X-PW-UA-HMAC']).toBe(args2.headers['X-PW-UA-HMAC']);
  });

  test('confidence token is deterministic for same inputs', async () => {
    const args1 = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    const args2 = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    expect(args1.headers['X-PW-CT-FP']).toBe(args2.headers['X-PW-CT-FP']);
  });

  // ── All 14 signal headers present (Chrome full) ──────────────────────────

  test('Chrome full request — all 14 X-PW signal headers emitted', async () => {
    const args = await proxyVAI('https://pub.example.com/pw/vai.json', CHROME_MAC_HEADERS, CF_PROPS);
    const xpwHeaders = Object.keys(args.headers).filter(k => k.startsWith('X-PW-'));
    expect(xpwHeaders).toHaveLength(14);
    expect(xpwHeaders).toEqual(expect.arrayContaining([
      'X-PW-V',
      'X-PW-Sec-Fetch-Dest', 'X-PW-Sec-Fetch-Mode', 'X-PW-Sec-Fetch-Site',
      'X-PW-TLS-Version', 'X-PW-HTTP-Protocol',
      'X-PW-Accept', 'X-PW-Enc', 'X-PW-Lang', 'X-PW-Net', 'X-PW-CH',
      'X-PW-UA', 'X-PW-UA-HMAC', 'X-PW-CT-FP',
    ]));
  });
});

// ── logAccess — non-VAI path raw header forwarding ───────────────────────────
//
// Verifies that logAccess() does NOT transform headers like proxyVAIRequest().
// The access-log body must contain the raw browser User-Agent (not the SDK
// sentinel) and must NOT contain any X-PW-* signal headers.

describe('logAccess — non-VAI path forwards raw user-agent in body', () => {
  let handler;
  let fetchCalls;

  beforeAll(async () => {
    handler = await init('cloudflare');
  });

  beforeEach(() => {
    fetchCalls = [];
    globalThis.fetch = async (url, opts) => {
      const call = { url, ...opts };
      fetchCalls.push(call);
      if (String(url).includes('/agents/metadata')) {
        // loadAgentPatterns — return empty pattern list
        return {
          ok: true,
          json: async () => ({ version: 2, patterns: [] }),
        };
      }
      if (String(url).includes('/agents/auth')) {
        // checkAgentStatus — allow the bot through so logAccess is called
        return {
          ok: true,
          json: async () => ({ access: 'allow', reason: 'known_bot', response: { code: 200, headers: {} } }),
        };
      }
      // logAccess POST /access/logs
      return { ok: true, status: 200, statusText: 'OK' };
    };
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
  });

  test('logAccess body contains raw user-agent, not SDK identifier', async () => {
    const browserUA = CHROME_MAC_HEADERS['user-agent'];
    // ?user-agent=testbot triggers isTestBot() → bot path → checkAgentStatus + logAccess
    const request = makeRequest(
      'https://pub.example.com/article/1?user-agent=testbot',
      CHROME_MAC_HEADERS,
      CF_PROPS,
    );
    let logPromise;
    const ctx = { waitUntil: (p) => { logPromise = p; } };

    await handler(request, ENV, ctx);
    if (logPromise) await logPromise;

    const logCall = fetchCalls.find(c => String(c.url).includes('/access/logs'));
    expect(logCall).toBeDefined();
    const body = JSON.parse(logCall.body);

    expect(body.user_agent).toBe(browserUA);
    expect(body.user_agent).not.toMatch(/^pw-filter-sdk\//);
  });

  test('logAccess body headers contain no X-PW-* signal headers', async () => {
    const request = makeRequest(
      'https://pub.example.com/article/2?user-agent=testbot',
      CHROME_MAC_HEADERS,
      CF_PROPS,
    );
    let logPromise;
    const ctx = { waitUntil: (p) => { logPromise = p; } };

    await handler(request, ENV, ctx);
    if (logPromise) await logPromise;

    const logCall = fetchCalls.find(c => String(c.url).includes('/access/logs'));
    expect(logCall).toBeDefined();
    const body = JSON.parse(logCall.body);

    const xpwKeysInLog = Object.keys(body.headers || {}).filter(
      k => k.toLowerCase().startsWith('x-pw-'),
    );
    expect(xpwKeysInLog).toHaveLength(0);
  });
});
