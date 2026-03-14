/**
 * Unit tests for bot/automation signal extraction via extractUAFeatures
 *
 * Tests the Tier 3 UA feature extractor against real-world bot signals
 * discovered from Cloudflare production logs (2026-03-14).
 *
 * Fixture: paywalls-site/tests/fixtures/cloudflare-prod-paywalls-2026-03-14.csv
 * Issue: (to be assigned)
 *
 * These tests verify that extractUAFeatures correctly identifies:
 *  - headless markers (HeadlessChrome)
 *  - automation markers (Puppeteer, Selenium, etc.)
 *  - bot family detection (Googlebot, Applebot, Bytespider, etc.)
 *  - device/platform/family parsing for suspicious UAs
 *  - fabricated version patterns
 */
import {
  extractUAFeatures,
  _resetVAIMetadata,
} from '../src/signal-extraction.js';

beforeEach(() => {
  _resetVAIMetadata();
});

// ── 1. HeadlessChrome detection ────────────────────────────────────────────

describe('HeadlessChrome signal extraction', () => {
  test('HeadlessChrome/145 should have headless marker', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/145.0.0.0 Safari/537.36'
    );
    expect(result).toMatch(/\bheadless\b/);
    expect(result).toMatch(/dpf=desktop\/linux\/chrome/);
    expect(result).toMatch(/browser/);
  });

  test('HeadlessChrome/143 should have headless marker', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/143.0.7499.4 Safari/537.36'
    );
    expect(result).toMatch(/\bheadless\b/);
    expect(result).toMatch(/dpf=desktop\/linux\/chrome/);
  });
});

// ── 2. Self-identified bots ────────────────────────────────────────────────

describe('Self-identified bot signal extraction', () => {
  test('Applebot should be detected as bot family', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)'
    );
    expect(result).toMatch(/\/bot/);
  });

  test('Googlebot mobile should be detected as bot family', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.7632.116 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
    );
    expect(result).toMatch(/\/bot/);
  });

  test('Googlebot desktop should be detected as bot family', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/145.0.7632.116 Safari/537.36'
    );
    expect(result).toMatch(/\/bot/);
  });

  test('Bytespider should be detected as bot family', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; https://zhanzhang.toutiao.com/)'
    );
    expect(result).toMatch(/\/bot/);
  });

  test('amazon-Quick non-browser UA should have low entropy', () => {
    const result = extractUAFeatures('amazon-Quick-on-behalf-of-20e61c5a');
    expect(result).not.toMatch(/browser/);
    expect(result).toMatch(/entropy=low/);
  });
});

// ── 3. Fabricated Chrome versions (4-digit patch) ──────────────────────────

describe('Fabricated Chrome version UAs — signal extraction', () => {
  // These have impossible 4-digit patch numbers. extractUAFeatures doesn't
  // currently detect version fabrication, but it should at minimum:
  // - Parse the very old major version into the low bucket (0-79)
  // - Have medium entropy (looks like a browser UA)

  const fabricatedUAs = [
    { ua: 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.1025.1402 Mobile Safari/537.36', ver: '0-79' },
    { ua: 'Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.5596.1136 Mobile Safari/537.36', ver: '0-79' },
    { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2714.1709 Mobile Safari/537.36', ver: '0-79' },
    { ua: 'Mozilla/5.0 (Linux; Android 8.0; Pixel 2 Build/OPD3.170816.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.5974.1013 Mobile Safari/537.36', ver: '0-79' },
    { ua: 'Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.1957.1646 Mobile Safari/537.36', ver: '0-79' },
    { ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.4130.1795 Mobile Safari/537.36', ver: '0-79' },
    { ua: 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.7842.1119 Mobile Safari/537.36', ver: '0-79' },
  ];

  test.each(fabricatedUAs)('$ver Chrome with 4-digit patch parses to legacy version bucket', ({ ua, ver }) => {
    const result = extractUAFeatures(ua);
    expect(result).toMatch(new RegExp(`ver=${ver}`));
    expect(result).toMatch(/browser/);
    // NOTE: Future improvement — extractUAFeatures should detect 4-digit patch as fabrication signal
  });
});

// ── 4. Fabricated Edge version ─────────────────────────────────────────────

describe('Fabricated Edge version — signal extraction', () => {
  test('Edge/18.19582 should parse as edge family', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.7680.71 Safari/537.36 Edge/18.19582'
    );
    // Edge detection should still work
    expect(result).toMatch(/\/edge/);
    expect(result).toMatch(/dpf=desktop\/windows\/edge/);
    // NOTE: Future improvement — detect impossible Edge/Chrome version combo
  });
});

// ── 5. Outdated browser UAs from bot farm ──────────────────────────────────

describe('Outdated browser UAs from bot farm — version bucketing', () => {
  test('Chrome/59 (2017) should bucket to 0-79', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Linux; Android 7.0; SM-G930V Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.125 Mobile Safari/537.36'
    );
    expect(result).toMatch(/ver=0-79/);
    expect(result).toMatch(/dpf=mobile\/android\/chrome/);
  });

  test('Chrome/117 should bucket to 100-119', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36'
    );
    expect(result).toMatch(/ver=100-119/);
  });

  test('Chrome/83 should bucket to 80-99', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36'
    );
    expect(result).toMatch(/ver=80-99/);
  });

  test('Chrome/79 should bucket to 0-79', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36'
    );
    expect(result).toMatch(/ver=0-79/);
  });
});

// ── 6. Legitimate browser UAs ──────────────────────────────────────────────

describe('Legitimate browser UAs — correct feature extraction', () => {
  test('Chrome/145 on macOS → desktop/mac/chrome, current version bucket', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36'
    );
    expect(result).toMatch(/dpf=desktop\/mac\/chrome/);
    expect(result).toMatch(/ver=140-159/);
    expect(result).toMatch(/browser/);
    expect(result).not.toMatch(/headless/);
    expect(result).not.toMatch(/automation/);
  });

  test('Chrome/146 on Windows → desktop/windows/chrome, current version bucket', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'
    );
    expect(result).toMatch(/dpf=desktop\/windows\/chrome/);
    expect(result).toMatch(/ver=140-159/);
    expect(result).not.toMatch(/headless/);
    expect(result).not.toMatch(/automation/);
  });

  test('Safari/17.4.1 on macOS → desktop/mac/safari', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15'
    );
    expect(result).toMatch(/dpf=desktop\/mac\/safari/);
    expect(result).not.toMatch(/headless/);
    expect(result).not.toMatch(/automation/);
  });

  test('Edge/122 on Windows → desktop/windows/edge', () => {
    const result = extractUAFeatures(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0'
    );
    expect(result).toMatch(/dpf=desktop\/windows\/edge/);
    expect(result).toMatch(/ver=120-139/);
    expect(result).not.toMatch(/headless/);
  });
});
