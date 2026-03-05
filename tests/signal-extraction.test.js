/**
 * Unit tests for Tier 2 signal extraction functions
 *
 * Spec: specs/vai-privacy-v2.spec.md §6.2.1–§6.2.5
 */
import {
  extractAcceptFeatures,
  extractEncodingFeatures,
  extractLanguageFeatures,
  extractNetFeatures,
  extractCHFeatures,
} from '../src/signal-extraction.js';

// ── §6.2.1  extractAcceptFeatures ──────────────────────────────────────────

describe('extractAcceptFeatures', () => {
  test('typical browser Accept → html, wildcard', () => {
    expect(extractAcceptFeatures('text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'))
      .toBe('html, wildcard');
  });

  test('API client → json', () => {
    expect(extractAcceptFeatures('application/json')).toBe('json');
  });

  test('curl default → wildcard', () => {
    expect(extractAcceptFeatures('*/*')).toBe('wildcard');
  });

  test('image request → image', () => {
    expect(extractAcceptFeatures('image/webp,image/apng,image/*,*/*;q=0.8'))
      .toBe('wildcard, image');
  });

  test('combined html + json + wildcard', () => {
    expect(extractAcceptFeatures('text/html, application/json, */*'))
      .toBe('html, wildcard, json');
  });

  test('null input → null', () => {
    expect(extractAcceptFeatures(null)).toBeNull();
  });

  test('undefined input → null', () => {
    expect(extractAcceptFeatures(undefined)).toBeNull();
  });

  test('empty string → null', () => {
    expect(extractAcceptFeatures('')).toBeNull();
  });

  test('unrecognized type only → null', () => {
    expect(extractAcceptFeatures('application/xml')).toBeNull();
  });
});

// ── §6.2.2  extractEncodingFeatures ────────────────────────────────────────

describe('extractEncodingFeatures', () => {
  test('modern browser → br, gzip, modern', () => {
    expect(extractEncodingFeatures('gzip, deflate, br, zstd'))
      .toBe('br, gzip, modern');
  });

  test('gzip only → gzip (no modern)', () => {
    expect(extractEncodingFeatures('gzip, deflate')).toBe('gzip');
  });

  test('br only → br (no modern)', () => {
    expect(extractEncodingFeatures('br')).toBe('br');
  });

  test('null → null', () => {
    expect(extractEncodingFeatures(null)).toBeNull();
  });

  test('empty string → null', () => {
    expect(extractEncodingFeatures('')).toBeNull();
  });

  test('deflate only (no br/gzip) → null', () => {
    expect(extractEncodingFeatures('deflate')).toBeNull();
  });
});

// ── §6.2.3  extractLanguageFeatures ────────────────────────────────────────

describe('extractLanguageFeatures', () => {
  test('typical browser → present, primary=en, count=3', () => {
    expect(extractLanguageFeatures('en-US,en;q=0.9,fr;q=0.8'))
      .toBe('present, primary=en, count=3');
  });

  test('single locale → count=1', () => {
    expect(extractLanguageFeatures('ja'))
      .toBe('present, primary=ja, count=1');
  });

  test('primary with region → primary extracts 2-char family', () => {
    expect(extractLanguageFeatures('fr-FR'))
      .toBe('present, primary=fr, count=1');
  });

  test('wildcard only → null (not a real locale)', () => {
    expect(extractLanguageFeatures('*')).toBeNull();
  });

  test('null → null', () => {
    expect(extractLanguageFeatures(null)).toBeNull();
  });

  test('empty string → null', () => {
    expect(extractLanguageFeatures('')).toBeNull();
  });

  test('whitespace only → null', () => {
    expect(extractLanguageFeatures('   ')).toBeNull();
  });

  test('Chinese locale → primary=zh', () => {
    expect(extractLanguageFeatures('zh-CN,zh;q=0.9,en;q=0.8'))
      .toBe('present, primary=zh, count=3');
  });
});

// ── §6.2.4  extractNetFeatures ─────────────────────────────────────────────

describe('extractNetFeatures', () => {
  // ── Classification boundary ────────────────────────────────────────────
  test('well-known cloud ASN (AWS) → asn=cloud', () => {
    expect(extractNetFeatures('16509')).toBe('asn=cloud');
  });

  test('well-known consumer ISP (Comcast) → asn=consumer', () => {
    expect(extractNetFeatures('7922')).toBe('asn=consumer');
  });

  // ── Input type handling ────────────────────────────────────────────────
  test('numeric input (number, not string) → works', () => {
    expect(extractNetFeatures(16509)).toBe('asn=cloud');
  });

  test('string number for consumer → works', () => {
    expect(extractNetFeatures('7018')).toBe('asn=consumer');
  });

  test('null → null', () => {
    expect(extractNetFeatures(null)).toBeNull();
  });

  test('undefined → null', () => {
    expect(extractNetFeatures(undefined)).toBeNull();
  });

  test('empty string → null', () => {
    expect(extractNetFeatures('')).toBeNull();
  });

  test('non-numeric string → null', () => {
    expect(extractNetFeatures('abc')).toBeNull();
  });
});

// ── §6.2.5  extractCHFeatures ──────────────────────────────────────────────

describe('extractCHFeatures', () => {
  const CHROME_134_CH = '"Google Chrome";v="134", "Chromium";v="134", "Not:A-Brand";v="24"';
  const CHROME_134_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36';

  test('Chrome 134 with matching UA → present, brands=3, grease, consistent', () => {
    expect(extractCHFeatures(CHROME_134_CH, CHROME_134_UA))
      .toBe('present, brands=3, grease, consistent');
  });

  test('version mismatch → no consistent', () => {
    const mismatchUA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/120.0.0.0 Safari/537.36';
    expect(extractCHFeatures(CHROME_134_CH, mismatchUA))
      .toBe('present, brands=3, grease');
  });

  test('no User-Agent → present but no consistent', () => {
    expect(extractCHFeatures(CHROME_134_CH, null))
      .toBe('present, brands=3, grease');
  });

  test('CH without GREASE brand', () => {
    const noGrease = '"Google Chrome";v="134", "Chromium";v="134"';
    expect(extractCHFeatures(noGrease, CHROME_134_UA))
      .toBe('present, brands=2, consistent');
  });

  test('null CH → null (Firefox, etc.)', () => {
    expect(extractCHFeatures(null, CHROME_134_UA)).toBeNull();
  });

  test('empty CH → null', () => {
    expect(extractCHFeatures('', CHROME_134_UA)).toBeNull();
  });

  test('whitespace-only CH → null', () => {
    expect(extractCHFeatures('   ', CHROME_134_UA)).toBeNull();
  });

  test('Edge CH (different brand name) with Chromium match', () => {
    const edgeCH = '"Microsoft Edge";v="134", "Chromium";v="134", "Not-A.Brand";v="99"';
    const edgeUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0';
    expect(extractCHFeatures(edgeCH, edgeUA))
      .toBe('present, brands=3, grease, consistent');
  });
});
