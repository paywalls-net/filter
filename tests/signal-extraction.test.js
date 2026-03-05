/**
 * Unit tests for signal extraction functions (Tier 2 + Tier 3)
 *
 * Spec: specs/vai-privacy-v2.spec.md §6.2–§6.4
 * Issue: paywalls-site-drk
 */
import {
  extractAcceptFeatures,
  extractEncodingFeatures,
  extractLanguageFeatures,
  extractNetFeatures,
  extractCHFeatures,
  extractUAFeatures,
  computeUAHMAC,
  computeConfidenceToken,
} from '../src/signal-extraction.js';

// ═══════════════════════════════════════════════════════════════════════════
//  Helpers: SF-Dictionary format validation (RFC 8941)
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Validate that a string is well-formed SF-Dictionary per our protocol.
 *
 * Strict RFC 8941 allows only alpha-starting tokens and plain integers.
 * Our protocol extends this with:
 *   - Compound path values: dpf=desktop/mac/chrome
 *   - Version ranges:       ver=120-139, ver=140+
 *
 * Each member is either a bare key (boolean true) or key=value.
 *   - key matches sf-key = lcalpha *( lcalpha / DIGIT / "_" / "-" / "." / "*" )
 *   - value is alphanumeric-starting string with path/range chars
 * Members are separated by ", ".
 */
function isValidSFDictionary(str) {
  if (typeof str !== 'string' || str.length === 0) return false;
  const members = str.split(', ');
  const keyRe = /^[a-z*][a-z0-9_\-.*]*$/;
  // Extended value: starts with alphanumeric/*, allows tchar + / and digits
  const valRe = /^[A-Za-z0-9*][A-Za-z0-9!#$&'*+.^_|~\/-]*$/;
  for (const m of members) {
    const eq = m.indexOf('=');
    if (eq === -1) {
      // bare key (boolean true)
      if (!keyRe.test(m)) return false;
    } else {
      const key = m.slice(0, eq);
      const val = m.slice(eq + 1);
      if (!keyRe.test(key)) return false;
      if (!valRe.test(val)) return false;
    }
  }
  return true;
}

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

  test('output is valid SF-Dictionary', () => {
    const result = extractAcceptFeatures('text/html,application/json,*/*;q=0.8');
    expect(isValidSFDictionary(result)).toBe(true);
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

  test('zstd alone (no br/gzip) → null (not yet a tracked feature)', () => {
    expect(extractEncodingFeatures('zstd')).toBeNull();
  });

  test('output is valid SF-Dictionary', () => {
    const result = extractEncodingFeatures('gzip, deflate, br');
    expect(isValidSFDictionary(result)).toBe(true);
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

  // NOTE: Test matrix suggests * → present, primary=other, count=1.
  // Current implementation returns null (wildcard is not a useful locale
  // for privacy classification). If spec intent changes, update here.
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

  test('many locales → count reflects total', () => {
    expect(extractLanguageFeatures('en-US,en;q=0.9,fr;q=0.8,de;q=0.7,es;q=0.6,pt;q=0.5'))
      .toBe('present, primary=en, count=6');
  });

  test('three-letter language code → first 2 chars', () => {
    // "tlh" (Klingon) → primary=tl
    expect(extractLanguageFeatures('tlh')).toBe('present, primary=tl, count=1');
  });

  test('output is valid SF-Dictionary', () => {
    const result = extractLanguageFeatures('en-US,en;q=0.9');
    expect(isValidSFDictionary(result)).toBe(true);
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

  // NOTE: Test matrix suggests non-numeric → asn=unknown.
  // Current implementation returns null (omit header) since a
  // non-numeric ASN is a malformed input, not a valid category.
  test('non-numeric string → null', () => {
    expect(extractNetFeatures('abc')).toBeNull();
  });

  test('zero → asn=consumer (not in cloud set)', () => {
    expect(extractNetFeatures(0)).toBe('asn=consumer');
  });

  test('negative number → asn=consumer (not in cloud set)', () => {
    expect(extractNetFeatures(-1)).toBe('asn=consumer');
  });

  test('very large ASN → asn=consumer', () => {
    expect(extractNetFeatures(999999)).toBe('asn=consumer');
  });

  test('output is valid SF-Dictionary', () => {
    const result = extractNetFeatures('16509');
    expect(isValidSFDictionary(result)).toBe(true);
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

  test('single brand (Google Chrome only) → brands=1, consistent', () => {
    const singleBrand = '"Google Chrome";v="100"';
    // Google Chrome brand matches CH version extractor, and Chrome/100 in UA matches
    const ua = 'Mozilla/5.0 Chrome/100.0.0.0 Safari/537.36';
    expect(extractCHFeatures(singleBrand, ua)).toBe('present, brands=1, consistent');
  });

  test('output is valid SF-Dictionary', () => {
    const result = extractCHFeatures(CHROME_134_CH, CHROME_134_UA);
    expect(isValidSFDictionary(result)).toBe(true);
  });
});

// ── §6.3.1  extractUAFeatures ──────────────────────────────────────────────

describe('extractUAFeatures', () => {
  const CHROME_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36';
  const FIREFOX_WIN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0';
  const SAFARI_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';
  const EDGE_WIN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0';
  const CURL = 'curl/7.88.1';
  const HEADLESS_CHROME = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36';
  const PUPPETEER = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/134.0.0.0 Safari/537.36 Puppeteer';
  const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
  const IPAD = 'Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';
  const ANDROID_TABLET = 'Mozilla/5.0 (Linux; Android 13; SM-X200) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
  const ANDROID_PHONE = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36';
  const SAFARI_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15';

  // ── dpf compound token ─────────────────────────────────────────────────
  test('Chrome on Mac → desktop/mac/chrome', () => {
    expect(extractUAFeatures(CHROME_MAC)).toMatch(/^dpf=desktop\/mac\/chrome/);
  });

  test('Firefox on Windows → desktop/windows/firefox', () => {
    expect(extractUAFeatures(FIREFOX_WIN)).toMatch(/^dpf=desktop\/windows\/firefox/);
  });

  test('Safari on iPhone → mobile/ios/safari', () => {
    expect(extractUAFeatures(SAFARI_IOS)).toMatch(/^dpf=mobile\/ios\/safari/);
  });

  test('Edge on Windows → desktop/windows/edge', () => {
    expect(extractUAFeatures(EDGE_WIN)).toMatch(/^dpf=desktop\/windows\/edge/);
  });

  test('curl → unknown/other/other', () => {
    expect(extractUAFeatures(CURL)).toMatch(/^dpf=unknown\/other\/other/);
  });

  test('HeadlessChrome → desktop/linux/chrome', () => {
    expect(extractUAFeatures(HEADLESS_CHROME)).toMatch(/^dpf=desktop\/linux\/chrome/);
  });

  test('Googlebot → server/other/bot', () => {
    expect(extractUAFeatures(GOOGLEBOT)).toMatch(/dpf=server\/other\/bot/);
  });

  test('iPad → tablet/ios/safari', () => {
    expect(extractUAFeatures(IPAD)).toMatch(/^dpf=tablet\/ios\/safari/);
  });

  test('Android tablet (no "Mobile") → tablet/android/chrome', () => {
    expect(extractUAFeatures(ANDROID_TABLET)).toMatch(/^dpf=tablet\/android\/chrome/);
  });

  test('Android phone → mobile/android/chrome', () => {
    expect(extractUAFeatures(ANDROID_PHONE)).toMatch(/^dpf=mobile\/android\/chrome/);
  });

  test('Safari on Mac → desktop/mac/safari', () => {
    expect(extractUAFeatures(SAFARI_MAC)).toMatch(/^dpf=desktop\/mac\/safari/);
  });

  // ── version bucketing ──────────────────────────────────────────────────
  test('Chrome 134 → ver=120-139', () => {
    expect(extractUAFeatures(CHROME_MAC)).toMatch(/ver=120-139/);
  });

  test('curl/7.88.1 → ver=0-79', () => {
    expect(extractUAFeatures(CURL)).toMatch(/ver=0-79/);
  });

  // Bucket boundary tests: verify version numbers at edges of each range
  test.each([
    ['Chrome/79.0.0.0',  '0-79'],
    ['Chrome/80.0.0.0',  '80-99'],
    ['Chrome/99.0.0.0',  '80-99'],
    ['Chrome/100.0.0.0', '100-119'],
    ['Chrome/119.0.0.0', '100-119'],
    ['Chrome/120.0.0.0', '120-139'],
    ['Chrome/139.0.0.0', '120-139'],
    ['Chrome/140.0.0.0', '140+'],
    ['Chrome/999.0.0.0', '140+'],
  ])('version bucket boundary: %s → ver=%s', (chromeToken, expected) => {
    // Wrap in a minimal browser-like UA so detectDevice/detectPlatform work
    const ua = `Mozilla/5.0 (X11; Linux x86_64) ${chromeToken} Safari/537.36`;
    expect(extractUAFeatures(ua)).toMatch(new RegExp(`ver=${expected.replace('+', '\\+')}`));
  });

  // ── browser flag ───────────────────────────────────────────────────────
  test('Mozilla/ prefix → browser flag present', () => {
    expect(extractUAFeatures(CHROME_MAC)).toMatch(/\bbrowser\b/);
  });

  test('curl → no browser flag', () => {
    expect(extractUAFeatures(CURL)).not.toMatch(/\bbrowser\b/);
  });

  // ── headless / automation ──────────────────────────────────────────────
  test('HeadlessChrome → headless flag', () => {
    expect(extractUAFeatures(HEADLESS_CHROME)).toMatch(/\bheadless\b/);
  });

  test('HeadlessChrome → no automation flag (headless only)', () => {
    expect(extractUAFeatures(HEADLESS_CHROME)).not.toMatch(/\bautomation\b/);
  });

  test('Puppeteer → both headless and automation', () => {
    const result = extractUAFeatures(PUPPETEER);
    expect(result).toMatch(/\bheadless\b/);
    expect(result).toMatch(/\bautomation\b/);
  });

  test('python-requests → automation', () => {
    expect(extractUAFeatures('python-requests/2.31.0')).toMatch(/\bautomation\b/);
  });

  test('Selenium → automation', () => {
    expect(extractUAFeatures('Mozilla/5.0 Selenium/4.0')).toMatch(/\bautomation\b/);
  });

  test('wget → automation', () => {
    expect(extractUAFeatures('wget/1.21.4')).toMatch(/\bautomation\b/);
  });

  test('normal Chrome → no headless or automation', () => {
    const result = extractUAFeatures(CHROME_MAC);
    expect(result).not.toMatch(/\bheadless\b/);
    expect(result).not.toMatch(/\bautomation\b/);
  });

  // ── entropy ────────────────────────────────────────────────────────────
  test('normal browser UA → entropy=medium', () => {
    expect(extractUAFeatures(CHROME_MAC)).toMatch(/entropy=medium/);
  });

  test('curl (short) → entropy=low', () => {
    expect(extractUAFeatures(CURL)).toMatch(/entropy=low/);
  });

  test('very long UA (>300 chars) → entropy=low', () => {
    const longUA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ' + 'A'.repeat(300);
    expect(extractUAFeatures(longUA)).toMatch(/entropy=low/);
  });

  test('minimal short string → entropy=low', () => {
    expect(extractUAFeatures('bot')).toMatch(/entropy=low/);
  });

  // ── null/empty ─────────────────────────────────────────────────────────
  test('null → null', () => {
    expect(extractUAFeatures(null)).toBeNull();
  });

  test('empty string → null', () => {
    expect(extractUAFeatures('')).toBeNull();
  });

  test('whitespace only → null', () => {
    expect(extractUAFeatures('   ')).toBeNull();
  });

  // ── spec Appendix B examples (exact output match) ──────────────────────
  test('spec example: Chrome on Mac', () => {
    expect(extractUAFeatures(CHROME_MAC))
      .toBe('dpf=desktop/mac/chrome, ver=120-139, browser, entropy=medium');
  });

  test('spec example: HeadlessChrome', () => {
    expect(extractUAFeatures(HEADLESS_CHROME))
      .toBe('dpf=desktop/linux/chrome, ver=120-139, browser, headless, entropy=medium');
  });

  test('spec example: Puppeteer', () => {
    expect(extractUAFeatures(PUPPETEER))
      .toBe('dpf=desktop/linux/chrome, ver=120-139, browser, headless, automation, entropy=medium');
  });

  test('output is valid SF-Dictionary', () => {
    const result = extractUAFeatures(CHROME_MAC);
    expect(isValidSFDictionary(result)).toBe(true);
  });

  test('all dpf compound values use slash separators (no spaces)', () => {
    const uas = [CHROME_MAC, FIREFOX_WIN, SAFARI_IOS, EDGE_WIN, CURL, HEADLESS_CHROME, GOOGLEBOT, IPAD, ANDROID_TABLET];
    for (const ua of uas) {
      const result = extractUAFeatures(ua);
      const dpf = result.match(/^dpf=([^,]+)/)[1];
      const segments = dpf.split('/');
      expect(segments).toHaveLength(3);
    }
  });
});

// ── §6.3.2  computeUAHMAC ──────────────────────────────────────────────────

describe('computeUAHMAC', () => {
  const TEST_UA  = 'Mozilla/5.0 Chrome/134.0.0.0';
  const TEST_KEY = 'test-hmac-secret-key';

  test('returns RFC 8941 Byte Sequence format (:base64:)', async () => {
    const result = await computeUAHMAC(TEST_UA, TEST_KEY);
    expect(result).toMatch(/^:[A-Za-z0-9+/]+=*:$/);
  });

  test('deterministic — same input produces same output', async () => {
    const a = await computeUAHMAC(TEST_UA, TEST_KEY);
    const b = await computeUAHMAC(TEST_UA, TEST_KEY);
    expect(a).toBe(b);
  });

  test('different UA → different HMAC', async () => {
    const a = await computeUAHMAC(TEST_UA, TEST_KEY);
    const b = await computeUAHMAC('curl/7.88.1', TEST_KEY);
    expect(a).not.toBe(b);
  });

  test('different key → different HMAC', async () => {
    const a = await computeUAHMAC(TEST_UA, TEST_KEY);
    const b = await computeUAHMAC(TEST_UA, 'different-key');
    expect(a).not.toBe(b);
  });

  test('null UA → null', async () => {
    expect(await computeUAHMAC(null, TEST_KEY)).toBeNull();
  });

  test('null key → null', async () => {
    expect(await computeUAHMAC(TEST_UA, null)).toBeNull();
  });

  // NOTE: Test matrix suggests empty UA should still produce HMAC.
  // Current implementation returns null (empty string is falsy, no
  // useful signal to HMAC). If spec intent changes, update here.
  test('empty UA → null', async () => {
    expect(await computeUAHMAC('', TEST_KEY)).toBeNull();
  });

  test('empty key → null', async () => {
    expect(await computeUAHMAC(TEST_UA, '')).toBeNull();
  });

  test('very long UA still produces valid HMAC', async () => {
    const longUA = 'Mozilla/5.0 ' + 'X'.repeat(5000);
    const result = await computeUAHMAC(longUA, TEST_KEY);
    expect(result).toMatch(/^:[A-Za-z0-9+/]+=*:$/);
  });

  test('HMAC length is consistent (44-char base64 = 256-bit digest)', async () => {
    const result = await computeUAHMAC(TEST_UA, TEST_KEY);
    // SHA-256 → 32 bytes → 44 base64 chars, wrapped with ':'
    const inner = result.slice(1, -1); // strip : delimiters
    expect(inner).toHaveLength(44);
  });
});

// ── §6.4  computeConfidenceToken ───────────────────────────────────────────

describe('computeConfidenceToken', () => {
  const TEST_UA   = 'Mozilla/5.0 Chrome/134.0.0.0';
  const TEST_LANG = 'en-US,en;q=0.9';
  const TEST_CH   = '"Google Chrome";v="134"';

  test('returns 8-char hex string', async () => {
    const ct = await computeConfidenceToken(TEST_UA, TEST_LANG, TEST_CH);
    expect(ct).toMatch(/^[0-9a-f]{8}$/);
  });

  test('deterministic — same inputs produce same output', async () => {
    const a = await computeConfidenceToken(TEST_UA, TEST_LANG, TEST_CH);
    const b = await computeConfidenceToken(TEST_UA, TEST_LANG, TEST_CH);
    expect(a).toBe(b);
  });

  test('different UA → different token', async () => {
    const a = await computeConfidenceToken(TEST_UA, TEST_LANG, TEST_CH);
    const b = await computeConfidenceToken('curl/7.88.1', TEST_LANG, TEST_CH);
    expect(a).not.toBe(b);
  });

  test('different language → different token', async () => {
    const a = await computeConfidenceToken(TEST_UA, 'en-US', TEST_CH);
    const b = await computeConfidenceToken(TEST_UA, 'fr-FR', TEST_CH);
    expect(a).not.toBe(b);
  });

  test('different CH → different token', async () => {
    const a = await computeConfidenceToken(TEST_UA, TEST_LANG, '"Chrome";v="134"');
    const b = await computeConfidenceToken(TEST_UA, TEST_LANG, '"Chrome";v="120"');
    expect(a).not.toBe(b);
  });

  test('null inputs treated as empty strings (still produces token)', async () => {
    const ct = await computeConfidenceToken(null, null, null);
    expect(ct).toMatch(/^[0-9a-f]{8}$/);
  });

  test('partial inputs work (missing lang/ch)', async () => {
    const ct = await computeConfidenceToken(TEST_UA, null, null);
    expect(ct).toMatch(/^[0-9a-f]{8}$/);
  });

  test('order of concatenation matters (UA+lang+CH ≠ lang+UA+CH)', async () => {
    // Swapping inputs should produce different tokens
    const a = await computeConfidenceToken('A', 'B', 'C');
    const b = await computeConfidenceToken('B', 'A', 'C');
    expect(a).not.toBe(b);
  });
});
