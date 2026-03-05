/**
 * Signal Extraction Module — Tier 2 + Tier 3 feature extractors
 *
 * Transforms raw browser headers into compact RFC 8941 Structured Field
 * Dictionary strings for privacy-preserving VAI signal forwarding.
 *
 * Spec: specs/vai-privacy-v2.spec.md §6.2–§6.4
 *
 * Each function returns an SF-Dictionary string (e.g. "html, wildcard")
 * or null if the input is absent/empty.  null means the caller should
 * omit the header entirely (not send an empty value).
 */

// ── §6.2.4 / Appendix A: Data-center ASN set ──────────────────────────────
// Comprehensive cloud/hosting provider ASNs for DC classification.
// Kept in sync with cloud-api DC_ASN_LIST (cloudflare/vai.js).
// Source: public ASN registries (PeeringDB, RIPE, ARIN).
const DC_ASN_SET = new Set([
  // ── Major IaaS ───────────────────────────────────────────────────────────
  16509, 14618,          // Amazon AWS (primary + secondary)
  396982, 36492, 15169,  // Google Cloud + Google infra
  8075, 8069, 8068,      // Microsoft Azure
  31898,                 // Oracle Cloud
  36351,                 // IBM Cloud / SoftLayer
  45102,                 // Alibaba Cloud
  132203,                // Tencent Cloud

  // ── VPS / Hosting ────────────────────────────────────────────────────────
  14061,                 // DigitalOcean
  24940, 213230,         // Hetzner (dedicated + cloud)
  16276,                 // OVH
  63949,                 // Linode / Akamai Connected Cloud
  20473,                 // Vultr / The Constant Company
  12876,                 // Scaleway
  51167,                 // Contabo
  60781, 28753,          // Leaseweb (NL + global)
]);

// ── §6.2.1  Accept → X-PW-Accept ──────────────────────────────────────────
/**
 * Extract boolean feature flags from the Accept header.
 *
 * @param {string|null|undefined} accept  Raw Accept header value
 * @returns {string|null}  SF-Dictionary string or null if absent/empty
 */
export function extractAcceptFeatures(accept) {
  if (!accept) return null;

  const parts = [];
  if (accept.includes('text/html'))          parts.push('html');
  if (accept.includes('*/*'))                parts.push('wildcard');
  if (accept.includes('application/json'))   parts.push('json');
  if (accept.includes('image/'))             parts.push('image');

  return parts.length > 0 ? parts.join(', ') : null;
}

// ── §6.2.2  Accept-Encoding → X-PW-Enc ────────────────────────────────────
/**
 * Extract boolean feature flags from the Accept-Encoding header.
 *
 * @param {string|null|undefined} acceptEncoding  Raw Accept-Encoding value
 * @returns {string|null}  SF-Dictionary string or null if absent/empty
 */
export function extractEncodingFeatures(acceptEncoding) {
  if (!acceptEncoding) return null;

  const parts = [];
  const hasBr   = acceptEncoding.includes('br');
  const hasGzip = acceptEncoding.includes('gzip');

  if (hasBr)   parts.push('br');
  if (hasGzip) parts.push('gzip');
  if (hasBr && hasGzip) parts.push('modern');

  return parts.length > 0 ? parts.join(', ') : null;
}

// ── §6.2.3  Accept-Language → X-PW-Lang ───────────────────────────────────
/**
 * Extract presence, primary language family, and locale count from
 * the Accept-Language header.
 *
 * @param {string|null|undefined} acceptLanguage  Raw Accept-Language value
 * @returns {string|null}  SF-Dictionary string or null if absent/empty
 */
export function extractLanguageFeatures(acceptLanguage) {
  if (!acceptLanguage) return null;

  const trimmed = acceptLanguage.trim();
  if (trimmed === '' || trimmed === '*') return null;

  // Split on comma to count locales, ignoring quality values
  const locales = trimmed.split(',').map(s => s.trim().split(';')[0].trim()).filter(Boolean);
  const count = locales.length;
  if (count === 0) return null;

  // Primary language family = first 2 chars of first locale (lowercase)
  const first = locales[0].toLowerCase();
  const primary = first.length >= 2 ? first.slice(0, 2) : first;

  const parts = ['present', `primary=${primary}`, `count=${count}`];
  return parts.join(', ');
}

// ── §6.2.4  ASN → X-PW-Net ────────────────────────────────────────────────
/**
 * Classify an ASN into a named enum category.
 *
 * @param {string|number|null|undefined} asn  Numeric ASN value
 * @returns {string|null}  SF-Dictionary string or null if absent/empty
 */
export function extractNetFeatures(asn) {
  if (asn == null || asn === '') return null;

  const num = typeof asn === 'number' ? asn : parseInt(asn, 10);
  if (isNaN(num)) return null;

  const category = DC_ASN_SET.has(num) ? 'cloud' : 'consumer';
  return `asn=${category}`;
}

// ── §6.2.5  Sec-CH-UA → X-PW-CH ───────────────────────────────────────────

/**
 * Extract Chrome version from a Sec-CH-UA header value.
 * Looks for "Chromium" or "Google Chrome" brand and returns the major version.
 *
 * @param {string} secChUA  Raw Sec-CH-UA header
 * @returns {number|null}  Major Chrome version or null
 */
function extractChromeVersionFromCH(secChUA) {
  // Sec-CH-UA format: "Brand";v="version", "Brand";v="version", ...
  const match = secChUA.match(/"(?:Google Chrome|Chromium)";v="(\d+)"/);
  return match ? parseInt(match[1], 10) : null;
}

/**
 * Extract Chrome version from a User-Agent string.
 *
 * @param {string} userAgent  Raw User-Agent string
 * @returns {number|null}  Major Chrome version or null
 */
function extractChromeVersionFromUA(userAgent) {
  // UA format: ...Chrome/134.0.0.0...
  const match = userAgent.match(/Chrome\/(\d+)/);
  return match ? parseInt(match[1], 10) : null;
}

/**
 * Extract features from Sec-CH-UA header, cross-referenced with User-Agent
 * for the consistency check.
 *
 * @param {string|null|undefined} secChUA    Raw Sec-CH-UA header value
 * @param {string|null|undefined} userAgent  Raw User-Agent string (for consistency check)
 * @returns {string|null}  SF-Dictionary string or null if CH absent/empty
 */
export function extractCHFeatures(secChUA, userAgent) {
  if (!secChUA) return null;

  const trimmed = secChUA.trim();
  if (trimmed === '') return null;

  const parts = ['present'];

  // Count brand entries: each is a quoted string followed by ;v="..."
  // Split on comma to count entries
  const brands = trimmed.split(',').map(s => s.trim()).filter(Boolean);
  parts.push(`brands=${brands.length}`);

  // GREASE detection: Chromium convention includes a "Not" brand
  const hasGrease = brands.some(b => /not[^"]*brand/i.test(b) || /not[:\-_.]/i.test(b));
  if (hasGrease) parts.push('grease');

  // Consistency check: Chrome version in CH matches Chrome version in UA
  if (userAgent) {
    const chVersion = extractChromeVersionFromCH(trimmed);
    const uaVersion = extractChromeVersionFromUA(userAgent);
    if (chVersion != null && uaVersion != null && chVersion === uaVersion) {
      parts.push('consistent');
    }
  }

  return parts.join(', ');
}

// ═══════════════════════════════════════════════════════════════════════════
//  Tier 3 — Replace User-Agent with derived features (§6.3) + CT FP (§6.4)
// ═══════════════════════════════════════════════════════════════════════════

// ── §6.3.3  Automation marker detection ────────────────────────────────────
// HeadlessChrome triggers 'headless' only (via HEADLESS_MARKERS).
// Explicit automation tools (Puppeteer, Selenium, etc.) trigger 'automation'.
const AUTOMATION_MARKERS = [
  /Puppeteer/i, /Playwright/i, /Selenium/i, /WebDriver/i,
  /PhantomJS/i, /CasperJS/i,
  /python-requests/i, /python-urllib/i, /Go-http-client/i,
  /okhttp/i, /Apache-HttpClient/i, /libcurl/i,
  /\bcurl\//i, /\bwget\//i, /HTTPie/i,
  /node-fetch/i, /undici/i, /axios\//i, /\bgot\//i, /superagent/i,
  /Cypress/i, /TestCafe/i, /Nightwatch/i, /WebdriverIO/i,
];

const HEADLESS_MARKERS = [/HeadlessChrome/i, /\bHeadless\b/i];

// ── §6.3.4  Entropy bucketing ──────────────────────────────────────────────
/**
 * Bucket a User-Agent string's structural complexity.
 * @param {string} userAgent
 * @returns {'low'|'medium'|'high'}
 */
function computeUAEntropy(userAgent) {
  if (!userAgent || userAgent.length < 10) return 'low';

  const hasUpper   = /[A-Z]/.test(userAgent);
  const hasLower   = /[a-z]/.test(userAgent);
  const hasDigit   = /\d/.test(userAgent);
  const hasSpecial = /[\/\.;()\s,_\-]/.test(userAgent);
  const classCount = [hasUpper, hasLower, hasDigit, hasSpecial].filter(Boolean).length;

  const len = userAgent.length;
  const hasParens = /\([^)]+\)/.test(userAgent);

  // Typical browser UA: 60-250 chars, 4 char classes, has parens
  if (classCount >= 4 && len >= 60 && len <= 250 && hasParens) return 'medium';
  if (classCount >= 3 && len >= 40 && len <= 300) return 'medium';

  // Very short, very long, or missing structure
  if (len < 40 || len > 300 || classCount < 3) return 'low';

  // Unusual: high-entropy random strings
  const uniqueChars = new Set(userAgent).size;
  if (uniqueChars / len > 0.7) return 'high';

  return 'medium';
}

// ── §6.3.1  UA dpf/version parsing ─────────────────────────────────────────

/** @returns {'desktop'|'mobile'|'tablet'|'server'|'unknown'} */
function detectDevice(ua) {
  if (/\b(iPad|Tablet|PlayBook|Silk|Kindle)\b/i.test(ua)) return 'tablet';
  if (/\b(iPhone|iPod|Android.*Mobile|Mobile.*Android|webOS|BlackBerry|Opera Mini|IEMobile|Windows Phone)\b/i.test(ua)) return 'mobile';
  if (/\b(Android)\b/i.test(ua) && !/Mobile/i.test(ua)) return 'tablet';
  if (/\b(Macintosh|Windows NT|X11|Linux(?!.*Android))\b/i.test(ua)) return 'desktop';
  if (/\b(Googlebot|bingbot|Baiduspider|YandexBot|DuckDuckBot)\b/i.test(ua)) return 'server';
  return 'unknown';
}

/** @returns {'windows'|'mac'|'ios'|'android'|'linux'|'other'} */
function detectPlatform(ua) {
  if (/\b(iPhone|iPad|iPod)\b/i.test(ua))          return 'ios';
  if (/\bAndroid\b/i.test(ua))                      return 'android';
  if (/\bMacintosh\b/i.test(ua))                    return 'mac';
  if (/\bWindows\b/i.test(ua))                      return 'windows';
  if (/\bLinux\b/i.test(ua) || /\bX11\b/i.test(ua)) return 'linux';
  return 'other';
}

/** @returns {'chrome'|'safari'|'firefox'|'edge'|'other'|'bot'} */
function detectFamily(ua) {
  if (/\b(Googlebot|bingbot|Baiduspider|YandexBot|DuckDuckBot|Slurp|ia_archiver)\b/i.test(ua)) return 'bot';
  // Order matters: Edge before Chrome (Edge UA contains "Chrome")
  if (/\bEdg(?:e|A)?\/\d/i.test(ua))  return 'edge';
  if (/\bFirefox\//i.test(ua))         return 'firefox';
  // Safari check: has "Safari/" but NOT "Chrome/" or "Chromium/" or "HeadlessChrome/"
  if (/\bSafari\//i.test(ua) && !/Chrome|Chromium|HeadlessChrome/i.test(ua)) return 'safari';
  if (/(?:\b|Headless)Chrom(?:e|ium)\//i.test(ua))  return 'chrome';
  return 'other';
}

/**
 * Extract major browser version from a User-Agent string.
 * @param {string} ua
 * @returns {number|null}
 */
function extractMajorVersion(ua) {
  // Try common version patterns in order of specificity
  let m = ua.match(/\bEdg(?:e|A)?\/(\d+)/);
  if (m) return parseInt(m[1], 10);
  m = ua.match(/\bFirefox\/(\d+)/);
  if (m) return parseInt(m[1], 10);
  // Chrome / Chromium / HeadlessChrome
  m = ua.match(/(?:\b|Headless)Chrom(?:e|ium)\/(\d+)/);
  if (m) return parseInt(m[1], 10);
  // Safari: Version/17.x  (not the Safari/605 build number)
  m = ua.match(/\bVersion\/(\d+)/);
  if (m) return parseInt(m[1], 10);
  // Generic: first thing/number pattern
  m = ua.match(/\/(\d+)/);
  if (m) return parseInt(m[1], 10);
  return null;
}

/**
 * Bucket a major version number into a range token.
 * @param {number|null} ver
 * @returns {string}
 */
function bucketVersion(ver) {
  if (ver == null) return '0-79';
  if (ver < 80)  return '0-79';
  if (ver < 100) return '80-99';
  if (ver < 120) return '100-119';
  if (ver < 140) return '120-139';
  return '140+';
}

// ── §6.3.1  extractUAFeatures ──────────────────────────────────────────────
/**
 * Parse a User-Agent string into an SF-Dictionary of derived features.
 *
 * @param {string|null|undefined} userAgent  Raw User-Agent string
 * @returns {string|null}  SF-Dictionary string or null if absent/empty
 */
export function extractUAFeatures(userAgent) {
  if (!userAgent) return null;
  const ua = userAgent.trim();
  if (ua === '') return null;

  const device   = detectDevice(ua);
  const platform = detectPlatform(ua);
  const family   = detectFamily(ua);
  const ver      = bucketVersion(extractMajorVersion(ua));

  const parts = [`dpf=${device}/${platform}/${family}`, `ver=${ver}`];

  if (/^Mozilla\//i.test(ua)) parts.push('browser');

  if (HEADLESS_MARKERS.some(re => re.test(ua))) parts.push('headless');
  if (AUTOMATION_MARKERS.some(re => re.test(ua))) parts.push('automation');

  parts.push(`entropy=${computeUAEntropy(ua)}`);

  return parts.join(', ');
}

// ── §6.3.2  computeUAHMAC ─────────────────────────────────────────────────
/**
 * Compute HMAC-SHA256 of the raw User-Agent, returned as an RFC 8941
 * Byte Sequence string (:base64:).
 *
 * Uses crypto.subtle — compatible with Cloudflare Workers and modern Node.
 *
 * @param {string} userAgent  Raw User-Agent string
 * @param {string} hmacKey    HMAC secret key (plain text)
 * @returns {Promise<string|null>}  RFC 8941 Byte Sequence or null if inputs missing
 */
export async function computeUAHMAC(userAgent, hmacKey) {
  if (!userAgent || !hmacKey) return null;

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(hmacKey),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(userAgent));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `:${b64}:`;
}

// ── §6.4  computeCTFingerprint ─────────────────────────────────────────────
/**
 * Compute the confidence-token fingerprint.
 * fp = SHA-256(userAgent + acceptLanguage + secChUA)[0:8] hex
 *
 * Matches the logic in cloud-api computeConfidenceFingerprint().
 *
 * @param {string|null|undefined} userAgent       Raw User-Agent
 * @param {string|null|undefined} acceptLanguage  Raw Accept-Language
 * @param {string|null|undefined} secChUA         Raw Sec-CH-UA
 * @returns {Promise<string>}  8-char hex token, never null
 */
export async function computeCTFingerprint(userAgent, acceptLanguage, secChUA) {
  const ua   = userAgent || '';
  const lang = acceptLanguage || '';
  const ch   = secChUA || '';

  const msgBuffer  = new TextEncoder().encode(ua + lang + ch);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray  = Array.from(new Uint8Array(hashBuffer));
  const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.slice(0, 8);
}
