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

// ── VAI Metadata: dynamic loading with hardcoded fallbacks ──────────────────
// (paywalls-site-fc4)
//
// These module-level vars are initialized from hardcoded defaults below.
// When loadVAIMetadata() is called, they are updated from the cloud-api
// /pw/vai/metadata endpoint.  If the fetch fails, the hardcoded defaults
// remain in effect — no data loss, no crash.

// ── Hardcoded defaults (bootstrap / fallback) ──────────────────────────────

const DEFAULT_DC_ASNS = [
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
];

const DEFAULT_AUTOMATION_PATTERNS = [
  'Puppeteer', 'Playwright', 'Selenium', 'WebDriver',
  'PhantomJS', 'CasperJS',
  'python-requests', 'python-urllib', 'Go-http-client',
  'okhttp', 'Apache-HttpClient', 'libcurl',
  '\\bcurl\\/', '\\bwget\\/', 'HTTPie',
  'node-fetch', 'undici', 'axios\\/', '\\bgot\\/', 'superagent',
  'Cypress', 'TestCafe', 'Nightwatch', 'WebdriverIO',
  'Scrapy', 'Java\\/|Java HttpURLConnection', 'PostmanRuntime\\/',
  '\\bDeno\\/', '\\bhttpx\\b|python-httpx',
];

const DEFAULT_HEADLESS_PATTERNS = [
  'HeadlessChrome', '\\bHeadless\\b',
];

const DEFAULT_BOT_PATTERNS = [
  'Googlebot', 'bingbot', 'Baiduspider', 'YandexBot', 'DuckDuckBot',
  'Slurp', 'ia_archiver', 'GPTBot', 'ClaudeBot', 'CCBot', 'Bytespider',
  'Applebot', 'PetalBot', 'SemrushBot', 'AhrefsBot', 'DotBot',
];

// ── Mutable state: updated by loadVAIMetadata() ────────────────────────────

/** @type {Set<number>} */
let DC_ASN_SET = new Set(DEFAULT_DC_ASNS);

/** @type {RegExp[]} */
let AUTOMATION_MARKERS = DEFAULT_AUTOMATION_PATTERNS.map(p => new RegExp(p, 'i'));

/** @type {RegExp[]} */
let HEADLESS_MARKERS = DEFAULT_HEADLESS_PATTERNS.map(p => new RegExp(p, 'i'));

/** @type {RegExp} — single combined regex for bot family detection */
let BOT_FAMILY_RE = new RegExp('\\b(' + DEFAULT_BOT_PATTERNS.join('|') + ')\\b', 'i');

// ── Metadata cache ─────────────────────────────────────────────────────────

let _vaiMetadataCache = null;     // { data, ts }
const VAI_METADATA_TTL = 60 * 60 * 1000; // 1 hour

/**
 * Compile pattern strings (from metadata JSON) into RegExp objects.
 * Each string is treated as a regex source with case-insensitive flag.
 * @param {string[]} patterns
 * @returns {RegExp[]}
 */
function compilePatterns(patterns) {
  return patterns.map(p => new RegExp(p, 'i'));
}

/**
 * Fetch VAI metadata from cloud-api and update mutable module state.
 * Caches for 1 hour.  Falls back to hardcoded defaults on failure.
 *
 * Pattern: matches loadAgentPatterns() in user-agent-classification.js.
 *
 * @param {Object} cfg  Config with paywallsAPIHost (cloud-api base URL)
 * @returns {Promise<void>}
 */
export async function loadVAIMetadata(cfg) {
  const now = Date.now();

  // Return early if cache is still valid
  if (_vaiMetadataCache && (now - _vaiMetadataCache.ts) < VAI_METADATA_TTL) {
    return;
  }

  try {
    const response = await fetch(`${cfg.paywallsAPIHost}/pw/vai/metadata`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });

    if (!response.ok) {
      throw new Error(`VAI metadata fetch failed: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();

    // Validate minimal schema
    if (!data || typeof data.version !== 'number') {
      throw new Error('VAI metadata: invalid schema (missing version)');
    }

    // Update mutable state from fetched data
    if (Array.isArray(data.dc_asns) && data.dc_asns.length > 0) {
      DC_ASN_SET = new Set(data.dc_asns);
    }
    if (Array.isArray(data.automation_patterns) && data.automation_patterns.length > 0) {
      AUTOMATION_MARKERS = compilePatterns(data.automation_patterns);
    }
    if (Array.isArray(data.headless_patterns) && data.headless_patterns.length > 0) {
      HEADLESS_MARKERS = compilePatterns(data.headless_patterns);
    }
    if (Array.isArray(data.bot_patterns) && data.bot_patterns.length > 0) {
      BOT_FAMILY_RE = new RegExp('\\b(' + data.bot_patterns.join('|') + ')\\b', 'i');
    }

    _vaiMetadataCache = { data, ts: now };
  } catch (error) {
    console.error('loadVAIMetadata: fetch failed, using hardcoded defaults.', error.message || error);
    // Mark cache so we don't retry immediately (back off for 5 minutes)
    _vaiMetadataCache = { data: null, ts: now - VAI_METADATA_TTL + (5 * 60 * 1000) };
  }
}

/**
 * Reset metadata state to hardcoded defaults and clear cache.
 * Exposed for testing only.
 */
export function _resetVAIMetadata() {
  DC_ASN_SET = new Set(DEFAULT_DC_ASNS);
  AUTOMATION_MARKERS = DEFAULT_AUTOMATION_PATTERNS.map(p => new RegExp(p, 'i'));
  HEADLESS_MARKERS = DEFAULT_HEADLESS_PATTERNS.map(p => new RegExp(p, 'i'));
  BOT_FAMILY_RE = new RegExp('\\b(' + DEFAULT_BOT_PATTERNS.join('|') + ')\\b', 'i');
  _vaiMetadataCache = null;
}

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
//  Tier 3 — Replace User-Agent with derived features (§6.3) + CT (§6.4)
// ═══════════════════════════════════════════════════════════════════════════

// ── §6.3.3  Automation marker detection ────────────────────────────────────
// HeadlessChrome triggers 'headless' only (via HEADLESS_MARKERS).
// Explicit automation tools (Puppeteer, Selenium, etc.) trigger 'automation'.
// AUTOMATION_MARKERS and HEADLESS_MARKERS are now module-level mutable vars
// initialized from hardcoded defaults (top of file) and updated dynamically
// by loadVAIMetadata().  See paywalls-site-fc4.

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

/** @returns {'desktop'|'mobile'|'tablet'|'smarttv'|'console'|'car'|'wearable'|'vr'|'server'|'unknown'} */
function detectDevice(ua) {
  // Smart TV: check before tablet/mobile (some TVs include Android)
  if (/SmartTV|SMART-TV|\bTizen\b|\bWebOS\b|\bBRAVIA\b|\bVizio\b|\bRoku\b|\bAppleTV\b|\bFire TV\b|\bAndroidTV\b|\btvOS\b|\bHBBTV\b/i.test(ua)) return 'smarttv';
  // Gaming consoles
  if (/\b(PlayStation|PLAYSTATION|Xbox|Nintendo)\b/i.test(ua)) return 'console';
  // VR headsets (Meta Quest / Oculus)
  if (/OculusBrowser|\bQuest\b/i.test(ua)) return 'vr';
  // Wearables (Apple Watch, etc.)
  if (/\bWatch\b|\bwearable\b/i.test(ua)) return 'wearable';
  // Automotive
  if (/\bTesla\b|\bCarPlay\b/i.test(ua)) return 'car';
  if (/\b(iPad|Tablet|PlayBook|Silk|Kindle)\b/i.test(ua)) return 'tablet';
  if (/\b(iPhone|iPod|Android.*Mobile|Mobile.*Android|webOS|BlackBerry|Opera Mini|IEMobile|Windows Phone)\b/i.test(ua)) return 'mobile';
  if (/\b(Android)\b/i.test(ua) && !/Mobile/i.test(ua)) return 'tablet';
  if (/\b(Macintosh|Windows NT|X11|Linux(?!.*Android))\b/i.test(ua)) return 'desktop';
  if (/\b(Googlebot|bingbot|Baiduspider|YandexBot|DuckDuckBot)\b/i.test(ua)) return 'server';
  return 'unknown';
}

/** @returns {'windows'|'mac'|'ios'|'android'|'linux'|'chromeos'|'freebsd'|'other'} */
function detectPlatform(ua) {
  if (/\b(iPhone|iPad|iPod)\b/i.test(ua))          return 'ios';
  if (/\bAndroid\b/i.test(ua))                      return 'android';
  if (/\bCrOS\b/i.test(ua))                         return 'chromeos';
  if (/\bMacintosh\b/i.test(ua))                    return 'mac';
  if (/\bWindows\b/i.test(ua))                      return 'windows';
  if (/\bFreeBSD\b/i.test(ua))                      return 'freebsd';
  if (/\bLinux\b/i.test(ua) || /\bX11\b/i.test(ua)) return 'linux';
  return 'other';
}

/** @returns {'chrome'|'safari'|'firefox'|'edge'|'ucbrowser'|'other'|'bot'} */
function detectFamily(ua) {
  // Bots: search engine crawlers + AI/SEO crawlers (dynamic via loadVAIMetadata)
  if (BOT_FAMILY_RE.test(ua)) return 'bot';
  // UC Browser: mobile-heavy, no Client Hints — check before Chrome
  if (/UCBrowser|UCWEB/i.test(ua)) return 'ucbrowser';
  // Order matters: Edge before Chrome (Edge UA contains "Chrome")
  if (/\bEdg(?:e|A)?\/\d/i.test(ua))  return 'edge';
  if (/\bFirefox\//i.test(ua))         return 'firefox';
  // Safari check: has "Safari/" but NOT "Chrome/" or "Chromium/" or "HeadlessChrome/"
  if (/\bSafari\//i.test(ua) && !/Chrome|Chromium|HeadlessChrome/i.test(ua)) return 'safari';
  // Opera (OPR/) and Brave share Chromium engine; keep as 'chrome' family
  // since they support Client Hints and score the same.
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
 * Uses math-based 20-version spans starting at 80, capped at 420+.
 * Legacy range: 0-79. Then 80-99, 100-119, …, 400-419, 420+.
 * @param {number|null} ver
 * @returns {string}
 */
function bucketVersion(ver) {
  if (ver == null || ver < 80)  return '0-79';
  if (ver >= 420) return '420+';
  // 20-version spans starting at 80: floor((ver - 80) / 20) gives bucket index
  const base = 80;
  const span = 20;
  const bucketIndex = Math.floor((ver - base) / span);
  const lo = base + bucketIndex * span;
  const hi = lo + span - 1;
  return `${lo}-${hi}`;
}

// ── §6.3.1  extractUAFeatures ──────────────────────────────────────────────

/**
 * Detect structurally impossible or fabricated browser version strings.
 *
 * Chrome frozen UA policy (since Chrome 107, late 2022):
 *   Real Chrome reports Chrome/[major].0.0.0 — minor, build, and patch are
 *   always zero.  Any major >= 107 with non-zero build or patch is fabricated.
 *
 * Legacy Chrome with 4-digit patch (e.g. Chrome/48.0.1025.1402):
 *   Chrome patch numbers are 1-4 digits (max ~6367 in historical builds).
 *   A 4+ digit patch on an old Chrome version is structurally fabricated.
 *
 * Fabricated Edge (e.g. Edge/18.19582):
 *   Edge/18 was EdgeHTML-era; real minor versions were at most 3 digits.
 *   A 5-digit minor on EdgeHTML is structurally impossible.
 *
 * @param {string} ua
 * @returns {boolean}
 */
function isFabricatedVersion(ua) {
  // Chrome / HeadlessChrome / Chromium: full version parse
  const chromeMatch = ua.match(/(?:\b|Headless)Chrom(?:e|ium)\/(\d+)\.(\d+)\.(\d+)\.(\d+)/);
  if (chromeMatch) {
    const major = parseInt(chromeMatch[1], 10);
    const build = parseInt(chromeMatch[3], 10);
    const patch = parseInt(chromeMatch[4], 10);

    // Frozen UA policy: Chrome >= 107 must be major.0.0.0
    if (major >= 107 && (build !== 0 || patch !== 0)) return true;

    // 4-digit patch on any Chrome version is structurally impossible
    if (chromeMatch[4].length >= 4) return true;
  }

  // EdgeHTML-era (Edge/12-18): minor version should be ≤ 3 digits
  const edgeMatch = ua.match(/\bEdge\/(\d+)\.(\d+)/);
  if (edgeMatch) {
    const major = parseInt(edgeMatch[1], 10);
    if (major <= 18 && edgeMatch[2].length >= 5) return true;
  }

  return false;
}

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
  if (isFabricatedVersion(ua)) parts.push('fabricated');

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

// ── §6.4  computeConfidenceToken ───────────────────────────────────────────
/**
 * Compute the confidence token.
 * ct = SHA-256(userAgent + acceptLanguage + secChUA)[0:8] hex
 *
 * Matches the logic in cloud-api computeConfidenceFingerprint().
 *
 * @param {string|null|undefined} userAgent       Raw User-Agent
 * @param {string|null|undefined} acceptLanguage  Raw Accept-Language
 * @param {string|null|undefined} secChUA         Raw Sec-CH-UA
 * @returns {Promise<string>}  8-char hex token, never null
 */
export async function computeConfidenceToken(userAgent, acceptLanguage, secChUA) {
  const ua   = userAgent || '';
  const lang = acceptLanguage || '';
  const ch   = secChUA || '';

  const msgBuffer  = new TextEncoder().encode(ua + lang + ch);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray  = Array.from(new Uint8Array(hashBuffer));
  const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.slice(0, 8);
}
