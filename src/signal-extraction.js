/**
 * Signal Extraction Module — Tier 2 feature extractors
 *
 * Transforms raw browser headers into compact RFC 8941 Structured Field
 * Dictionary strings for privacy-preserving VAI signal forwarding.
 *
 * Spec: specs/vai-privacy-v2.spec.md §6.2.1–§6.2.5
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
