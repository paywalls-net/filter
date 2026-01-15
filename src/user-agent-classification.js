import { UAParser } from 'ua-parser-js';

// Cache for user agent patterns
let cachedUserAgentPatterns = null;
let cacheTimestamp = null;
const CACHE_DURATION = 60 * 60 * 1000; // 1 hour

// Cache for user agent classifications
// 
// CACHE STRATEGY CONSIDERATIONS:
// 
// Current approach: Raw user-agent string as cache key
// - Pro: No parsing overhead before cache lookup
// - Pro: Exact matches are very fast
// - Con: User-agents with minor version differences create separate cache entries
// - Con: Cache could grow large with many unique UAs (especially browser traffic)
//
// Alternative approaches to consider:
// 1. Normalized keys (e.g., browser name + major version + OS)
//    - Would improve hit rate and reduce memory
//    - But adds parsing cost before every cache check
//    - Risk: Might miss pattern-specific matches if patterns are version-sensitive
//
// 2. LRU cache with size limit
//    - Bounds memory usage
//    - Evicts least-recently-used entries
//    - Good if traffic patterns are consistent
//
// 3. Separate caches for bots vs browsers
//    - Bot UAs are typically more stable (better cache hit rate)
//    - Browser UAs change frequently with versions (lower hit rate)
//    - Could optimize each differently
//
// Decision: Start with raw UA keys until we have production metrics showing:
// - Actual cache size growth
// - Cache hit rates
// - Memory pressure
// Then optimize based on data rather than speculation.
let classificationCache = new Map();

/**
 * Fetch user agent patterns from the API and cache them.
 * @returns {Promise<Array>} The user agent patterns.
 */
export async function loadAgentPatterns(cfg) {
    const now = Date.now();

    // Return cached patterns if still valid
    if (cachedUserAgentPatterns && (now - cacheTimestamp < CACHE_DURATION)) {
        return cachedUserAgentPatterns;
    }

    try {
        const response = await fetch(`${cfg.paywallsAPIHost}/api/filter/agents/metadata`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Authorization: `Bearer ${cfg.paywallsAPIKey}`
            }
        });

        if (!response.ok) {
            throw new Error(`Failed to fetch agent patterns: ${response.status} ${response.statusText}`);
        }

        const serializedPatterns = await response.json();

        // Deserialize RegExp strings back into RegExp objects
        cachedUserAgentPatterns = serializedPatterns.map((pattern) => ({
            ...pattern,
            patterns: pattern.patterns.map((regexString) => new RegExp(regexString.slice(1, -1))) // Remove leading and trailing slashes
        }));

        cacheTimestamp = now;
        
        // Clear classification cache when patterns are refreshed
        classificationCache.clear();
        
        return cachedUserAgentPatterns;
    } catch (error) {
        console.error('Error loading agent patterns:', error);
        throw error;
    }
}

/**
 * Classifies the user agent string based on fetched patterns.
 * @param {Object} cfg - Configuration object containing API host details.
 * @param {string} userAgent - The user agent string to classify.
 * @returns {Promise<Object>} An object containing the browser, OS, operator, usage, and user_initiated status.
 */
export async function classifyUserAgent(cfg, userAgent) {
    // Check classification cache first (single lookup is more efficient than has + get)
    const cached = classificationCache.get(userAgent);
    if (cached !== undefined) {
        console.log(`User agent classification cache hit for: ${userAgent}`);
        return cached;
    }
    console.log(`User agent classification cache miss for: ${userAgent}`);

    const parsedUA = new UAParser(userAgent).getResult();

    const browser = parsedUA.browser.name || 'Unknown';
    const os = parsedUA.os.name || 'Unknown';

    const userAgentPatterns = await loadAgentPatterns(cfg);

    for (const config of userAgentPatterns) {
        if (!config.patterns) continue;
        for (const pattern of config.patterns) {
            if (new RegExp(pattern).test(userAgent)) {         
                const result = {
                    operator: config.operator,
                    agent: config.agent || browser,
                    usage: config.usage,
                    user_initiated: config.user_initiated,
                    browser,
                    os,
                };
                // Cache the classification result
                classificationCache.set(userAgent, result);
                return result;
            }
        }
    }

    const result = {
        browser,
        os
    };
    // Cache the default classification
    classificationCache.set(userAgent, result);
    return result;
}
