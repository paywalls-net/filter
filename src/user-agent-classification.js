import { UAParser } from 'ua-parser-js';

// Cache for user agent patterns
let cachedUserAgentPatterns = null;
let cacheTimestamp = null;
const CACHE_DURATION = 60 * 60 * 1000; // 1 hour

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
            throw new Error(`Failed to fetch user agent patterns: ${response.status} ${response.statusText}`);
        }

        cachedUserAgentPatterns = await response.json();
        cacheTimestamp = now;
        return cachedUserAgentPatterns;
    } catch (error) {
        console.error('Failed to fetch user agent patterns:', error);
        throw new Error('Could not load user agent patterns');
    }
}

/**
 * Classifies the user agent string based on fetched patterns.
 * @param {Object} cfg - Configuration object containing API host details.
 * @param {string} userAgent - The user agent string to classify.
 * @returns {Promise<Object>} An object containing the browser, OS, operator, usage, and user_initiated status.
 */
export async function classifyUserAgent(cfg, userAgent) {
    const parsedUA = new UAParser(userAgent).getResult();

    const browser = parsedUA.browser.name || 'Unknown';
    const os = parsedUA.os.name || 'Unknown';

    const userAgentPatterns = await loadAgentPatterns(cfg);

    for (const config of userAgentPatterns) {
        if (!config.patterns) continue;
        for (const pattern of config.patterns) {
            if (new RegExp(pattern).test(userAgent)) {
                return {
                    operator: config.operator,
                    agent: config.agent || browser,
                    usage: config.usage,
                    user_initiated: config.user_initiated,
                    browser,
                    os,
                };
            }
        }
    }

    return {
        browser,
        os
    };
}
