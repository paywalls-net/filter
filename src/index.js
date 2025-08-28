/**
 * Example publisher-hosted client code for a Cloudflare Worker that
 * filters bot-like requests by using paywalls.net authorization services.
 */

import { classifyUserAgent, loadAgentPatterns } from './user-agent-classification.js';

const PAYWALLS_CLOUD_API_HOST = "https://cloud-api.paywalls.net";

async function logAccess(cfg, request, access) {
    // Separate html from the status in the access object.
    const { response, ...status } = access;

    // Get all headers as a plain object (name-value pairs)
    let headers = {};
    for (const [key, value] of request.headers.entries()) {
        headers[key] = value;
    }
    const url = new URL(request.url);
    let body = {
        account_id: cfg.paywallsPublisherId,
        status: status,
        method: request.method,
        hostname: url.hostname,
        resource: url.pathname + url.search,
        user_agent: headers['user-agent'],
        headers: headers
    };

    const logResponse = await fetch(`${cfg.paywallsAPIHost}/api/filter/access/logs`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${cfg.paywallsAPIKey}`
        },
        body: JSON.stringify(body)
    });
    if (!logResponse.ok) {
        console.error(`Error logging access: ${logResponse.status} ${logResponse.statusText}`);
        // Optionally, you can handle the error here, e.g., retry or log to a different service
    }
}

/**
 * Typedef for AgentStatus
 * @typedef {Object} AgentStatus
 * @property {string} access - Whether access is granted (allow, deny)
 * @property {string} reason - The reason for the status (e.g., missing_user_agent, unknown_error)
 * @property {object} response - The response object
 * @property {number} response.code - The HTTP status code to be sent to the client
 * @property {object} response.headers - The headers to be sent to the client
 * @property {string} response.html - The HTML response to be sent to the client
 */

/**
 * 
 * @param {*} cfg 
 * @param {Request} request - The incoming request object
 * @returns {Promise<AgentStatus>} - The authorization for this agent
 */
async function checkAgentStatus(cfg, request) {
    const userAgent = request.headers.get("User-Agent");
    const token = getAcessToken(request);

    if (!userAgent) {
        console.error("Missing user-agent");
        return {
            access: 'deny',
            reason: 'missing_user_agent',
            response: { code: 401, html: "Unauthorized access." }
        };
    }

    const agentInfo = await classifyUserAgent(cfg, userAgent);

    const body = JSON.stringify({
        account_id: cfg.paywallsPublisherId,
        operator: agentInfo.operator,
        agent: agentInfo.agent,
        token: token
    });

    const response = await fetch(`${cfg.paywallsAPIHost}/api/filter/agents/auth`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${cfg.paywallsAPIKey}`
        },
        body: body
    });

    if (!response.ok) {
        console.error(`Failed to fetch agent auth: ${response.status} ${response.statusText}`);
        return {
            access: 'deny',
            reason: 'unknown_error',
            response: { code: 502, html: "Bad Gateway." }
        };
    }

    return response.json();
}

function getAcessToken(request) {
    const authHeader = request.headers.get("Authorization");
    if (!authHeader) {
        return null;
    }

    const token = authHeader.split(" ")[1];
    return token;
}

function isFastlyKnownBot(request) {
    const botScore = request.headers.get("X-Fastly-Bot-Score");
    const isKnownBot = request.headers.get("X-Fastly-Known-Bot");

    return isKnownBot === "true" || (botScore && parseInt(botScore) < 30);
}

function isCloudflareKnownBot(request) {
    const cf = request.cf || {};
    const botScore = cf.botManagement?.score;
    const isKnownBot = cf.botManagement?.verifiedBot;
    return isKnownBot || (botScore !== undefined && botScore < 30);
}

function isTestBot(request) {
    // check if the URL has a query parameter to always test as a bot
    const url = new URL(request.url);
    const uaParam = url.searchParams.get("user-agent");
    return uaParam && uaParam.includes("bot");
}
async function isPaywallsKnownBot(cfg, request) {
    const userAgent = request.headers.get("User-Agent");
    const uaClassification = await classifyUserAgent(cfg, userAgent);
    return uaClassification.operator && uaClassification.agent;
}

async function isRecognizedBot(cfg, request) {
    return isFastlyKnownBot(request) || isCloudflareKnownBot(request) || isTestBot(request) || await isPaywallsKnownBot(cfg, request);
}


/**
 * Create response in format used by most CDNs
 * @param {*} authz 
 * @returns 
 */
function setHeaders(authz) {
    let headers = {
        "Content-Type": "text/html",
    };

    if (authz.response?.headers) {
        for (const [key, value] of Object.entries(authz.response.headers)) {
            headers[key] = value;
        }
    }

    return new Response(authz.response?.html || "Payment required.", {
        status: authz.response?.code || 402,
        headers: headers
    });
}

/**
 * Create CloudFront format response 
 * @param {*} authz 
 * @returns 
 */
function setCloudFrontHeaders(authz) {
    const headers = {};

    if (authz.response?.headers) {
        for (const [key, value] of Object.entries(authz.response.headers)) {
            headers[key.toLowerCase()] = [
                {
                    key: key,
                    value: value
                }
            ];
        }
    }

    // Add default Content-Type header if not already set
    if (!headers["content-type"]) {
        headers["content-type"] = [
            {
                key: "Content-Type",
                value: "text/html"
            }
        ];
    }

    return {
        status: authz.response?.code || 402,
        statusDescription: authz.response?.code === 402 ? "Payment Required" : "Error",
        headers: headers,
        body: authz.response?.html || "Payment required."
    };
}

/**
 * Detect AI Bot and authorize it using paywalls.net.
 * @param {Request} request 
 * @param {*} env 
 * @param {*} ctx 
 * @returns 
 */
async function cloudflare(config = null) {

    return async function handle(request, env, ctx) {
        const paywallsConfig = {
            paywallsAPIHost: env.PAYWALLS_CLOUD_API_HOST || PAYWALLS_CLOUD_API_HOST,
            paywallsAPIKey: env.PAYWALLS_CLOUD_API_KEY,
            paywallsPublisherId: env.PAYWALLS_PUBLISHER_ID
        };
        await loadAgentPatterns(paywallsConfig);

        if (await isRecognizedBot(paywallsConfig, request)) {
            const authz = await checkAgentStatus(paywallsConfig, request);

            ctx.waitUntil(logAccess(paywallsConfig, request, authz));

            if (authz.access === 'deny') {
                return setHeaders(authz);
            } else {
                // console.log("Bot-like request allowed. Proceeding to origin/CDN.");
            }
        }
    };
}


async function fastly(config) {
    const paywallsConfig = {
        paywallsAPIHost: config.get('PAYWALLS_CLOUD_API_HOST') || PAYWALLS_CLOUD_API_HOST,
        paywallsAPIKey: config.get('PAYWALLS_API_KEY'),
        paywallsPublisherId: config.get('PAYWALLS_PUBLISHER_ID')
    };
    await loadAgentPatterns(paywallsConfig);

    return async function handle(request) {
        if (await isRecognizedBot(paywallsConfig, request)) {
            const authz = await checkAgentStatus(paywallsConfig, request);

            await logAccess(paywallsConfig, request, authz);

            if (authz.access === 'deny') {
                return setHeaders(authz);
            }
        }
    };
}

async function cloudfront(config) {
    const paywallsConfig = {
        paywallsAPIHost: config.get('PAYWALLS_CLOUD_API_HOST') || PAYWALLS_CLOUD_API_HOST,
        paywallsAPIKey: config.get('PAYWALLS_API_KEY'),
        paywallsPublisherId: config.get('PAYWALLS_PUBLISHER_ID')
    };
    await loadAgentPatterns(paywallsConfig);

    return async function handle(request) {
        if (await isRecognizedBot(paywallsConfig, request)) {
            const authz = await checkAgentStatus(paywallsConfig, request);

            await logAccess(paywallsConfig, request, authz);

            if (authz.access === 'deny') {
                return setCloudFrontHeaders(authz);
            }
        }
    };
}


/**
 * Initializes the appropriate handler based on the CDN.
 * @param {string} cdn - The name of the CDN (e.g., 'cloudflare', 'fastly', 'cloudfront').
 * @returns {Function} - The handler function for the specified CDN.
 */
export async function init(cdn, config = {}) {

    switch (cdn.toLowerCase()) {
        case 'cloudflare':
            return await cloudflare(config);
        case 'fastly':
            return await fastly(config);
        case 'cloudfront':
            return await cloudfront(config);
        default:
            throw new Error(`Unsupported CDN: ${cdn}`);
    }
}
