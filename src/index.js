/**
 * Example publisher-hosted client code for a Cloudflare Worker that
 * filters bot-like requests by using paywalls.net authorization services.
 */
const sdk_version = "1.2.x";
import { classifyUserAgent, loadAgentPatterns } from './user-agent-classification.js';

const PAYWALLS_CLOUD_API_HOST = "https://cloud-api.paywalls.net";

function detectRuntime() {
    if (typeof process !== "undefined" && process.versions && process.versions.node) {
        return `Node.js/${process.versions.node}`;
    } else if (typeof navigator !== "undefined" && navigator.userAgent) {
        return `Browser/${navigator.userAgent}`;
    } else if (typeof globalThis !== "undefined" && globalThis.Deno && Deno.version) {
        return `Deno/${Deno.version.deno}`;
    } else if (typeof globalThis !== "undefined" && globalThis.Bun && Bun.version) {
        return `Bun/${Bun.version}`;
    }
    return "unknown";
}

function detectFetchVersion() {
    if (typeof fetch !== "undefined" && fetch.name) {
        return fetch.name;
    } else if (typeof globalThis !== "undefined" && globalThis.fetch) {
        return "native";
    } else {
        return "unavailable";
    }
}

let runtime = detectRuntime();
let fetchVersion = detectFetchVersion();
const sdkUserAgent = `pw-filter-sdk/${sdk_version} (${runtime}; fetch/${fetchVersion})`;

function getAllHeaders(request) {
    // Get all headers as a plain object (name-value pairs)
    let headers = {};
    if (typeof request.headers.entries === "function") {
        // Standard Headers object (e.g., in Cloudflare Workers)
        for (const [key, value] of request.headers.entries()) {
            headers[key] = value;
        }
    } else {
        // CloudFront headers object
        for (const key in request.headers) {
            headers[key] = request.headers[key][0]?.value || "";
        }
    }
    return headers;
}

/**
 * Check if the request is for a VAI endpoint (vai.json or vai.js)
 * @param {Request} request - The incoming request
 * @param {string} vaiPath - The path prefix for VAI endpoints (default: '/pw')
 * @returns {boolean} - True if this is a VAI endpoint request
 */
function isVAIRequest(request, vaiPath = '/pw') {
    try {
        const url = new URL(request.url || `http://host${request.uri || ''}`);
        const pathname = url.pathname;
        return pathname === `${vaiPath}/vai.json` || pathname === `${vaiPath}/vai.js`;
    } catch (err) {
        return false;
    }
}

/**
 * Proxy VAI requests to the cloud-api service
 * @param {Object} cfg - Configuration object with paywallsAPIHost and paywallsAPIKey
 * @param {Request} request - The incoming request
 * @returns {Promise<Response>} - The proxied response from cloud-api
 */
async function proxyVAIRequest(cfg, request) {
    try {
        const url = new URL(request.url || `http://host${request.uri || ''}`);
        const isJson = url.pathname.endsWith('/vai.json');
        const cloudApiPath = isJson ? '/pw/vai.json' : '/pw/vai.js';
        
        // Get all request headers
        const headers = getAllHeaders(request);
        
        // Build forwarding headers
        const forwardHeaders = {
            'User-Agent': headers['user-agent'] || sdkUserAgent,
            'Authorization': `Bearer ${cfg.paywallsAPIKey}`
        };
        
        // Add forwarding headers if available
        if (headers['x-forwarded-for']) {
            forwardHeaders['X-Forwarded-For'] = headers['x-forwarded-for'];
        } else if (headers['cf-connecting-ip']) {
            forwardHeaders['X-Forwarded-For'] = headers['cf-connecting-ip'];
        }
        
        if (headers['host']) {
            forwardHeaders['X-Original-Host'] = headers['host'];
        }
        
        // Forward request to cloud-api
        const response = await fetch(`${cfg.paywallsAPIHost}${cloudApiPath}`, {
            method: 'GET',
            headers: forwardHeaders
        });
        
        if (!response.ok) {
            console.error(`VAI proxy error: ${response.status} ${response.statusText}`);
        }
        
        return response;
    } catch (err) {
        console.error(`Error proxying VAI request: ${err.message}`);
        return new Response('Internal Server Error', { status: 500 });
    }
}

async function logAccess(cfg, request, access) {
    // Separate html from the status in the access object.
    const { response, ...status } = access;

    // Get all headers as a plain object (name-value pairs)
    let headers = getAllHeaders(request);

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
            "User-Agent": sdkUserAgent,
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
    let headers = getAllHeaders(request);
    const agentInfo = await classifyUserAgent(cfg, userAgent);

    const body = JSON.stringify({
        account_id: cfg.paywallsPublisherId,
        operator: agentInfo.operator,
        agent: agentInfo.agent,
        token: token,
        headers: headers
    });

    const response = await fetch(`${cfg.paywallsAPIHost}/api/filter/agents/auth`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "User-Agent": sdkUserAgent,
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
    try {
        // check if the URL has a query parameter to always test as a bot
        const url = new URL(request.url || request.uri);
        const uaParam = url.searchParams.get("user-agent");
        return uaParam && uaParam.includes("bot");
    } catch (err) {
        throw new Error(`test bot failed: ${request.url} | ${request.uri} | ${err.message}`);
    }
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
            paywallsPublisherId: env.PAYWALLS_PUBLISHER_ID,
            vaiPath: env.PAYWALLS_VAI_PATH || '/pw'
        };
        
        // Check if this is a VAI endpoint request and proxy it
        if (isVAIRequest(request, paywallsConfig.vaiPath)) {
            return await proxyVAIRequest(paywallsConfig, request);
        }
        
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


async function fastly() {

    return async function handle(request, config, ctx) {
        const paywallsConfig = {
            paywallsAPIHost: config.get('PAYWALLS_CLOUD_API_HOST') || PAYWALLS_CLOUD_API_HOST,
            paywallsAPIKey: config.get('PAYWALLS_API_KEY'),
            paywallsPublisherId: config.get('PAYWALLS_PUBLISHER_ID'),
            vaiPath: config.get('PAYWALLS_VAI_PATH') || '/pw'
        };
        
        // Check if this is a VAI endpoint request and proxy it
        if (isVAIRequest(request, paywallsConfig.vaiPath)) {
            return await proxyVAIRequest(paywallsConfig, request);
        }

        await loadAgentPatterns(paywallsConfig);

        if (await isRecognizedBot(paywallsConfig, request)) {
            const authz = await checkAgentStatus(paywallsConfig, request);

            await logAccess(paywallsConfig, request, authz);

            if (authz.access === 'deny') {
                return setHeaders(authz);
            }
        }
    };
}
/**
 * Convert a standard Response to CloudFront format
 * @param {Response} response - Standard fetch Response object
 * @returns {Promise<Object>} - CloudFront-formatted response
 */
async function responseToCloudFront(response) {
    const headers = {};
    
    // Convert response headers to CloudFront format
    for (const [key, value] of response.headers.entries()) {
        headers[key.toLowerCase()] = [
            {
                key: key,
                value: value
            }
        ];
    }
    
    const body = await response.text();
    
    return {
        status: response.status,
        statusDescription: response.statusText || 'OK',
        headers: headers,
        body: body
    };
}

/**
 * Adapt to CloudFront format
 * Lambda@Edge events see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-event-structure.html#lambda-event-structure-request
 * CloudFront events see https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/functions-event-structure.html#functions-event-structure-example
 * @param {*} request 
 * @returns 
 */
function requestShim(request) {
    if (!request.headers.get) {
        // add get() to headers object to adapt to CloudFront
        request.headers.get = (name) => {
            const header = request.headers[name.toLowerCase()];
            return header ? header[0].value : null;
        };
    }

    // combine the CloudFront host, request.uri and request.querystring into request.url
    if (!request.url && request.uri) {
        let host = request.headers.get('host');
        request.url = `http://${host}${request.uri}`;
        if (request.querystring) {
            request.url += `?${request.querystring}`;
        }
    }

    return request;
}

async function cloudfront(config) {
    const paywallsConfig = {
        paywallsAPIHost: config.PAYWALLS_CLOUD_API_HOST || PAYWALLS_CLOUD_API_HOST,
        paywallsAPIKey: config.PAYWALLS_API_KEY,
        paywallsPublisherId: config.PAYWALLS_PUBLISHER_ID,
        vaiPath: config.PAYWALLS_VAI_PATH || '/pw'
    };
    await loadAgentPatterns(paywallsConfig);

    return async function handle(event, ctx) {
        let request = event.Records[0].cf.request;
        request = requestShim(request);
        
        // Check if this is a VAI endpoint request and proxy it
        if (isVAIRequest(request, paywallsConfig.vaiPath)) {
            const response = await proxyVAIRequest(paywallsConfig, request);
            return await responseToCloudFront(response);
        }
        
        if (await isRecognizedBot(paywallsConfig, request)) {
            const authz = await checkAgentStatus(paywallsConfig, request);

            // log the result asynchronously
            ctx.callbackWaitsForEmptyEventLoop = false;
            logAccess(paywallsConfig, request, authz);

            if (authz.access === 'deny') {
                return setCloudFrontHeaders(authz);
            }
        }
    };
}


/**
 * Initializes the appropriate handler based on the CDN.
 * @param {string} cdn - The name of the CDN (e.g., 'cloudflare', 'fastly', 'cloudfront').
 * @param {Object} [config={}] - Optional configuration object for the CDN handler.
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
