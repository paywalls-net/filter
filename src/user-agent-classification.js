import { UAParser } from 'ua-parser-js';

const userAgentPatterns = [
    {
        operator: 'Anthropic',
        agent: 'ClaudeBot',
        usage: ['ai_training'],
        user_initiated: 'no',
        patterns: [/ClaudeBot/, /anthropic-ai/]
    },
    {
        operator: 'Anthropic',
        agent: 'Claude-User',
        usage: ['ai_chat'],
        user_initiated: 'yes',
        patterns: [/Claude-User/]
    },
    {
        operator: 'Anthropic',
        agent: 'Claude-SearchBot',
        usage: ['ai_indexing'],
        user_initiated: 'maybe',
        patterns: [/Claude-SearchBot/]
    },

    {
        operator: 'Lumar',
        agent: 'DeepCrawl',
        usage: ['webmaster tools'],
        user_initiated: 'no',
        patterns: [/deepcrawl.com/]
    },

    {
        operator: 'Google',
        agent: 'Googlebot',
        usage: ['search_indexing','ai_training'],
        user_initiated: 'maybe',
        patterns: [/Googlebot/]
    },
    {
        operator: 'Google',
        agent: 'Gemini-Deep-Research',
        usage: ['ai_agents'],
        user_initiated: 'maybe',
        patterns: [/Gemini-Deep-Research/]
    }, 
    {
        operator: 'Google',
        agent: 'Google-Extended',
        usage: ['ai_training'],
        usage_prefs_only: true,
        user_initiated: 'no',
    },
    {
        operator: 'Google',
        agent: 'Googlebot-News',
        usage: ['Google News'],
        usage_prefs_only: true,
        user_initiated: 'no'
    },    
    {
        operator: 'Google',
        agent: 'Googlebot-Image',
        usage: ['image indexing'],
        user_initiated: 'no',
        patterns: [/Googlebot-Image/]
    },
    {
        operator: 'Google',
        agent: 'Google-Site-Verification',
        usage: ['site verification'],
        user_initiated: 'no',
        patterns: [/Google-Site-Verification/]
    },
    {
        operator: 'Google',
        agent: 'Google Web Preview',
        usage: ['web preview'],
        user_initiated: 'no',
        patterns: [/Google Web Preview/]
    },
    {
        operator: 'Google',
        agent: 'Googlebot-Video',
        usage: ['video indexing'],
        user_initiated: 'no',
        patterns: [/Googlebot-Video/]
    },
    {
        operator: 'Google',
        agent: 'FeedFetcher-Google',
        usage: ['Feed crawling'],
        user_initiated: 'yes',
        patterns: [/FeedFetcher-Google/]
    },

    {
        operator: 'OpenAI',
        agent: 'GPTBot',
        usage: ['ai_training'],
        user_initiated: 'no',
        patterns: [/GPTBot/]
    },
    {
        operator: 'OpenAI',
        agent: 'OAI-SearchBot',
        usage: ['ai_indexing'],
        user_initiated: 'no',
        patterns: [/OAI-SearchBot/]
    },
    {
        operator: 'OpenAI',
        agent: 'ChatGPT-User',
        usage: ['ai_chat'],
        user_initiated: 'yes',
        patterns: [/ChatGPT-User/]
    },

   
    {
        operator: 'Meta',
        agent: 'facebookexternalhit',
        usage: ['content sharing'],
        user_initiated: 'no',
        patterns: [/facebookexternalhit/]
    },
    {
        operator: 'Meta',
        agent: 'meta-externalagent',
        usage: ['ai_training'],
        user_initiated: 'no',
        patterns: [/meta-externalagent/]
    },
    {
        operator: 'Meta',
        agent: 'meta-externalfetcher',
        usage: ['web preview'],
        user_initiated: 'no',
        patterns: [/meta-externalfetcher/]
    },

    {
        operator: 'Perplexity',
        agent: 'Perplexity-User',
        usage: ['ai_chat'],
        user_initiated: 'yes',
        patterns: [/Perplexity-User/]
    },
    {
        operator: 'Perplexity',
        agent: 'PerplexityBot',
        usage: ['ai_indexing'],
        user_initiated: 'maybe',
        patterns: [/PerplexityBot/]
    },
    
    {
        operator: 'Cohere',
        agent: 'cohere-ai',
        usage: ['ai_training'],
        user_initiated: 'no',
        patterns: [/cohere-ai/i]
    },

    {
        operator: 'Bing',
        agent: 'BingBot',
        usage: ['search_indexing','ai_indexing'],
        user_initiated: 'maybe',
        patterns: [/bingbot/i, /BingPreview/]
    },

    {
        operator: 'Microsoft',
        agent: 'BF-DirectLine',
        usage: ['Bot Framework SDK'],
        user_initiated: 'no',
        patterns: [/BF-DirectLine/]
    }
];

/**
 * Classifies the user agent string based on predefined patterns.
 * @param {string} userAgent - The user agent string to classify.
 * @returns {Object} An object containing the browser, OS, operator, usage, and user_initiated status.
 */
export function classifyUserAgent(userAgent) {
    const parsedUA = new UAParser(userAgent).getResult();

    const browser = parsedUA.browser.name || 'Unknown';
    const os = parsedUA.os.name || 'Unknown';

    for (const config of userAgentPatterns) {
        if (!config.patterns) continue;
        for (const pattern of config.patterns) {
            if (pattern.test(userAgent)) {
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
