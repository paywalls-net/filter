# paywalls-net/filter

SDK for integrating paywalls.net authorization services with CDN or edge environments.

## Install

```bash
npm install @paywalls-net/filter
```

## Environment Variables
- `PAYWALLS_PUBLISHER_ID`: The unique identifier for the publisher using paywalls.net services.
- `PAYWALLS_CLOUD_API_HOST`: The host for the paywalls.net API. eg `https://cloud-api.paywalls.net`.
- `PAYWALLS_CLOUD_API_KEY`: The API key for accessing paywalls.net services. NOTE: This key should be treated like a password and kept secret and stored in a secure secrets vault or environment variable.

## Usage
```javascript
import { init } from '@paywalls-net/filter';

const handleRequest = await init('cloudflare');

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};
```

