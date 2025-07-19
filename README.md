# paywalls-net/client

SDK for integrating paywalls.net authorization services with CDN or edge environments.

## Install

```bash
npm install @paywalls-net/client
```

## Environment Variables
- `PAYWALLS_PUBLISHER_ID`: The unique identifier for the publisher using Paywalls.net services.
- `PAYWALLS_CLOUD_API_HOST`: The host for the Paywalls.net API. eg `https://cloud-api.paywalls.net`.
- `PAYWALLS_CLOUD_API_KEY`: The API key for accessing Paywalls.net services. NOTE: This key should be treated like a password and kept secret and stored in a secure secrets vault or environment variable.

## Usage
```javascript
import { init } from '@paywalls-net/client';

const handleRequest = await init('cloudflare');

export default {
  async fetch(request, env, ctx) {
    return handleRequest(request, env, ctx);
  }
};
```

