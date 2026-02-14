# paywalls-net/filter

SDK for paywalls.net authorization and real-time licensing services. For use with CDN or edge environments.

## Install

```bash
npm install @paywalls-net/filter
```

## Environment Variables
- `PAYWALLS_PUBLISHER_ID`: The unique identifier for the publisher using paywalls.net services.
- `PAYWALLS_CLOUD_API_KEY`: The API key for accessing paywalls.net services. NOTE: This key should be treated like a password and kept secret and stored in a secure secrets vault or environment variable.

## Architecture: Path Prefix Ownership

The SDK uses a **path prefix ownership strategy** for VAI (Validated Actor Inventory) endpoints. All requests to `/pw/*` are automatically proxied to the paywalls.net cloud-api service with API key authentication.

### Benefits
- **Version Independent**: New VAI endpoints work automatically without SDK updates
- **Reduced Publisher Friction**: Publishers don't need to update client code when new features are added
- **Future Proof**: Supports nested paths like `/pw/v2/*` or `/pw/analytics/*`

### Proxied Endpoints
Any request matching `/pw/*` is proxied with authentication:
- `/pw/vai.json` - VAI classification (JSON)
- `/pw/vai.js` - VAI classification (JavaScript)
- `/pw/jwks.json` - JSON Web Key Set for signature verification
- Future endpoints automatically supported

This strategy minimizes version coupling between the client SDK and the paywalls.net platform.

## Usage
The following is an example of using the SDK with Cloudflare Workers:

```javascript
import { init } from '@paywalls-net/filter';

// Initialize the paywalls.net handler for Cloudflare
const handleRequest = await init('cloudflare');

export default {
   async fetch(request, env, ctx) {
       let pw_response = await handleRequest(request, env, ctx);
       if (pw_response) {
           // If the handler returns a response, return it
           return pw_response;
       }
       return fetch(request); // Proceed to origin/CDN
   }
};
```

