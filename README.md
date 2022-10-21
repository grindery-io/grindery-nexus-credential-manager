# Grindery Nexus Credential Manager

## Development

Run `npm run server` to start locally. All JSON-RPC methods are callable via the HTTP endpoint. Almost all of the methods require authentication, please go to https://nexus.grindery.org/ and sign in, then get your token from dev tools.

## Deployment

Pushing to the repository will trigger a deployment to the live Grindery GKE cluster. A deployment should complete in ~5 minutes.

## Driver API requests

Driver API requests will go through the orchestrator like: `https://orchestrator.grindery.org/credentials/authTest/request/httpbin.org/get` , with Authorization header set to the credential manager token (sent via `authentication` field in WebSocket message). The credential manager will fetch real credentials from DB and forward the request.

Driver should read the URL prefix from the environment variable CREDENTIAL_MANAGER_REQUEST_PREFIX, which includes $CDS_NAME token and should be replaced with CDS file name (excluding .json) of the driver. If the driver is in development outside the production K8s cluster, the environment variable should be set to:

```
https://orchestrator.grindery.org/credentials/$CDS_NAME/request/
```

In this case, the driver is usable only from the staging environment. Before going live, be sure to deploy the driver to the production K8s cluster and update its CDS file accordingly.

No HTTP headers other than Content-Type are forwarded. To send extra headers, use one of the following headers:

```
X-Grindery-Request-HEADER: VALUE
X-Grindery-Request-Base64-HEADER: BASE64-ENCODED-VALUE
```

By default, credential manager will only run template replacement for HTTP headers. To run template replacement for request URL and body as well, send following header:

```
X-Grindery-Template-Scope: all
```
