import { createJsonRpcServer, forceObject, runJsonRpcServer } from "grindery-nexus-common-utils";

import {
  getAuthCredentialsDisplayInfo,
  makeRequest,
  putAuthCredentials,
  putConnectorSecrets,
  getConnectorAuthorizeUrl,
  completeConnectorAuthorization,
} from "./credentialManager";

function createServer() {
  const server = createJsonRpcServer();
  const methods = {
    putConnectorSecrets,
    putAuthCredentials,
    getAuthCredentialsDisplayInfo,
    makeRequest,
    getConnectorAuthorizeUrl,
    completeConnectorAuthorization,
  };
  for (const [name, func] of Object.entries(methods) as [string, (params: unknown) => Promise<unknown>][]) {
    server.addMethod("cm_" + name, forceObject(func));
    server.addMethod(name, forceObject(func));
  }
  return server;
}

export const server = createServer();
if (require.main === module) {
  runJsonRpcServer(server);
}
