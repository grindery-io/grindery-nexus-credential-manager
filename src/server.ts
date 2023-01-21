import { LoggerAdaptToConsole, LOG_LEVEL } from "console-log-json";
import { createJsonRpcServer, forceObject, runJsonRpcServer, ServerParams } from "grindery-nexus-common-utils";
import {
  getAuthCredentialsDisplayInfo,
  makeRequest,
  putAuthCredentials,
  putConnectorSecrets,
  getConnectorAuthorizeUrl,
  completeConnectorAuthorization,
  updateAuthCredentials,
  deleteAuthCredentials,
  deleteAllAuthCredentials,
} from "./credentialManager";

import {
  createJSONRPCErrorResponse,
  JSONRPCErrorCode,
  JSONRPCRequest,
  JSONRPCServerMiddlewareNext,
} from "json-rpc-2.0";
import assert from "assert";
import { parseUserAccessToken, TAccessToken } from "./jwt";

if (process.env.LOG_JSON) {
  LoggerAdaptToConsole({ logLevel: LOG_LEVEL.debug });
}

export type Context = {
  user?: TAccessToken;
};

const authMiddleware = async (
  next: JSONRPCServerMiddlewareNext<ServerParams>,
  request: JSONRPCRequest,
  serverParams: ServerParams<Context> | undefined
) => {
  let token = "";
  if (serverParams?.req) {
    const m = /Bearer +(.+$)/i.exec(serverParams.req.get("Authorization") || "");
    if (m) {
      token = m[1];
    }
  } else if (["authenticate"].includes(request.method)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    token = (request.params as any)?.token || "";
  }
  if (token) {
    assert(serverParams?.context);
    try {
      serverParams.context.user = await parseUserAccessToken(token);
    } catch (e) {
      return createJSONRPCErrorResponse(request.id || "", JSONRPCErrorCode.InvalidParams, "Invalid access token");
    }
  }
  return await next(request, serverParams);
};

function createServer() {
  const server = createJsonRpcServer<Context>();
  server.applyMiddleware(authMiddleware);
  const methods = {
    putConnectorSecrets,
    putAuthCredentials,
    getAuthCredentialsDisplayInfo,
    updateAuthCredentials,
    deleteAuthCredentials,
    deleteAllAuthCredentials,

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
