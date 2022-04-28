import { createJSONRPCErrorResponse, JSONRPCErrorCode, JSONRPCParams, JSONRPCServer } from "json-rpc-2.0";
import {
  getAuthCredentialsDisplayInfo,
  makeRequest,
  putAuthCredentials,
  putConnectorSecrets,
} from "./credentialManager";
import * as Sentry from "@sentry/node";

export class InvalidParamsError extends Error {
  constructor(message?: string) {
    super(message || "Invalid parameters");
  }
}
const exceptionMiddleware = async (next, request, serverParams) => {
  try {
    return await next(request, serverParams);
  } catch (error) {
    if (error instanceof InvalidParamsError) {
      return createJSONRPCErrorResponse(request.id, JSONRPCErrorCode.InvalidParams, error.message);
    } else if (error.isAxiosError) {
      return createJSONRPCErrorResponse(request.id, error.response?.status, error.message, {
        headers: error.response?.headers,
        data: error.response?.data,
      });
    } else {
      Sentry.captureException(error);
      await Sentry.flush(2000);
      throw error;
    }
  }
};
function byPosition(func) {
  return async function (params: Partial<JSONRPCParams> | undefined) {
    if (!Array.isArray(params)) {
      throw new InvalidParamsError("Only positional parameters are supported");
    }
    return func(...params);
  };
}
export function createJsonRpcServer() {
  const server = new JSONRPCServer();
  server.applyMiddleware(exceptionMiddleware);
  server.addMethod("cm_putConnectorSecrets", byPosition(putConnectorSecrets));
  server.addMethod("cm_putAuthCredentials", byPosition(putAuthCredentials));
  server.addMethod("cm_getAuthCredentialsDisplayInfo", byPosition(getAuthCredentialsDisplayInfo));
  server.addMethod("cm_makeRequest", byPosition(makeRequest));
  return server;
}
