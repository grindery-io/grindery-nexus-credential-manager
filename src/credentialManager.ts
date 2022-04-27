import { InvalidParamsError } from "./jsonrpc";
import { RequestSchema, AuthCredentialsDisplayInfo, MakeRequestResponse, Oauth2Config } from "./types";
import { getCollection } from "./db";
import { DEMO_CONNECTORS } from "./demoConnectors";
import {
  makeRequestBasicDigest,
  makeRequestInternal,
  replaceTokens,
  updateHeaders,
  verifyRequestSchema,
} from "./request";

function verifyDid(did: string) {
  if (typeof did !== "string" || !/^did:[^:]+:.+$/.test(did)) {
    throw new InvalidParamsError("Invalid DID");
  }
}
function verifyConnectorId(connectorId: string) {
  if (typeof connectorId !== "string" || !/^[a-zA-Z0-9-_]+$/.test(connectorId)) {
    throw new InvalidParamsError("Invalid connector ID");
  }
  if (!(connectorId in DEMO_CONNECTORS)) {
    throw new InvalidParamsError("Unknown connector ID");
  }
}

export async function putConnectorSecrets(connectorId: string, secrets: { [key: string]: unknown }) {
  verifyConnectorId(connectorId);
  if (typeof secrets !== "object") {
    throw new InvalidParamsError("Invalid secrets");
  }
  const collection = await getCollection("connectorSecrets");
  await collection.replaceOne(
    { connectorId },
    { connectorId, secrets: JSON.stringify(secrets), updatedAt: Date.now() },
    { upsert: true }
  );
}
export async function putAuthCredentials(
  connectorId: string,
  userDid: string,
  authCredentials: RequestSchema | object,
  displayName: string
) {
  verifyConnectorId(connectorId);
  verifyDid(userDid);
  if (typeof authCredentials !== "object") {
    throw new InvalidParamsError("Invalid auth credentials");
  }
  if ("url" in authCredentials) {
    verifyRequestSchema(authCredentials as RequestSchema);
  }
  if (typeof displayName !== "string" || !displayName) {
    throw new InvalidParamsError("Invalid display name");
  }
  const connector = DEMO_CONNECTORS[connectorId];
  if (!connector) {
    throw new InvalidParamsError("Unknown connector ID");
  }
  const authType = connector.authentication?.type;
  if (authType === "basic" || authType === "digest") {
    if (typeof authCredentials !== "object" || !("username" in authCredentials) || !("password" in authCredentials)) {
      throw new InvalidParamsError("Invalid auth credentials");
    }
  }
  const collection = await getCollection("authCredentials");
  const existingDoc = await collection.findOne({ connectorId, userDid });
  const result = await collection.replaceOne(
    { connectorId, userDid },
    {
      connectorId,
      userDid,
      authCredentials: JSON.stringify(authCredentials),
      displayName,
      updatedAt: Date.now(),
      createdAt: existingDoc?.createdAt ?? Date.now(),
    },
    { upsert: true }
  );
  return result.upsertedId.toString();
}
export async function getAuthCredentialsDisplayInfo(
  connectorId: string,
  userDid: string
): Promise<AuthCredentialsDisplayInfo[]> {
  verifyConnectorId(connectorId);
  verifyDid(userDid);
  const collection = await getCollection("authCredentials");
  const docs = await collection.find({ connectorId, userDid }).toArray();
  return docs.map((doc) => ({
    id: doc._id.toString(),
    name: doc.displayName?.toString() || "<unknown>",
    createdAt: new Date(doc.createdAt).toISOString(),
  }));
}

async function refreshOauth2AccessToken({
  connectorId,
  userDid,
  credentials,
  authConfig,
  displayName,
}: {
  connectorId: string;
  userDid: string;
  credentials: unknown;
  authConfig: Oauth2Config;
  displayName: string;
}) {
  if (!authConfig?.refreshAccessToken) {
    throw new Error("We don't know how to refresh access tokens for this connector");
  }
  const secretsConnection = await getCollection("connectorSecrets");
  const secretsDoc = await secretsConnection.findOne({ connectorId });
  const secrets = JSON.parse(secretsDoc?.secrets || "{}");
  const refreshRequest = replaceTokens(authConfig.refreshAccessToken, { auth: credentials, secrets });
  const refreshResponse = await makeRequestInternal(refreshRequest);
  credentials = refreshResponse.data;
  await putAuthCredentials(connectorId, userDid, credentials as object, displayName);
  return credentials;
}

export async function makeRequest(
  connectorId: string,
  userDid: string,
  request: RequestSchema
): Promise<MakeRequestResponse> {
  verifyConnectorId(connectorId);
  verifyDid(userDid);
  verifyRequestSchema(request);
  const connector = DEMO_CONNECTORS[connectorId];
  if (!connector) {
    throw new InvalidParamsError("Unknown connector ID");
  }
  const collection = await getCollection("authCredentials");
  const doc = await collection.findOne({ connectorId, userDid });
  if (!doc) {
    throw new InvalidParamsError("No credentials found");
  }
  let credentials = JSON.parse(doc.authCredentials);
  const originalRequest = request;
  request = replaceTokens(request, { auth: credentials });
  const authType = connector.authentication?.type;
  if (authType === "basic") {
    request.auth = [credentials.username, credentials.password];
  }
  if (authType === "basic" || authType === "digest") {
    return await makeRequestBasicDigest(request, credentials.username, credentials.password);
  }
  if (authType === "oauth2") {
    let accessTokenRefreshed = false;
    const authConfig = connector.authentication?.oauth2Config;
    if (authConfig?.refreshAccessToken && authConfig?.autoRefresh && credentials.expires_in) {
      const expiresAt = doc.updatedAt + credentials.expires_in * 1000;
      if (expiresAt < Date.now() + 10000) {
        credentials = await refreshOauth2AccessToken({
          connectorId,
          userDid,
          credentials,
          authConfig,
          displayName: doc.displayName,
        });
        accessTokenRefreshed = true;
      }
    }
    request = replaceTokens(originalRequest, { auth: credentials });
    if (credentials.access_token) {
      request.headers = updateHeaders(request.headers || {}, {
        Authorization: `Bearer ${credentials.access_token}`,
      });
    }
    try {
      return await makeRequestInternal(request);
    } catch (e) {
      if (e.response?.status !== 401) {
        throw e;
      }
      if (accessTokenRefreshed || !authConfig?.refreshAccessToken || !authConfig?.autoRefresh) {
        throw e;
      }
      credentials = await refreshOauth2AccessToken({
        connectorId,
        userDid,
        credentials,
        authConfig,
        displayName: doc.displayName,
      });
      accessTokenRefreshed = true;
      request = replaceTokens(originalRequest, { auth: credentials });
      if (credentials.access_token) {
        request.headers = updateHeaders(request.headers || {}, {
          Authorization: `Bearer ${credentials.access_token}`,
        });
      }
      return await makeRequestInternal(request);
    }
  }
  throw new Error("Not implemented");
}
