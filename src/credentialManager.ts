import { v4 as uuidv4 } from "uuid";
import {
  RequestSchema,
  AuthCredentialsDisplayInfo,
  MakeRequestResponse,
  Oauth2Config,
} from "grindery-nexus-common-utils/dist/types";
import { getCollection } from "./db";
import { makeRequestBasicDigest, makeRequestInternal, updateHeaders, verifyRequestSchema } from "./request";
import { replaceTokens, InvalidParamsError, getConnectorSchema } from "grindery-nexus-common-utils";
import { AUD_CREDENTIAL_TOKEN, decryptJWT, encryptJWT, parseUserAccessToken } from "./jwt";

async function verifyConnectorId(connectorId: string) {
  if (typeof connectorId !== "string" || !/^[a-zA-Z0-9-_]+$/.test(connectorId)) {
    throw new InvalidParamsError("Invalid connector ID");
  }
  if (!(await getConnectorSchema(connectorId, "production"))) {
    throw new InvalidParamsError(`Connector ${connectorId} doesn't exist`);
  }
}

export async function putConnectorSecrets({
  connectorId,
  secrets,
}: {
  connectorId: string;
  secrets: { [key: string]: unknown };
}) {
  await verifyConnectorId(connectorId);
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
async function getCredentialToken({ userId, credentialKey }: { userId: string; credentialKey: string }) {
  return await encryptJWT({ aud: AUD_CREDENTIAL_TOKEN, sub: userId, credentialKey }, "100y");
}
export async function putAuthCredentials({
  connectorId,
  accessToken,
  authCredentials,
  displayName,
}: {
  connectorId: string;
  accessToken: string;
  authCredentials: RequestSchema | object;
  displayName: string;
}) {
  await verifyConnectorId(connectorId);
  const parsedToken = await parseUserAccessToken(accessToken);
  const userId = parsedToken.sub || "";
  if (typeof authCredentials !== "object") {
    throw new InvalidParamsError("Invalid auth credentials");
  }
  if ("url" in authCredentials) {
    verifyRequestSchema(authCredentials as RequestSchema);
  }
  if (typeof displayName !== "string" || !displayName) {
    throw new InvalidParamsError("Invalid display name");
  }
  const connector = await getConnectorSchema(connectorId, "production");
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
  const key = uuidv4();
  await collection.insertOne({
    key,
    connectorId,
    userId,
    authCredentials: JSON.stringify(authCredentials),
    displayName,
    updatedAt: Date.now(),
    createdAt: Date.now(),
  });
  return { id: key, token: await getCredentialToken({ userId, credentialKey: key }) };
}
export async function getAuthCredentialsDisplayInfo({
  connectorId,
  accessToken,
}: {
  connectorId: string;
  accessToken: string;
}): Promise<AuthCredentialsDisplayInfo[]> {
  await verifyConnectorId(connectorId);
  const parsedToken = await parseUserAccessToken(accessToken);
  const userId = parsedToken.sub || "";
  const collection = await getCollection("authCredentials");
  const docs = await collection.find({ connectorId, userId }).toArray();
  const ret = docs.map(
    (doc) =>
      ({
        id: doc.key,
        name: doc.displayName?.toString() || "<unknown>",
        createdAt: new Date(doc.createdAt).toISOString(),
      } as AuthCredentialsDisplayInfo)
  );
  for (const item of ret) {
    item.token = await getCredentialToken({ userId, credentialKey: item.id });
  }
  return ret;
}

async function refreshOauth2AccessToken({
  connectorId,
  userId,
  credentials,
  authConfig,
  displayName,
}: {
  connectorId: string;
  userId: string;
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
  await putAuthCredentials({ connectorId, accessToken: userId, authCredentials: credentials as object, displayName });
  return credentials;
}

export async function makeRequest({
  connectorId,
  credentialToken,
  request,
}: {
  connectorId: string;
  credentialToken: string;
  request: RequestSchema;
}): Promise<MakeRequestResponse> {
  await verifyConnectorId(connectorId);
  const { payload } = await decryptJWT(credentialToken, { audience: AUD_CREDENTIAL_TOKEN });
  const userId = payload.sub || "";
  verifyRequestSchema(request);
  const connector = await getConnectorSchema(connectorId, "production");
  if (!connector) {
    throw new InvalidParamsError("Unknown connector ID");
  }
  const collection = await getCollection("authCredentials");
  const doc = await collection.findOne({ connectorId, key: String(payload.credentialKey) });
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
          userId,
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
        userId,
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
export async function getConnectorAuthorizeUrl({
  connectorId,
  environment,
}: {
  connectorId: string;
  environment: string;
}) {
  const connector = await getConnectorSchema(connectorId, environment);
  if (!connector) {
    throw new InvalidParamsError("Unknown connector ID");
  }
  let url: string;
  if (connector.authentication?.type === "oauth2") {
    url = connector.authentication?.oauth2Config.authorizeUrl;
  } else {
    throw new InvalidParamsError("Connector doesn't support authorization");
  }
  const secretsConnection = await getCollection("connectorSecrets");
  const secretsDoc = await secretsConnection.findOne({ connectorId });
  const secrets = JSON.parse(secretsDoc?.secrets || "{}");
  return replaceTokens(url, { secrets });
}
export async function completeConnectorAuthorization({
  connectorId,
  environment,
  params,
  accessToken,
  displayName,
}: {
  connectorId: string;
  environment: string;
  params: { code: string; redirect_uri: string };
  accessToken: string;
  displayName: string;
}) {
  const connector = await getConnectorSchema(connectorId, environment);
  if (!connector) {
    throw new InvalidParamsError("Unknown connector ID");
  }
  let request: RequestSchema;
  if (connector.authentication?.type === "oauth2") {
    request = connector.authentication.oauth2Config.getAccessToken;
  } else {
    throw new InvalidParamsError("Connector doesn't support authorization");
  }
  const secretsConnection = await getCollection("connectorSecrets");
  const secretsDoc = await secretsConnection.findOne({ connectorId });
  const secrets = JSON.parse(secretsDoc?.secrets || "{}");
  const resp = await makeRequestInternal(replaceTokens(request, { ...params, secrets }));
  const internalCredentials = await putAuthCredentials({
    connectorId,
    accessToken,
    authCredentials: resp.data as object,
    displayName,
  });
  return { ...(resp.data as object), _grinderyCredentialToken: internalCredentials.token };
}
