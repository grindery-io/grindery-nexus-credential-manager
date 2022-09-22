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
import { CredentialToken, TAccessToken } from "./jwt";
import { Context } from "./server";
import _ from "lodash";
import { AxiosResponse } from "axios";

async function verifyConnectorId(connectorId: string, environment: string) {
  if (typeof connectorId !== "string" || !/^[a-zA-Z0-9-_]+$/.test(connectorId)) {
    throw new InvalidParamsError("Invalid connector ID");
  }
  if (!(await getConnectorSchema(connectorId, environment))) {
    throw new InvalidParamsError(`Connector ${connectorId} doesn't exist`);
  }
}

export async function putConnectorSecrets({
  connectorId,
  secrets,
  environment,
}: {
  connectorId: string;
  secrets: { [key: string]: unknown };
  environment: string;
}) {
  await verifyConnectorId(connectorId, environment);
  if (typeof secrets !== "object") {
    throw new InvalidParamsError("Invalid secrets");
  }
  const collection = await getCollection("connectorSecrets");
  await collection.replaceOne(
    { connectorId, environment },
    { connectorId, environment, secrets: JSON.stringify(secrets), updatedAt: Date.now() },
    { upsert: true }
  );
}
function getUserId(user?: TAccessToken): string {
  if (!user?.sub) {
    throw new Error("Not authorized");
  }
  if ("workspace" in user && user.workspace) {
    return "grindery:workspace:" + user.workspace;
  }
  return user.sub;
}
async function putAuthCredentialsInternal({
  connectorId,
  authCredentials,
  displayName,
  environment,
  userId,
}: {
  connectorId: string;
  authCredentials: RequestSchema | object;
  displayName: string;
  environment: string;
  userId: string;
}) {
  await verifyConnectorId(connectorId, environment);
  if (typeof authCredentials !== "object") {
    throw new InvalidParamsError("Invalid auth credentials");
  }
  if ("url" in authCredentials) {
    verifyRequestSchema(authCredentials as RequestSchema);
  }
  if (typeof displayName !== "string" || !displayName) {
    throw new InvalidParamsError("Invalid display name");
  }
  const connector = await getConnectorSchema(connectorId, environment);
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
    environment,
    authCredentials: JSON.stringify(authCredentials),
    displayName,
    updatedAt: Date.now(),
    createdAt: Date.now(),
  });
  return { key, token: await CredentialToken.encrypt({ sub: userId, credentialKey: key }, "1000y") };
}
export async function putAuthCredentials(
  {
    connectorId,
    authCredentials,
    displayName,
    environment,
  }: {
    connectorId: string;
    authCredentials: RequestSchema | object;
    displayName: string;
    environment: string;
  },
  { context: { user } }: { context: Context }
) {
  return await putAuthCredentialsInternal({
    connectorId,
    authCredentials,
    displayName,
    environment,
    userId: getUserId(user),
  });
}
export async function updateAuthCredentials(
  {
    key,
    displayName,
    environment,
  }: {
    key: string;
    displayName: string;
    environment: string;
  },
  { context: { user } }: { context: Context }
) {
  const userId = getUserId(user);
  const collection = await getCollection("authCredentials");
  const result = await collection.updateOne(
    { key, userId, environment },
    { $set: { displayName, updatedAt: Date.now() } }
  );
  if (!result.matchedCount) {
    throw new Error("Credential not found");
  }
  return result.matchedCount > 0;
}
export async function deleteAuthCredentials(
  {
    key,
    environment,
  }: {
    key: string;
    environment: string;
  },
  { context: { user } }: { context: Context }
) {
  const userId = getUserId(user);
  const collection = await getCollection("authCredentials");
  const result = await collection.deleteOne({ key, userId, environment });
  return result.deletedCount > 0;
}
export async function getAuthCredentialsDisplayInfo(
  {
    connectorId,
    environment,
  }: {
    connectorId: string;
    environment: string;
  },
  { context: { user } }: { context: Context }
): Promise<AuthCredentialsDisplayInfo[]> {
  await verifyConnectorId(connectorId, environment);
  const userId = getUserId(user);
  const collection = await getCollection("authCredentials");
  const docs = await collection.find({ connectorId, userId, environment }).toArray();
  const ret = docs.map(
    (doc) =>
      ({
        key: doc.key,
        name: doc.displayName?.toString() || "<unknown>",
        createdAt: new Date(doc.createdAt).toISOString(),
      } as AuthCredentialsDisplayInfo)
  );
  for (const item of ret) {
    item.token = await CredentialToken.encrypt({ sub: userId, credentialKey: item.key }, "1000y");
  }
  return ret;
}

async function refreshOauth2AccessToken({
  key,
  connectorId,
  credentials,
  authConfig,
  environment,
}: {
  key: string;
  connectorId: string;
  credentials: unknown;
  authConfig: Oauth2Config;
  environment: string;
}) {
  if (!authConfig?.refreshAccessToken) {
    throw new Error("We don't know how to refresh access tokens for this connector");
  }
  const secretsCollection = await getCollection("connectorSecrets");
  const secretsDoc = await secretsCollection.findOne({ connectorId, environment });
  const secrets = JSON.parse(secretsDoc?.secrets || "{}");
  const refreshRequest = replaceTokens(authConfig.refreshAccessToken, { auth: credentials, secrets });
  const refreshResponse = await makeRequestInternal(refreshRequest);
  credentials = refreshResponse.data;
  const credentialCollection = await getCollection("authCredentials");
  await credentialCollection.updateOne(
    {
      key,
    },
    { $set: { authCredentials: JSON.stringify(credentials), updatedAt: Date.now() } }
  );
  return credentials;
}

export async function makeRequest({
  connectorId,
  credentialToken,
  request,
  environment,
}: {
  connectorId: string;
  credentialToken: string;
  request: RequestSchema;
  environment: string;
}): Promise<MakeRequestResponse> {
  await verifyConnectorId(connectorId, environment);
  const payload = await CredentialToken.decrypt(credentialToken);
  verifyRequestSchema(request);
  const connector = await getConnectorSchema(connectorId, environment);
  if (!connector) {
    throw new InvalidParamsError("Unknown connector ID");
  }
  const collection = await getCollection("authCredentials");
  const doc = await collection.findOne({ connectorId, environment, key: String(payload.credentialKey) });
  if (!doc) {
    throw new InvalidParamsError("No credentials found");
  }
  let credentials = JSON.parse(doc.authCredentials);
  const originalRequest = _.merge(connector.authentication?.authenticatedRequestTemplate || {}, request);
  request = replaceTokens(originalRequest, { auth: credentials });
  const authType = connector.authentication?.type;
  if (authType === "basic") {
    request.auth = [credentials.username, credentials.password];
  }
  try {
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
            key: String(payload.credentialKey),
            connectorId,
            credentials,
            authConfig,
            environment,
          });
          accessTokenRefreshed = true;
        }
      }
      request = replaceTokens(originalRequest, { auth: credentials });
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
          key: String(payload.credentialKey),
          connectorId,
          credentials,
          authConfig,
          environment,
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
  } catch (e) {
    if (!e.response) {
      throw e;
    }
    const resp = e.response as AxiosResponse;
    return {
      status: resp.status,
      data: resp.data,
      headers: resp.headers,
    };
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
  const secretsCollection = await getCollection("connectorSecrets");
  const secretsDoc = await secretsCollection.findOne({ connectorId, environment });
  const secrets = JSON.parse(secretsDoc?.secrets || "{}");
  return replaceTokens(url, { secrets });
}
export async function completeConnectorAuthorization(
  {
    connectorId,
    environment,
    params,
    displayName,
  }: {
    connectorId: string;
    environment: string;
    params: { code: string; redirect_uri: string };
    displayName: string;
  },
  { context: { user } }: { context: Context }
) {
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
  const secretsCollection = await getCollection("connectorSecrets");
  const secretsDoc = await secretsCollection.findOne({ connectorId, environment });
  const secrets = JSON.parse(secretsDoc?.secrets || "{}");
  const resp = await makeRequestInternal(replaceTokens(request, { ...params, secrets }));
  const internalCredentials = await putAuthCredentials(
    {
      connectorId,
      authCredentials: resp.data as object,
      displayName,
      environment,
    },
    { context: { user } }
  );
  return { ...(resp.data as object), _grinderyCredentialToken: internalCredentials.token };
}
