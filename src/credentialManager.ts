/* eslint-disable no-catch-shadow */
/* eslint-disable no-use-before-define */
import { URL } from "node:url";
import { v4 as uuidv4 } from "uuid";
import {
  RequestSchema,
  AuthCredentialsDisplayInfo,
  MakeRequestResponse,
  Oauth2Config,
} from "grindery-nexus-common-utils/dist/types";
import { getCollection } from "./db";
import { makeRequestBasicDigest, makeRequestInternal, verifyRequestSchema } from "./request";
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
async function getConnectorSecretDoc({ connectorId, environment }: { connectorId: string; environment: string }) {
  const secretsCollection = await getCollection("connectorSecrets");
  const secretsDoc = await secretsCollection.find({ connectorId, environment }).sort({ createdAt: -1 }).next();
  if (!secretsDoc) {
    throw new InvalidParamsError("Connector secret is not configured");
  }
  return secretsDoc;
}
export async function putConnectorSecrets(
  {
    key,
    connectorId,
    secrets,
    environment,
    forceCreateNew,
  }: {
    key?: string;
    connectorId: string;
    secrets: { [key: string]: unknown };
    environment: string;
    forceCreateNew?: boolean;
  },
  { context: { user } }: { context: Context }
) {
  if (!user || !("workspace" in user) || user.workspace !== "ADMIN") {
    throw new Error("Only admin can update connector secret");
  }
  if (key && forceCreateNew) {
    throw new InvalidParamsError("Can't create new secret when key is set");
  }
  await verifyConnectorId(connectorId, environment);
  if (typeof secrets !== "object") {
    throw new InvalidParamsError("Invalid secrets");
  }
  const collection = await getCollection("connectorSecrets");
  if (!key && !forceCreateNew) {
    const latestDoc = await collection.find({ connectorId, environment }).sort({ createdAt: -1 }).next();
    if (latestDoc) {
      key = latestDoc.key;
    } else {
      forceCreateNew = true;
    }
  }
  if (forceCreateNew) {
    const key = uuidv4();
    await collection.insertOne({
      key,
      connectorId,
      environment,
      secrets: JSON.stringify(secrets),
      updatedAt: Date.now(),
      createdAt: Date.now(),
    });
    return { key };
  }
  const result = await collection.updateOne(
    { connectorId, environment, key },
    { $set: { secrets: JSON.stringify(secrets), updatedAt: Date.now() } }
  );
  if (result.modifiedCount < 1) {
    throw new Error("Invalid connector secret key");
  }
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
  secretKey,
}: {
  connectorId: string;
  authCredentials: RequestSchema | object;
  displayName?: string;
  environment: string;
  userId: string;
  secretKey?: string;
}) {
  await verifyConnectorId(connectorId, environment);
  if (typeof authCredentials !== "object") {
    throw new InvalidParamsError("Invalid auth credentials");
  }
  if ("url" in authCredentials) {
    verifyRequestSchema(authCredentials as RequestSchema);
  }
  if (displayName && typeof displayName !== "string") {
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
  if (!secretKey) {
    const secretDoc = await getConnectorSecretDoc({ connectorId, environment });
    secretKey = secretDoc.key;
  } else {
    const secretsCollection = await getCollection("connectorSecrets");
    if (!(await secretsCollection.findOne({ connectorId, environment, key: secretKey }))) {
      throw new InvalidParamsError("Invalid connector secret key");
    }
  }
  const collection = await getCollection("authCredentials");
  const key = uuidv4();
  const ts = Date.now();
  const tsString = new Date(ts).toISOString();
  await collection.insertOne({
    key,
    connectorId,
    userId,
    environment,
    authCredentials: JSON.stringify(authCredentials),
    displayName: displayName || tsString,
    secretKey,
    updatedAt: ts,
    createdAt: ts,
  });
  const token = await CredentialToken.encrypt({ sub: userId, credentialKey: key }, "1000y");
  if (!displayName && connector.authentication?.defaultDisplayName && connector.authentication.test) {
    const testResponse = await makeRequest({
      connectorId,
      credentialToken: token,
      request: connector.authentication.test,
      templateScope: "all",
    }).catch(() => ({ status: 500, data: {} }));
    if ((testResponse.status || 200) === 200) {
      displayName = replaceTokens(connector.authentication.defaultDisplayName, {
        data: testResponse.data,
        auth: authCredentials,
        timestamp: tsString,
      });
      await collection.updateOne({ key }, { $set: { displayName } });
    }
  }
  return { key, createdAt: ts, token, displayName: displayName || tsString };
}
export async function putAuthCredentials(
  {
    connectorId,
    authCredentials,
    displayName,
    environment,
    secretKey,
  }: {
    connectorId: string;
    authCredentials: RequestSchema | object;
    displayName?: string;
    environment: string;
    secretKey?: string;
  },
  { context: { user } }: { context: Context }
) {
  return await putAuthCredentialsInternal({
    connectorId,
    authCredentials,
    displayName,
    environment,
    secretKey,
    userId: getUserId(user),
  });
}
export async function updateAuthCredentials(
  {
    key,
    displayName,
  }: {
    key: string;
    displayName: string;
  },
  { context: { user } }: { context: Context }
) {
  const userId = getUserId(user);
  const collection = await getCollection("authCredentials");
  const result = await collection.updateOne({ key, userId }, { $set: { displayName, updatedAt: Date.now() } });
  if (!result.matchedCount) {
    throw new Error("Credential not found");
  }
  return result.matchedCount > 0;
}
export async function deleteAuthCredentials(
  {
    key,
  }: {
    key: string;
  },
  { context: { user } }: { context: Context }
) {
  const userId = getUserId(user);
  const collection = await getCollection("authCredentials");
  const result = await collection.deleteOne({ key, userId });
  return result.deletedCount > 0;
}
export async function deleteAllAuthCredentials(_, { context: { user } }: { context: Context }) {
  const userId = getUserId(user);
  const collection = await getCollection("authCredentials");
  const result = await collection.deleteMany({ userId });
  return result.deletedCount > 0;
}
export async function getAuthCredentialsDisplayInfo(
  {
    connectorId,
    environment,
    includeInvalid,
  }: {
    connectorId: string;
    environment: string;
    includeInvalid?: boolean;
  },
  { context: { user } }: { context: Context }
): Promise<AuthCredentialsDisplayInfo[]> {
  await verifyConnectorId(connectorId, environment);
  const userId = getUserId(user);
  const collection = await getCollection("authCredentials");
  const docs = await collection
    .find({ connectorId, userId, environment, ...(includeInvalid ? { invalid: { $ne: true } } : {}) })
    .toArray();
  const ret = docs.map(
    (doc) =>
      ({
        key: doc.key,
        name: doc.displayName?.toString() || "<unknown>",
        invalid: !!doc.invalid,
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
  secretKey,
}: {
  key: string;
  connectorId: string;
  credentials: unknown;
  authConfig: Oauth2Config;
  environment: string;
  secretKey: string;
}) {
  if (!authConfig?.refreshAccessToken) {
    throw new Error("We don't know how to refresh access tokens for this connector");
  }
  const secretsCollection = await getCollection("connectorSecrets");
  const secretsDoc = await secretsCollection.findOne({ connectorId, environment, key: secretKey });
  if (!secretsDoc) {
    throw new Error("Invalid connector secret key");
  }
  const secrets = JSON.parse(secretsDoc.secrets || "{}");
  const refreshRequest = replaceTokens(authConfig.refreshAccessToken, {
    auth: credentials,
    secrets,
  });
  const refreshResponse = await makeRequestInternal(refreshRequest);
  if ((refreshResponse.status || 200) >= 400) {
    const e: Error & { status?: number } = new Error(
      `Failed to refresh token: ${refreshResponse.status} ${JSON.stringify(refreshResponse.data)}`
    );
    e.status = refreshResponse.status;
    throw e;
  }
  credentials = { ...(credentials as object), ...(refreshResponse.data as object) };
  const credentialCollection = await getCollection("authCredentials");
  await credentialCollection.updateOne(
    {
      key,
    },
    { $set: { authCredentials: JSON.stringify(credentials), updatedAt: Date.now() } }
  );
  return credentials;
}
function normalizeHeaders<T extends RequestSchema | Partial<RequestSchema>>(request: T): T {
  request.headers = Object.fromEntries(Object.entries(request.headers || []).map(([k, v]) => [k.toLowerCase(), v]));
  return request;
}
function isEquivalentConnector(id1: string, id2: string) {
  return [id1, id2].every((x) => ["web3", "flow"].includes(x));
}
export async function makeRequest(
  {
    connectorId,
    credentialToken,
    request,
    templateScope,
    rejectProduction,
  }: {
    connectorId: string;
    credentialToken: string;
    request: RequestSchema;
    templateScope?: "all" | "headers";
    rejectProduction?: boolean;
  },
  { context: { user } }: { context: Context } = { context: {} }
): Promise<MakeRequestResponse> {
  const payload = await CredentialToken.decrypt(credentialToken).catch(() => null);
  if (!payload) {
    return {
      status: 403,
      data: { error: "Invalid credential token" },
      headers: {
        "content-type": "application/json",
      },
    };
  }
  const collection = await getCollection("authCredentials");
  const doc = await collection.findOne({ key: String(payload.credentialKey) });
  if (!doc) {
    return {
      status: 403,
      data: { error: "Credential token is no longer usable" },
      headers: {
        "content-type": "application/json",
      },
    };
  }
  if (doc.connectorId !== connectorId && !isEquivalentConnector(connectorId, doc.connectorId)) {
    return {
      status: 403,
      data: { error: "Credential token is not for this connector" },
      headers: {
        "content-type": "application/json",
      },
    };
  }
  // User is optional, this is for debugging only
  if (user && doc.userId !== getUserId(user)) {
    return {
      status: 403,
      data: { error: "User token is supplied, but the credential token is not usable by this user" },
      headers: {
        "content-type": "application/json",
      },
    };
  }
  if (rejectProduction && doc.environment === "production") {
    return {
      status: 403,
      data: { error: "Production usage is not allowed because the driver doesn't meet deployment requirement" },
      headers: {
        "content-type": "application/json",
      },
    };
  }
  const environment = doc.environment;
  await verifyConnectorId(connectorId, environment);
  verifyRequestSchema(request);
  const connector = await getConnectorSchema(connectorId, environment);
  if (!connector) {
    throw new InvalidParamsError("Unknown connector ID");
  }
  if (connector.authentication?.allowedHosts) {
    const url = new URL(request.url);
    if (!connector.authentication.allowedHosts.includes(url.host)) {
      return {
        status: 403,
        data: {
          error: `Sending request to ${url.host} is not allowed. If this is a legitimate request, update CDS file to include this host.`,
        },
        headers: {
          "content-type": "application/json",
        },
      };
    }
  }
  const secretsCollection = await getCollection("connectorSecrets");
  const secretsDoc = await secretsCollection.findOne({ environment, key: doc.secretKey });
  if (!secretsDoc) {
    throw new Error("Invalid connector secret key");
  }
  const secrets = JSON.parse(secretsDoc.secrets || "{}");
  let credentials = JSON.parse(doc.authCredentials);
  const getRequest = () => {
    const context = {
      auth: credentials,
      secrets,
    };
    return _.merge(
      {},
      normalizeHeaders(replaceTokens(connector.authentication?.authenticatedRequestTemplate || {}, context)),
      normalizeHeaders(
        templateScope === "headers"
          ? { ...request, headers: replaceTokens(request.headers || {}, context) }
          : replaceTokens(request, context)
      )
    );
  };
  const authType = connector.authentication?.type;
  if (authType === "basic") {
    request.auth = [credentials.username, credentials.password];
  }
  try {
    if (authType === "basic" || authType === "digest") {
      return await makeRequestBasicDigest(getRequest(), credentials.username, credentials.password);
    }
    if (authType === "oauth2") {
      let accessTokenRefreshed = false;
      const authConfig = connector.authentication?.oauth2Config;
      if (authConfig?.refreshAccessToken && authConfig?.autoRefresh && credentials.expires_in) {
        const expiresAt = doc.updatedAt + credentials.expires_in * 1000;
        if (expiresAt < Date.now() + 10000) {
          try {
            credentials = await refreshOauth2AccessToken({
              key: String(payload.credentialKey),
              connectorId,
              credentials,
              authConfig,
              environment,
              secretKey: doc.secretKey,
            });
          } catch (e) {
            if (e.status && e.status >= 400 && e.status <= 499 && !doc.invalid) {
              await collection
                .updateOne({ key: String(payload.credentialKey) }, { $set: { invalid: true } })
                .catch(() => null);
            }
            throw e;
          }
          accessTokenRefreshed = true;
        }
      }
      try {
        return await makeRequestInternal(getRequest());
      } catch (e) {
        if (e.response?.status !== 401) {
          throw e;
        }
        if (accessTokenRefreshed || !authConfig?.refreshAccessToken || !authConfig?.autoRefresh) {
          throw e;
        }
        try {
          credentials = await refreshOauth2AccessToken({
            key: String(payload.credentialKey),
            connectorId,
            credentials,
            authConfig,
            environment,
            secretKey: doc.secretKey,
          });
        } catch (e) {
          if (e.status && e.status >= 400 && e.status <= 499 && !doc.invalid) {
            await collection
              .updateOne({ key: String(payload.credentialKey) }, { $set: { invalid: true } })
              .catch(() => null);
          }
          throw e;
        }
        accessTokenRefreshed = true;
        return await makeRequestInternal(getRequest());
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
  const secretsDoc = await getConnectorSecretDoc({ connectorId, environment });
  const secrets = JSON.parse(secretsDoc.secrets || "{}");
  url = replaceTokens(url, { secrets });
  if (connector.authentication.oauth2Config.scope) {
    const urlObj = new URL(url);
    urlObj.searchParams.set("scope", connector.authentication.oauth2Config.scope);
    url = urlObj.toString();
  }
  return url;
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
    displayName?: string;
  },
  { context: { user } }: { context: Context }
): Promise<AuthCredentialsDisplayInfo> {
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
  const secretDoc = await getConnectorSecretDoc({ connectorId, environment });
  const secrets = JSON.parse(secretDoc.secrets || "{}");
  const resp = await makeRequestInternal(replaceTokens(request, { ...params, secrets }));
  const internalCredentials = await putAuthCredentials(
    {
      connectorId,
      authCredentials: resp.data as object,
      displayName,
      environment,
      secretKey: secretDoc.key,
    },
    { context: { user } }
  );
  return {
    key: internalCredentials.key,
    name: internalCredentials.displayName,
    createdAt: new Date(internalCredentials.createdAt).toISOString(),
    token: internalCredentials.token,
  };
}
