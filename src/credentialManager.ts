import { InvalidParamsError } from "./jsonrpc";
import { RequestSchema, AuthCredentialsDisplayInfo, MakeRequestResponse } from "./types";
import { getCollection } from "./db";
import axios from "axios";
import { DEMO_CONNECTORS } from "./demoConnectors";

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
function verifyRequestSchema(request: RequestSchema) {
  if (typeof request !== "object") {
    throw new InvalidParamsError("Invalid request schema");
  }
  if (request.method !== undefined && typeof request.method !== "string") {
    throw new InvalidParamsError("Invalid request method");
  }
  if (!request.url || typeof request.url !== "string") {
    throw new InvalidParamsError("Invalid request URL");
  }
  if (request.body !== undefined && typeof request.body !== "string" && typeof request.body !== "object") {
    throw new InvalidParamsError("Invalid request body");
  }
  if (request.params !== undefined && typeof request.params !== "object") {
    throw new InvalidParamsError("Invalid request params");
  }
  if (request.headers !== undefined && typeof request.headers !== "object") {
    throw new InvalidParamsError("Invalid request headers");
  }
  if (request.auth !== undefined && typeof request.auth !== "object") {
    throw new InvalidParamsError("Invalid request auth");
  }

  const method = request.method?.toString().toUpperCase() ?? "GET";
  if (["GET", "HEAD"].includes(method) && request.body) {
    throw new InvalidParamsError("Invalid body for GET/HEAD request");
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
async function makeRequestInternal(request: RequestSchema): Promise<MakeRequestResponse> {
  const resp = await axios({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    method: request.method || "GET",
    url: request.url,
    ...(request.body && { data: typeof request.body === "string" ? request.body : JSON.stringify(request.body) }),
    headers: {
      ...(request.body && typeof request.body !== "string" && { "Content-Type": "application/json" }),
      ...(request.headers && { ...request.headers }),
    },
    ...(Array.isArray(request.auth) && {
      auth: {
        username: request.auth[0],
        password: request.auth[1],
      },
    }),
    params: request.params,
    responseType: "text",
  });
  let data = resp.data;
  if (resp.headers["content-type"]?.includes("application/json")) {
    try {
      data = JSON.parse(data);
    } catch (e) {
      // ignore
    }
  }
  return {
    data,
    headers: resp.headers,
  };
}
export async function makeRequest(
  connectorId: string,
  userDid: string,
  request: RequestSchema
): Promise<MakeRequestResponse> {
  verifyConnectorId(connectorId);
  verifyDid(userDid);
  verifyRequestSchema(request);
  const collection = await getCollection("authCredentials");
  const doc = await collection.findOne({ connectorId, userDid });
  if (!doc) {
    throw new InvalidParamsError("No credentials found");
  }
  throw new Error("Not implemented");
}
