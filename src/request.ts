import { createHash } from "crypto";
import { RequestSchema, MakeRequestResponse } from "grindery-nexus-common-utils/dist/types";
import axios, { AxiosResponse } from "axios";
import { InvalidParamsError } from "grindery-nexus-common-utils/dist/jsonrpc";

export function verifyRequestSchema(request: RequestSchema) {
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
function logRequest(request: RequestSchema) {
  if (process.env.LOG_REQUEST) {
    console.debug(`${request.method || "GET"} ${request.url}`, { request });
  }
}
function logResponse(response: AxiosResponse) {
  if (process.env.LOG_REQUEST) {
    console.debug(`--> ${response.status} ${response.statusText} ${response.headers["content-length"] || "<no length>"}`, { data: response.data, request: response.config });
  }
}
export async function makeRequestInternal(request: RequestSchema): Promise<MakeRequestResponse> {
  logRequest(request);
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
  }).catch((e) => {
    if (e.response) {
      logResponse(e.response);
    }
    return Promise.reject(e);
  });
  logResponse(resp);
  let data = resp.data;
  if (resp.headers["content-type"]?.includes("application/json")) {
    try {
      data = JSON.parse(data);
    } catch (e) {
      // ignore
    }
  }
  return {
    status: resp.status,
    data,
    headers: resp.headers,
  };
}

function getDigestAuthHeader(authHeader: string, method: string, url: string, username: string, passwd: string) {
  const paramsString: string[] = authHeader.split(/\s*,?\s*Digest\s+/).filter((v) => v !== "");
  const paramsArray: string[][] = paramsString.map((v) => v.split(/\s*,(?=(?:[^"]*"[^"]*")*)\s*/));
  const paramsKvArray: [string, string][][] = paramsArray.map((v) =>
    v.map((value) => {
      const ret = value
        .split(/\s*=(?:(?=[^"]*"[^"]*")|(?!"))\s*/, 2)
        .map((v2) => v2.replace(/^"/, "").replace(/"$/, ""));
      return [ret[0], ret[1]];
    })
  );
  const paramsMapArray: { [s: string]: string }[] = paramsKvArray.map((v) => {
    const t: { [s: string]: string } = {};
    v.forEach((w) => {
      // eslint-disable-next-line prefer-destructuring
      t[w[0]] = w[1];
    });
    return t;
  });
  // const calams = ["realm", "nonce", "qop", "opaque"];
  const paramsCalamsOk = paramsMapArray
    .map((v) => {
      if (!("algorithm" in v)) {
        // eslint-disable-next-line no-param-reassign
        v.algorithm = "MD5";
      }
      return v;
    })
    .filter((v) => ["MD5", "SHA-256", "SHA-512-256", "SHA-512"].findIndex((i) => i === v.algorithm) >= 0)
    // .filter((v) => calams.filter((value) => !(value in v)).length === 0)
    .filter((v) => !v.qop || v.qop.split(/\s*,\s*/).filter((v2) => v2 === "auth").length !== 0);

  if (paramsCalamsOk.length === 0) {
    throw new Error("Auth params error.");
  }
  paramsCalamsOk.sort((a, b) => {
    const [aEval, bEval] = [a.algorithm, b.algorithm].map((v) => {
      if (v === "MD5") {
        return 0;
      }
      if (v === "SHA-256") {
        return 1;
      }
      if (v === "SHA-512-256") {
        return 2;
      }
      return 3;
    });
    return bEval - aEval;
  });
  const params: { [s: string]: string } = paramsCalamsOk[0];
  const qop = params["qop"] ? "auth" : undefined;
  const { realm, nonce, opaque, algorithm } = params;
  const uri: string = url.split(/^https?:\/\/[^/]+/i).filter((v) => v !== "")[0];
  const cnonce = qop ? Math.random().toString(36).substring(2, 10) : undefined;
  const nc = qop ? "00000001" : undefined;

  const hashHex = ((): ((str: string) => string) => {
    const algo = (algorithm || "MD5").replace("SHA-", "SHA");
    return (str: string) => {
      const hash = createHash(algo);
      hash.update(str);
      return hash.digest("hex");
    };
  })();

  const hashHexArray = (data: string[]) => hashHex(data.join(":"));
  const a1 = [username, realm, passwd];
  const a1hash = hashHexArray(a1);
  const a2 = [method.toUpperCase(), uri];
  const a2hash = hashHexArray(a2);
  const a3 = qop ? ([a1hash, nonce, nc, cnonce, qop, a2hash] as string[]) : [a1hash, nonce, a2hash];
  const response = hashHexArray(a3);
  const dh: { [s: string]: string | undefined } = {
    realm,
    nonce,
    uri,
    username,
    cnonce,
    nc,
    qop,
    algorithm,
    response,
    opaque,
  };

  const auth = `Digest ${Object.keys(dh)
    .filter((v) => dh[v] !== undefined)
    .map((v) => `${v}="${dh[v]}"`)
    .join(", ")}`;

  return auth;
}
export function updateHeaders(headers: { [s: string]: string }, update: { [s: string]: string | undefined }) {
  headers = Object.entries(headers).reduce((acc, [key, value]) => {
    acc[key.toLowerCase()] = value;
    return acc;
  }, {});
  Object.entries(update).forEach(([key, value]) => {
    key = key.toLowerCase();
    if (value === undefined) {
      delete headers[key];
    } else {
      headers[key] = value;
    }
  });
  return headers;
}

async function makeRequestBasicDigestInternal(
  request: RequestSchema,
  username: string,
  password: string,
  numStaleRetries = 5
): Promise<MakeRequestResponse> {
  try {
    return await makeRequestInternal(request);
  } catch (e) {
    if (e.response?.status !== 401) {
      throw e;
    }
    const wwwAuthHeader = e.response.headers["www-authenticate"];
    const authScheme = wwwAuthHeader?.split(" ")?.[0]?.toLowerCase();
    if (authScheme !== "basic" && authScheme !== "digest") {
      throw e;
    }
    if (authScheme === "basic") {
      if (request.auth?.[0] === username && request.auth?.[1] === password) {
        throw e;
      }
      request.auth = [username, password];
    } else {
      if (request.headers?.["authorization"].match("^Digest ")) {
        if (!/(^|,\s*)stale=true(,|$)/i.test(wwwAuthHeader) || numStaleRetries <= 0) {
          throw e;
        }
      }
      delete request.auth;
      request.headers = updateHeaders(request.headers || {}, {
        authorization: getDigestAuthHeader(wwwAuthHeader, request.method || "GET", request.url, username, password),
      });
    }
    return await makeRequestBasicDigestInternal(request, username, password, numStaleRetries - 1);
  }
}

export async function makeRequestBasicDigest(
  request: RequestSchema,
  username: string,
  password: string
): Promise<MakeRequestResponse> {
  request = { ...request };
  request.headers = updateHeaders(request.headers || {}, { authorization: undefined });
  return await makeRequestBasicDigestInternal(request, username, password);
}
