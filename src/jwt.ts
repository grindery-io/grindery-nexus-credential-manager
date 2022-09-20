import {URL} from "node:url";
import * as jose from "jose";
import { getJwtTools } from "grindery-nexus-common-utils";

export const ISSUER = "urn:grindery:credential-manager";

export const AUD_CREDENTIAL_TOKEN = "urn:grindery:credential-token:v1";

const jwtTools = getJwtTools(ISSUER);
jwtTools.getPublicJwk().catch((e) => {
  console.error("Failed to initialize keys:", e);
  process.exit(1);
});

const { encryptJWT, decryptJWT, signJWT, verifyJWT, getPublicJwk } = jwtTools;
export { encryptJWT, decryptJWT, signJWT, verifyJWT, getPublicJwk };

const ORCHESTRATOR_KEY = jose.createRemoteJWKSet(new URL("https://orchestrator.grindery.org/oauth/jwks"));
export async function parseUserAccessToken(token: string) {
  const { payload } = await jose.jwtVerify(token, ORCHESTRATOR_KEY, {
    issuer: "urn:grindery:orchestrator",
    audience: "urn:grindery:access-token:v1",
  });
  return payload;
}