export type RequestSchema = {
  method?: "GET" | "PUT" | "POST" | "PATCH" | "DELETE" | "HEAD";
  url: string;
  body?: null | string | object | unknown[];
  params?: { [key: string]: string };
  headers?: { [key: string]: string };
  auth?: string[] | object;
};
export type AuthCredentialsDisplayInfo = {
  id: string;
  name: string;
  createdAt: string;
};
export type MakeRequestResponse = {
  data: unknown;
  headers: { [key: string]: string };
};
export type AuthenticationSchema = {
  test: RequestSchema;
  // fields: FieldsSchema[];
  label?: string | RequestSchema;
} & (
  | {
      type: "basic" | "custom" | "digest";
    }
  | {
      type: "oauth1";
      oauth1Config: {
        getRequestToken: RequestSchema;
        authorizeUrl: string;
        getAccessToken: RequestSchema;
      };
    }
  | {
      type: "oauth2";
      oauth1Config: {
        authorizeUrl: string;
        getAccessToken: RequestSchema;
        refreshAccessToken?: RequestSchema;
        codeParam?: string;
        scope?: string;
        autoRefresh?: string;
      };
    }
  | {
      type: "session";
      oauth1Config: {
        operation: RequestSchema;
      };
    }
);
export type ConnectorSchema = {
  name: string;
  version: string;
  platformVersion: string;
  // triggers: TriggerSchema[];
  // actions: ActionSchema[];
  authentication?: AuthenticationSchema;
};