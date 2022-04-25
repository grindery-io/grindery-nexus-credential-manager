import { ConnectorSchema } from "./types";

export const DEMO_CONNECTORS: { [key: string]: ConnectorSchema } = {
  _demoBasic: {
    name: "demoBasic",
    version: "1.0.0",
    platformVersion: "1.0.0",
    authentication: {
      type: "basic",
      test: {
        url: "https://www.example.com/",
      },
    },
  },
  _demoDigest: {
    name: "demoDigest",
    version: "1.0.0",
    platformVersion: "1.0.0",
    authentication: {
      type: "digest",
      test: {
        url: "https://www.example.com/",
      },
    },
  },
};