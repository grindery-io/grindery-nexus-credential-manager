import { parseUserAccessToken } from "./jwt";
import { server } from "./server";

(async () =>
  server.receive(
    { jsonrpc: "2.0", id: "1", method: process.argv[2], params: JSON.parse(process.argv[3]) },
    {
      context: {
        user: process.env.TOKEN
          ? await parseUserAccessToken(process.env.TOKEN)
          : { sub: "grindery:internal:local", workspace: "ADMIN", role: "admin" },
      },
    }
  ))().then(
  (res) => {
    console.log(res?.error || res?.result);
    process.exit(res?.error ? 1 : 0);
  },
  (e) => {
    console.error(e);
    process.exit(1);
  }
);
