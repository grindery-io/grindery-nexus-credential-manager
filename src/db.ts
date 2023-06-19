import { Collection, MongoClient } from "mongodb";

let cachedClient: MongoClient | Promise<MongoClient> | null = null;

type DbSchema = {
  connectorSecrets: {
    key: string;
    connectorId: string;
    secrets: string; // JSON string
    environment: string;
    updatedAt: number; // milliseconds since epoch
    createdAt: number; // milliseconds since epoch
  };
  authCredentials: {
    key: string;
    connectorId: string;
    environment: string;
    userId: string;
    authCredentials: string; // JSON string
    secretKey: string;
    displayName: string;
    invalid?: boolean; // Failed to refresh
    updatedAt: number; // milliseconds since epoch
    createdAt: number; // milliseconds since epoch
  };
};

async function getDb() {
  if (cachedClient) {
    return (await cachedClient).db();
  }
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  cachedClient = MongoClient.connect(process.env.MONGODB_URI!);
  cachedClient = await cachedClient;
  return cachedClient.db();
}
export async function getCollection<T extends keyof DbSchema>(collectionName: T): Promise<Collection<DbSchema[T]>> {
  const db = await getDb();
  return db.collection(collectionName);
}
