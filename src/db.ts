import { Collection, CreateIndexesOptions, Db, IndexSpecification, MongoClient } from "mongodb";

let cachedClient: MongoClient | Promise<MongoClient> | null = null;

export type DbSchema = {
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
    credentialId?: string;
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

const INDEXES: { [name in keyof DbSchema]: [IndexSpecification, CreateIndexesOptions][] } = {
  connectorSecrets: [
    [{ key: 1 }, { unique: true }],
    [{ connectorId: 1 }, {}],
    [{ connectorId: 1, environment: 1 }, {}],
  ],
  authCredentials: [
    [{ key: 1 }, { unique: true }],
    [{ connectorId: 1 }, {}],
    [{ connectorId: 1, environment: 1 }, {}],
  ],
};

async function createIndexes(db: Db) {
  for (const collectionName of Object.keys(INDEXES)) {
    const collection = db.collection(collectionName);
    for (const [spec, options] of INDEXES[collectionName]) {
      await collection.createIndex(spec, options);
    }
  }
}

async function getDb() {
  if (cachedClient) {
    return (await cachedClient).db();
  }
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error("MONGODB_URI is not set");
    process.exit(1);
  }
  cachedClient = MongoClient.connect(uri);
  cachedClient = await cachedClient;
  await createIndexes(cachedClient.db());
  return cachedClient.db();
}
getDb().catch((e) => {
  console.error("Failed to connect to database:", e);
  process.exit(1);
});
export async function getCollection<T extends keyof DbSchema>(collectionName: T): Promise<Collection<DbSchema[T]>> {
  const db = await getDb();
  return db.collection(collectionName);
}
