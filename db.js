const { MongoClient } = require('mongodb');

let client = null;
let defaultDb = null;

const fs = require('fs');
const path = require('path');

async function getClient() {
  if (client) return client;

  // prefer environment variables
  let url = process.env.MONGODB_URI || process.env.DATABASE_URL || process.env.MONGO_URL;

  // if still missing, try fallback file `.txt` in project root (some users stash
  // connection info there). Last non-empty line is assumed to be the URI.
  if (!url) {
    try {
      const txtPath = path.join(__dirname, '.txt');
      if (fs.existsSync(txtPath)) {
        const raw = fs.readFileSync(txtPath, 'utf8');
        const lines = raw
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter(Boolean);
        if (lines.length > 0) {
          url = lines[lines.length - 1];
        }
      }
    } catch (e) {
      // ignore
    }
  }

  if (!url) {
    throw new Error('MONGODB_URI (or DATABASE_URL/MONGO_URL) environment variable must be set');
  }

  client = new MongoClient(url, { useNewUrlParser: true, useUnifiedTopology: true });
  await client.connect();
  return client;
}

async function getDb() {
  if (defaultDb) return defaultDb;
  const c = await getClient();
  // if the connection string contains a database name, MongoClient.db() will use it;
  // otherwise default to 'test'.
  defaultDb = c.db();
  return defaultDb;
}

async function getCollection(name) {
  const db = await getDb();
  return db.collection(name);
}

module.exports = { getClient, getDb, getCollection };