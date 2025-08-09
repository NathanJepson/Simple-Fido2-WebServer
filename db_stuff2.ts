import { DB } from "https://deno.land/x/sqlite/mod.ts";

const db = new DB("test.db");

db.execute(`
    CREATE TABLE IF NOT EXISTS cookies (
      cookie TEXT PRIMARY KEY,
      id INTEGER NOT NULL,
      FOREIGN KEY(id) REFERENCES people(id) ON DELETE CASCADE
    )
`);

db.close();