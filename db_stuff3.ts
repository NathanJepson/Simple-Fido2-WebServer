import { DB } from "https://deno.land/x/sqlite/mod.ts";

const db = new DB("test.db");

db.execute(`
    CREATE TABLE IF NOT EXISTS sessionChallenges (
      username TEXT PRIMARY KEY,
      sessionChallenge TEXT,
      FOREIGN KEY(username) REFERENCES people(username) ON DELETE CASCADE
    )
`);

db.close();