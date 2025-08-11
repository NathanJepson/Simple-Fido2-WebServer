import { DB } from "https://deno.land/x/sqlite/mod.ts";

const db = new DB("test.db");
function generateUserId() {
  // 32 random bytes (safe within 1–64 bytes range)
  return crypto.getRandomValues(new Uint8Array(32));
}

db.execute(`
    CREATE TABLE IF NOT EXISTS people (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE,
      display_name TEXT,
      password_hash TEXT
    )
  `);

const garbo = "garbo";

function bufferSourceToBase64Url(buf: BufferSource): string {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  const bin = String.fromCharCode(...bytes);
  return btoa(bin)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

for (const name of ["PeterParker", "ClarkKent", "BruceWayne"]) {
    db.query("INSERT INTO people (id,username,password_hash) VALUES (?,?,?)", [bufferSourceToBase64Url(generateUserId()),name,garbo]);
}

for (const [name] of db.query("SELECT username FROM people")) {
    console.log(name);
}

db.close();