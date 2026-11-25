// SPDX-License-Identifier: AGPL-3.0-or-later
// Prints the SQL that creates stem's tables, generated from the Better Auth config.
// Run with `npm run db:schema > migrations/000N_name.sql` after changing plugins or fields,
// against a database that already has the earlier migrations (see test/schema.test.ts).
import { DatabaseSync } from "node:sqlite";
import { readdirSync, readFileSync } from "node:fs";
import { getMigrations } from "better-auth/db/migration";
import { createAuth } from "../src/auth";

const db = new DatabaseSync(":memory:");
for (const f of readdirSync("migrations").filter((f) => f.endsWith(".sql")).sort()) db.exec(readFileSync(`migrations/${f}`, "utf8"));
const env = { STEM_URL: "https://stem.example.com", BETTER_AUTH_SECRET: "x".repeat(32), DB: db } as never;
const auth = createAuth(env);
const { compileMigrations } = await getMigrations({ ...auth.options, database: db } as never);
const sql = await compileMigrations();
process.stdout.write(sql.replace(/[;\s]/g, "") ? sql.replace(/;\s*/g, ";\n") : "-- schema is up to date\n");
