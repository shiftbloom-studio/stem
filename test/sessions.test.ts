// The account page lists sessions through /stem/sessions, which, unlike Better Auth's /list-sessions,
// doesn't need a session signed in within the last 15 minutes.
import { it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import app from "../src/index";
import type { Env } from "../src/env";

const ORIGIN = "https://stem.test";

it("lists a person's own sessions however old they are, and only theirs", async () => {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  for (const f of readdirSync("migrations").filter((f) => f.endsWith(".sql")).sort()) db.exec(readFileSync(`migrations/${f}`, "utf8"));
  const sent: { to: string; text: string }[] = [];
  const env = {
    DB: db as unknown as D1Database,
    ASSETS: { fetch: async () => new Response("") } as unknown as Fetcher,
    EMAIL: { send: async (m: { to: string; text: string }) => { sent.push(m); return { messageId: "m" }; } } as unknown as SendEmail,
    EMAIL_FROM: "stem <login@stem.test>",
    STEM_URL: ORIGIN,
    BETTER_AUTH_SECRET: randomBytes(32).toString("base64url"),
  } as Env;
  const pending: Promise<unknown>[] = [];
  const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {}, props: {} };
  const browser = (ip: string) => {
    let cookie = "";
    return async (path: string, body?: unknown) => {
      const res = await app.fetch(new Request(ORIGIN + path, { method: body ? "POST" : "GET", body: body ? JSON.stringify(body) : undefined, headers: { origin: ORIGIN, "content-type": "application/json", "cf-connecting-ip": ip, ...(cookie ? { cookie } : {}) } }), env, ctx as never);
      for (const c of res.headers.getSetCookie()) { const [pair] = c.split(";"); if (pair.includes("session_token")) cookie = pair; }
      await Promise.all(pending.splice(0));
      return res;
    };
  };
  const signIn = async (f: ReturnType<typeof browser>, email: string) => {
    await f("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" });
    const code = /(\d{6})/.exec(sent.filter((m) => m.to === email).at(-1)!.text)![1];
    expect((await f("/api/auth/sign-in/email-otp", { email, otp: code })).status).toBe(200);
  };

  const laptop = browser("203.0.113.50"), other = browser("203.0.113.52");
  await signIn(laptop, "me@example.com");
  // A second device (a second code for the same address would hit the per-address limit).
  db.prepare(`insert into "session" ("id", "expiresAt", "token", "createdAt", "updatedAt", "ipAddress", "userAgent", "userId") select ?, ?, ?, ?, ?, '203.0.113.51', 'phone', "id" from "user" where "email" = 'me@example.com'`)
    .run(crypto.randomUUID(), new Date(Date.now() + 86_400_000).toISOString(), "phone-token-" + "x".repeat(20), new Date().toISOString(), new Date().toISOString());
  await signIn(other, "someone@example.com");
  // An hour later: older than freshAge.
  db.exec(`update "session" set "createdAt" = '${new Date(Date.now() - 3_600_000).toISOString()}'`);

  expect((await laptop("/api/auth/list-sessions")).status).toBe(403);
  const r = await laptop("/api/auth/stem/sessions");
  expect(r.status).toBe(200);
  const list = (await r.json()) as { token: string; ipAddress: string }[];
  expect(list.map((s) => s.ipAddress).sort()).toEqual(["203.0.113.50", "203.0.113.51"]);
  expect(Object.keys(list[0]).sort()).toEqual(["createdAt", "expiresAt", "id", "ipAddress", "token", "updatedAt", "userAgent"]);

  // Ending the phone's session works from the laptop without a fresh sign-in.
  const phoneToken = list.find((s) => s.ipAddress === "203.0.113.51")!.token;
  expect((await laptop("/api/auth/revoke-session", { token: phoneToken })).status).toBe(200);
  expect(((await (await laptop("/api/auth/stem/sessions")).json()) as unknown[]).length).toBe(1);

  expect((await browser("203.0.113.53")("/api/auth/stem/sessions")).status).toBe(401);
});
