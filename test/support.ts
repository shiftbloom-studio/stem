// Shared test helpers: an in-memory stem, a cookie-keeping browser, the operator API, sign-in and the code flow.
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { decodeJwt } from "jose";
import { expect } from "vitest";
import app from "../src/index";
import type { Env } from "../src/env";

export const ORIGIN = "https://stem.test";
export const OPERATOR = "op_" + "x".repeat(40);
export const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";

export const sent: { to: string; text: string }[] = [];
export const pending: Promise<unknown>[] = [];
export const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {}, props: {} };

export function makeEnv(extra: Partial<Env> = {}): Env {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  for (const f of readdirSync("migrations").filter((f) => f.endsWith(".sql")).sort((a, b) => a.localeCompare(b))) db.exec(readFileSync(`migrations/${f}`, "utf8"));
  return {
    DB: db as unknown as D1Database,
    ASSETS: { fetch: async () => new Response("") } as unknown as Fetcher,
    EMAIL: { send: async (m: { to: string; text: string }) => { sent.push(m); return { messageId: "m" }; } } as unknown as SendEmail,
    EMAIL_FROM: "stem <login@stem.test>",
    STEM_URL: ORIGIN,
    BETTER_AUTH_SECRET: randomBytes(32).toString("base64url"),
    OPERATOR_TOKEN: OPERATOR,
    RESOURCES: "https://shared.test/api",
    ...extra,
  };
}

export class Browser {
  cookies = new Map<string, string>();
  constructor(private env: Env, public ip = "203.0.113.7") {}
  async fetch(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers);
    headers.set("origin", ORIGIN);
    headers.set("cf-connecting-ip", this.ip);
    headers.set("user-agent", UA);
    if (this.cookies.size) headers.set("cookie", [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "));
    const res = await app.fetch(new Request(new URL(path, ORIGIN), { ...init, headers, redirect: "manual" }), this.env, ctx as never);
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const i = pair.indexOf("=");
      const v = pair.slice(i + 1);
      if (v) this.cookies.set(pair.slice(0, i), v); else this.cookies.delete(pair.slice(0, i));
    }
    await Promise.all(pending.splice(0));
    return res;
  }
  json(path: string, body: unknown, headers: Record<string, string> = {}) {
    return this.fetch(path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json", ...headers } });
  }
}

export const op = (b: Browser, path: string, body?: unknown) =>
  b.fetch(`/api/v1/operator${path}`, { method: body ? "POST" : "GET", body: body ? JSON.stringify(body) : undefined, headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" } });

export async function signIn(b: Browser, email: string) {
  expect((await b.json("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" })).status).toBe(200);
  const code = /(\d{6})/.exec(sent.filter((m) => m.to === email).at(-1)!.text)![1];
  const r = await b.json("/api/auth/sign-in/email-otp", { email, otp: code });
  expect(r.status).toBe(200);
  return ((await r.json()) as { user: { id: string } }).user;
}

export type Client = { client_id: string; client_secret: string; subject_type?: string; scope?: string };

/** Code flow without a resource: opaque access token, ID token, then userinfo. */
export async function login(b: Browser, client: Client, callback: string, scope: string, resource?: string) {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: callback, scope, state: "s", nonce: "n", code_challenge: challenge, code_challenge_method: "S256" });
  if (resource) q.set("resource", resource);
  const r = await b.fetch(`/api/auth/oauth2/authorize?${q}`);
  if (!r.headers.get("location")) throw new Error(`authorize: ${r.status} ${await r.text()}`);
  const loc = new URL(r.headers.get("location")!);
  const code = loc.searchParams.get("code");
  if (!code) throw new Error(`authorize: ${loc.searchParams.get("error")}`);
  const basic = "Basic " + btoa(`${client.client_id}:${client.client_secret}`);
  const tr = await b.fetch("/api/auth/oauth2/token", {
    method: "POST",
    headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: callback, code_verifier: verifier }),
  });
  const tokens = (await tr.json()) as { access_token: string; id_token: string };
  expect(tr.status, JSON.stringify(tokens)).toBe(200);
  const ui = await b.fetch("/api/auth/oauth2/userinfo", { headers: { authorization: `Bearer ${tokens.access_token}` } });
  expect(ui.status).toBe(200);
  return { idToken: decodeJwt(tokens.id_token), userinfo: (await ui.json()) as Record<string, unknown>, accessToken: tokens.access_token };
}
