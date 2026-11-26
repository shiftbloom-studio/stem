// Passes: stem as a Privacy Pass issuer. The browser side and the app side are played by Cloudflare's
// reference library (@cloudflare/privacypass-ts), so these tests also check stem against RFC 9578.
import { describe, it, expect, beforeAll, afterEach, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { publicVerif, TOKEN_TYPES, TokenChallenge } from "@cloudflare/privacypass-ts";
import app from "../src/index";
import type { Env } from "../src/env";
import { b64u, unb64u, encodeTokenKey, parseSpki, isTokenKey, loadPrivateKey, blindSign, generateTokenKey } from "../src/passes/rsa";
import { cleanupPasses } from "../src/passes/issuer";

const ORIGIN = "https://stem.test";
const APP = "https://convert.test";
const pending: Promise<unknown>[] = [];
const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {}, props: {} };
const sent: { to: string; text: string }[] = [];

function makeEnv(extra: Partial<Env> = {}): Env {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  for (const f of readdirSync("migrations").filter((f) => f.endsWith(".sql")).sort()) db.exec(readFileSync(`migrations/${f}`, "utf8"));
  return {
    DB: db as unknown as D1Database,
    ASSETS: { fetch: async () => new Response("") } as unknown as Fetcher,
    EMAIL: { send: async (m: { to: string; text: string }) => { sent.push(m); return { messageId: "m" }; } } as unknown as SendEmail,
    EMAIL_FROM: "stem <login@stem.test>",
    STEM_URL: ORIGIN,
    BETTER_AUTH_SECRET: randomBytes(32).toString("base64url"),
    PASS_ORIGINS: `${APP}, https://other.test`,
    ...extra,
  };
}

class Browser {
  cookies = new Map<string, string>();
  constructor(private env: Env, public origin = ORIGIN) {}
  async fetch(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers);
    if (this.origin) headers.set("origin", this.origin);
    headers.set("cf-connecting-ip", "203.0.113.9");
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
}

async function signIn(env: Env, email: string) {
  const b = new Browser(env);
  const post = (path: string, body: unknown) => b.fetch(path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
  expect((await post("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" })).status).toBe(200);
  const code = /(\d{6})/.exec(sent.filter((m) => m.to === email).at(-1)!.text)![1];
  expect((await post("/api/auth/sign-in/email-otp", { email, otp: code })).status).toBe(200);
  return b;
}

/** What an app page does: take stem's key from the directory, blind n requests, send them with the stem cookie. */
async function fetchPasses(b: Browser, n: number, opts: { keyId?: string; keyIndex?: number } = {}) {
  const dir = await (await b.fetch("/.well-known/private-token-issuer-directory")).json() as { "token-keys": { "token-key": string; "stem-key-id": string }[] };
  const key = dir["token-keys"][opts.keyIndex ?? 0];
  const challenge = new publicVerif.Origin(publicVerif.BlindRSAMode.PSS, ["convert.test"]).createTokenChallenge("stem.test", new Uint8Array(0));
  const clients = await Promise.all(Array.from({ length: n }, async () => {
    const c = new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
    return { c, req: await c.createTokenRequest(challenge, unb64u(key["token-key"])) };
  }));
  const res = await b.fetch("/api/passes/issue", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token_key_id: opts.keyId ?? key["stem-key-id"], requests: clients.map((x) => b64u(x.req.serialize())) }),
  });
  const body = await res.json() as { responses?: string[]; remaining?: number; error?: string; per_day?: number };
  const tokens = await Promise.all((body.responses || []).map((r, i) => clients[i].c.finalize(clients[i].c.deserializeTokenResponse(unb64u(r)))));
  return { res, body, tokens, key, challenge };
}

async function verifies(tokenKey: string, token: { authenticator: Uint8Array; authInput: { serialize(): Uint8Array } }) {
  const pk = await crypto.subtle.importKey("spki", publicVerif.convertRSASSAPSSToEnc(unb64u(tokenKey)), { name: "RSA-PSS", hash: "SHA-384" }, true, ["verify"]);
  return new publicVerif.Origin(publicVerif.BlindRSAMode.PSS, ["convert.test"]).verify(token as never, pk);
}

afterEach(() => vi.useRealTimers());

describe("pass keys", () => {
  it("publishes keys exactly as the reference library encodes them", async () => {
    const pair = await publicVerif.Issuer.generateKey(publicVerif.BlindRSAMode.PSS, { modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
    const theirs = await publicVerif.getPublicKeyBytes(pair.publicKey);
    const { n, e } = parseSpki(theirs);
    expect(b64u(encodeTokenKey(n, e))).toBe(b64u(theirs));
    expect(isTokenKey(theirs)).toBe(true);
    const ours = await generateTokenKey();
    expect(isTokenKey(ours.tokenKey)).toBe(true);
  });

  it("signs like the reference issuer and refuses values outside the modulus", async () => {
    const pair = await publicVerif.Issuer.generateKey(publicVerif.BlindRSAMode.PSS, { modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) });
    const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
    const sk = await loadPrivateKey(pkcs8);
    const issuer = new publicVerif.Issuer(publicVerif.BlindRSAMode.PSS, "stem.test", pair.privateKey, pair.publicKey);
    const client = new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
    const challenge = new publicVerif.Origin(publicVerif.BlindRSAMode.PSS, ["convert.test"]).createTokenChallenge("stem.test", new Uint8Array(0));
    const req = await client.createTokenRequest(challenge, await publicVerif.getPublicKeyBytes(pair.publicKey));
    const mine = await blindSign(sk, req.blindedMsg);
    const theirs = (await issuer.issue(req)).blindSig;
    expect(b64u(mine)).toBe(b64u(theirs));
    await expect(blindSign(sk, new Uint8Array(256).fill(0xff))).rejects.toThrow(/message length/);
    await expect(blindSign(sk, new Uint8Array(255))).rejects.toThrow(/input size/);
  });
});

describe("passes", () => {
  let env: Env;
  beforeAll(() => { env = makeEnv(); });

  it("serves an issuer directory with one key per day, the same for everyone", async () => {
    const anon = new Browser(env, "");
    const r1 = await anon.fetch("/.well-known/private-token-issuer-directory");
    expect(r1.status).toBe(200);
    expect(r1.headers.get("content-type")).toBe("application/private-token-issuer-directory");
    expect(r1.headers.get("access-control-allow-origin")).toBe("*");
    const d1 = await r1.json() as Record<string, any>;
    expect(d1["issuer-request-uri"]).toBe(`${ORIGIN}/api/passes/issue`);
    expect(d1["token-keys"]).toHaveLength(1);
    const k = d1["token-keys"][0];
    expect(k["token-type"]).toBe(2);
    expect(isTokenKey(unb64u(k["token-key"]))).toBe(true);
    expect(k["stem-key-id"]).toBe(b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", unb64u(k["token-key"])))));
    const d2 = await (await anon.fetch("/.well-known/private-token-issuer-directory")).json() as Record<string, any>;
    expect(d2["token-keys"][0]["token-key"]).toBe(k["token-key"]);
  });

  it("gives a signed-in browser passes that an app can verify, and nothing to others", async () => {
    const b = await signIn(env, "pass@example.com");
    b.origin = APP;
    const { res, body, tokens, key } = await fetchPasses(b, 3);
    expect(res.status).toBe(200);
    expect(res.headers.get("access-control-allow-origin")).toBe(APP);
    expect(res.headers.get("access-control-allow-credentials")).toBe("true");
    expect(body.remaining).toBe(47);
    expect(tokens).toHaveLength(3);
    for (const t of tokens) expect(await verifies(key["token-key"], t)).toBe(true);
    // Tokens are unlinkable: different nonces, nothing account-shaped inside.
    expect(new Set(tokens.map((t) => b64u(t.authInput.nonce))).size).toBe(3);
    expect(tokens[0].serialize().length).toBe(2 + 32 + 32 + 32 + 256);

    const status = await (await b.fetch("/api/passes/status")).json();
    expect(status).toEqual({ signed_in: true, remaining: 47, per_day: 50 });

    // Not signed in.
    const anon = new Browser(env, APP);
    expect((await fetchPasses(anon, 1)).res.status).toBe(401);
    expect(await (await anon.fetch("/api/passes/status")).json()).toEqual({ signed_in: false, remaining: 0, per_day: 50 });
    // Signed in, but the page is on a site that isn't listed.
    b.origin = "https://evil.test";
    expect((await fetchPasses(b, 1)).res.status).toBe(403);
    expect((await b.fetch("/api/passes/status")).status).toBe(403);
    b.origin = "";
    expect((await fetchPasses(b, 1)).res.status).toBe(403);
  });

  it("answers CORS preflights only for listed origins", async () => {
    const ok = await new Browser(env, APP).fetch("/api/passes/issue", { method: "OPTIONS", headers: { "access-control-request-method": "POST" } });
    expect(ok.status).toBe(204);
    expect(ok.headers.get("access-control-allow-origin")).toBe(APP);
    expect(ok.headers.get("access-control-allow-headers")).toBe("content-type");
    const no = await new Browser(env, "https://evil.test").fetch("/api/passes/issue", { method: "OPTIONS" });
    expect(no.status).toBe(403);
    expect(no.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("hands out 50 a day and refuses the 51st", async () => {
    const b = await signIn(env, "fifty@example.com");
    b.origin = APP;
    const first = await fetchPasses(b, 30);
    expect(first.tokens).toHaveLength(30);
    // Asking for more than is left gets what's left.
    const second = await fetchPasses(b, 30);
    expect(second.res.status).toBe(200);
    expect(second.tokens).toHaveLength(20);
    expect(second.body.remaining).toBe(0);
    const third = await fetchPasses(b, 1);
    expect(third.res.status).toBe(429);
    expect(third.body.error).toBe("quota_used");
    for (const t of [...first.tokens, ...second.tokens]) expect(await verifies(first.key["token-key"], t)).toBe(true);
  });

  it("doesn't let parallel requests overdraw the allowance", async () => {
    const e = makeEnv({ PASSES_PER_DAY: "5" });
    const b = await signIn(e, "race@example.com");
    b.origin = APP;
    const results = await Promise.all(Array.from({ length: 8 }, () => fetchPasses(b, 1)));
    expect(results.filter((r) => r.res.status === 200)).toHaveLength(5);
    expect(results.filter((r) => r.res.status === 429)).toHaveLength(3);
  });

  it("accepts the plain RFC 9578 request too", async () => {
    const b = await signIn(env, "rfc@example.com");
    b.origin = APP;
    const dir = await (await b.fetch("/.well-known/private-token-issuer-directory")).json() as Record<string, any>;
    const tokenKey = unb64u(dir["token-keys"][0]["token-key"]);
    const challenge = TokenChallenge.deserialize(new publicVerif.Origin(publicVerif.BlindRSAMode.PSS, ["convert.test"]).createTokenChallenge("stem.test", new Uint8Array(0)).serialize());
    const client = new publicVerif.Client(publicVerif.BlindRSAMode.PSS);
    const req = await client.createTokenRequest(challenge, tokenKey);
    const res = await b.fetch("/api/passes/issue", { method: "POST", headers: { "content-type": "application/private-token-request" }, body: req.serialize() });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/private-token-response");
    const token = await client.finalize(client.deserializeTokenResponse(new Uint8Array(await res.arrayBuffer())));
    expect([...token.serialize().subarray(0, 2)]).toEqual([0, TOKEN_TYPES.BLIND_RSA.value]);
    expect(await verifies(dir["token-keys"][0]["token-key"], token)).toBe(true);
  });

  it("refuses malformed requests and keys it doesn't use", async () => {
    const b = await signIn(env, "bad@example.com");
    b.origin = APP;
    expect((await fetchPasses(b, 1, { keyId: b64u(new Uint8Array(32)) })).body.error).toBe("unknown_key");
    const post = (body: unknown) => b.fetch("/api/passes/issue", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const dir = await (await b.fetch("/.well-known/private-token-issuer-directory")).json() as Record<string, any>;
    const id = dir["token-keys"][0]["stem-key-id"];
    expect((await post({ token_key_id: id, requests: [] })).status).toBe(400);
    expect((await post({ token_key_id: id, requests: Array(51).fill("AA") })).status).toBe(400);
    expect((await post({ token_key_id: id, requests: ["AAAA"] })).status).toBe(400);
    expect((await post({ token_key_id: id, requests: ["not base64!"] })).status).toBe(400);
    // Right size, wrong truncated key id.
    const wrong = new Uint8Array(259);
    wrong[1] = 2;
    wrong[2] = unb64u(id)[31] ^ 1;
    expect((await post({ token_key_id: id, requests: [b64u(wrong)] })).status).toBe(400);
    // Nothing was taken from the allowance by any of that.
    expect((await (await b.fetch("/api/passes/status")).json() as { remaining: number }).remaining).toBe(50);
  });

  it("rotates daily, accepts yesterday's key for a day and cleans up after", async () => {
    const e = makeEnv();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-26T23:59:00Z"));
    const b = await signIn(e, "night@example.com");
    b.origin = APP;
    const before = await fetchPasses(b, 2);
    expect(before.tokens).toHaveLength(2);

    vi.setSystemTime(new Date("2026-11-27T00:01:00Z"));
    const dir = await (await b.fetch("/.well-known/private-token-issuer-directory")).json() as Record<string, any>;
    expect(dir["token-keys"]).toHaveLength(2);
    expect(dir["token-keys"][1]["token-key"]).toBe(before.key["token-key"]);
    expect(dir["token-keys"][0]["token-key"]).not.toBe(before.key["token-key"]);
    // A page that still holds yesterday's key gets passes for it; the new day has a fresh allowance.
    const late = await fetchPasses(b, 1, { keyIndex: 1 });
    expect(late.key["token-key"]).toBe(before.key["token-key"]);
    expect(late.res.status).toBe(200);
    expect(late.body.remaining).toBe(49);

    vi.setSystemTime(new Date("2026-11-29T03:23:00Z"));
    expect(await cleanupPasses(e)).toEqual({ passKeys: 2, passQuota: 2 });
    const after = await (await b.fetch("/.well-known/private-token-issuer-directory")).json() as Record<string, any>;
    expect(after["token-keys"]).toHaveLength(1);
    expect((await fetchPasses(b, 1, { keyId: before.key["stem-key-id"] })).body.error).toBe("unknown_key");
  });

  it("starts a new key when BETTER_AUTH_SECRET changes and keeps the old one listed", async () => {
    const e = makeEnv();
    const b = await signIn(e, "rotate@example.com");
    b.origin = APP;
    const before = await fetchPasses(b, 1);
    expect(before.tokens).toHaveLength(1);
    e.BETTER_AUTH_SECRET = randomBytes(32).toString("base64url");
    // Sessions don't survive a new secret either.
    const b2 = await signIn(e, "rotate2@example.com");
    b2.origin = APP;
    const dir = await (await b2.fetch("/.well-known/private-token-issuer-directory")).json() as Record<string, any>;
    expect(dir["token-keys"]).toHaveLength(2);
    expect(dir["token-keys"][1]["token-key"]).toBe(before.key["token-key"]);
    // The old key can't be opened anymore, so it doesn't sign; the new one does.
    expect((await fetchPasses(b2, 1, { keyIndex: 1 })).body.error).toBe("unknown_key");
    const after = await fetchPasses(b2, 1);
    expect(after.res.status).toBe(200);
    expect(await verifies(after.key["token-key"], after.tokens[0])).toBe(true);
  });

  it("keeps private keys encrypted at rest", async () => {
    const rows = (env.DB as unknown as DatabaseSync).prepare(`select "privateKey" from "passIssuerKey"`).all() as { privateKey: string }[];
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect(r.privateKey).toMatch(/^v1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  });

  it("sends people back only to listed app pages after signing in", async () => {
    const b = new Browser(env, "");
    const back = async (to: string) => (await b.fetch(`/passes/back?to=${encodeURIComponent(to)}`)).headers.get("location");
    expect(await back(`${APP}/heic-to-jpg?passes=1`)).toBe(`${APP}/heic-to-jpg?passes=1`);
    expect(await back("https://evil.test/")).toBe("/account");
    expect(await back(`${ORIGIN}/account`)).toBe("/account");
    expect(await back("javascript:alert(1)")).toBe("/account");
  });
});
