// Mandates end to end: an agent asks, the person signs with a passkey, stem countersigns, the agent
// narrows offline for sub-agents, apps authorize calls, the stop button and the shared budget hold.
// The passkey is simulated in Node (P-256, same bytes a real authenticator sends).
import { describe, it, expect, beforeAll } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { createHash, randomBytes, generateKeyPairSync, sign as nodeSign, type KeyObject } from "node:crypto";
import { SignJWT, generateKeyPair, exportJWK, decodeJwt, type JWK, type JSONWebKeySet } from "jose";
import app, { MandateGateway } from "../src/index";
import type { Env } from "../src/env";
import { MandateState, type Sql, trailHash } from "../src/mandates/object";
import { verifyMandate, canonicalize, narrower, allows, parseAuthorization, rootChallenge, MandateError, type Right } from "../src/mandates/verify";
// @ts-expect-error plain JS module
import { newKey, requestJwt, derive, headers, proof } from "../tools/mandate-agent.mjs";

const ORIGIN = "https://stem.test";
const DROP = "https://drop.test";
const RP = "stem.test";
const sent: { to: string; text: string }[] = [];
const pending: Promise<unknown>[] = [];
const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {}, props: {} };
const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");

/** Durable Object stand-in: the real MandateState on node:sqlite, one database per name. */
function fakeNamespace(clock: () => number = Date.now) {
  const objects = new Map<string, MandateState>();
  const sql = (db: DatabaseSync): Sql => ({ exec: (q: string, ...args: unknown[]) => { const rows = db.prepare(q).all(...(args as never[])); return { toArray: () => rows as never } } });
  const get = (name: string) => {
    let o = objects.get(name);
    if (!o) objects.set(name, (o = new MandateState(sql(new DatabaseSync(":memory:")), clock)));
    const s = o;
    return { open: async (exp: number, b: object) => s.open(exp, b), status: async () => s.status(), use: async (i: never) => s.use(i), revoke: async () => s.revoke(), trail: async (n?: number) => s.trail(n) };
  };
  return { idFromName: (n: string) => n, get, objects } as never as DurableObjectNamespace & { objects: Map<string, MandateState> };
}

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
    MANDATE: fakeNamespace() as never,
    MANDATE_APPS: JSON.stringify({ [DROP]: { name: "drop", actions: { upload: "Upload files", list: "See the files it uploaded", delete: "Delete the files it uploaded" } } }),
    ...extra,
  };
}

class Browser {
  cookies = new Map<string, string>();
  constructor(private env: Env) {}
  async fetch(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers);
    headers.set("origin", ORIGIN);
    headers.set("cf-connecting-ip", "203.0.113.9");
    if (this.cookies.size) headers.set("cookie", [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "));
    const res = await app.fetch(new Request(new URL(path, ORIGIN), { ...init, headers, redirect: "manual" }), this.env, ctx as never);
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const i = pair.indexOf("=");
      if (pair.slice(i + 1)) this.cookies.set(pair.slice(0, i), pair.slice(i + 1)); else this.cookies.delete(pair.slice(0, i));
    }
    await Promise.all(pending.splice(0));
    return res;
  }
  json(path: string, body: unknown) {
    return this.fetch(path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
  }
}

/** An agent talks to stem without cookies or an Origin header. */
const agentPost = (env: Env, path: string, body: unknown) =>
  app.fetch(new Request(new URL(path, ORIGIN), { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json", "cf-connecting-ip": "198.51.100.4" } }), env, ctx as never);

async function signIn(b: Browser, email: string) {
  await b.json("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" });
  const code = /(\d{6})/.exec(sent.filter((m) => m.to === email).at(-1)!.text)![1];
  const r = await b.json("/api/auth/sign-in/email-otp", { email, otp: code });
  expect(r.status).toBe(200);
  return ((await r.json()) as { user: { id: string } }).user;
}

/** A platform authenticator in Node: a P-256 key, stored on the account like Better Auth stores it. */
class Passkey {
  id = b64u(randomBytes(16));
  counter = 0;
  key: KeyObject;
  cose: Buffer;
  constructor(public uv = true) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.key = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    this.cose = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), Buffer.from(jwk.x!, "base64url"), Buffer.from([0x22, 0x58, 0x20]), Buffer.from(jwk.y!, "base64url")]);
  }
  enrol(env: Env, userId: string) {
    (env.DB as unknown as DatabaseSync).prepare(`insert into passkey (id, name, publicKey, userId, credentialID, counter, deviceType, backedUp, transports, createdAt) values (?, ?, ?, ?, ?, 0, 'singleDevice', 0, 'internal', ?)`)
      .run(crypto.randomUUID(), "Test key", this.cose.toString("base64"), userId, this.id, new Date().toISOString());
  }
  assert(challenge: string, origin = ORIGIN, rpId = RP) {
    this.counter++;
    const authData = Buffer.concat([createHash("sha256").update(rpId).digest(), Buffer.from([this.uv ? 0x05 : 0x01]), Buffer.from([0, 0, 0, this.counter])]);
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false }));
    const sig = nodeSign("sha256", Buffer.concat([authData, createHash("sha256").update(clientData).digest()]), this.key);
    return { id: this.id, rawId: this.id, type: "public-key", clientExtensionResults: {}, response: { authenticatorData: b64u(authData), clientDataJSON: b64u(clientData), signature: b64u(sig) } };
  }
}

const ROOT_RIGHTS: Right[] = [{ type: "stem_mandate", locations: [DROP], actions: ["upload", "list", "delete"], path_prefix: "screens/", max_bytes: 50_000_000 }];

async function approvedMandate(env: Env, b: Browser, pk: Passkey, terms: Record<string, unknown> = {}) {
  const agent = await newKey();
  const r = await agentPost(env, "/api/auth/mandates/request", { request: await requestJwt(agent, { authorization_details: ROOT_RIGHTS, purpose: "Publish tonight's screenshots", ttl: 86400, del_max_depth: 2, ...terms }) });
  expect(r.status).toBe(200);
  const req = (await r.json()) as { request_id: string; user_code: string; approve_url: string };
  const prep = await b.json("/api/auth/mandates/prepare", { request_id: req.request_id });
  expect(prep.status).toBe(200);
  const p = (await prep.json()) as { mandate: Record<string, unknown>; publicKey: { challenge: string } };
  const ok = await b.json("/api/auth/mandates/approve", { request_id: req.request_id, response: pk.assert(p.publicKey.challenge) });
  expect(ok.status).toBe(200);
  const c = (await (await agentPost(env, "/api/auth/mandates/collect", { request_id: req.request_id })).json()) as { status: string; mandate: string };
  expect(c.status).toBe("approved");
  return { chain: [c.mandate], key: agent, id: decodeJwt(c.mandate).jti as string };
}

describe("mandates: the whole flow", () => {
  const env = makeEnv();
  const gw = new MandateGateway(ctx as never, env);
  const b = new Browser(env);
  const pk = new Passkey();
  let user: { id: string };
  beforeAll(async () => {
    user = await signIn(b, "ada@example.com");
    pk.enrol(env, user.id);
  });

  it("refuses requests for apps and actions it doesn't know, and unsigned ones", async () => {
    const agent = await newKey();
    const unknownApp = await agentPost(env, "/api/auth/mandates/request", { request: await requestJwt(agent, { authorization_details: [{ ...ROOT_RIGHTS[0], locations: ["https://evil.test"] }], purpose: "x" }) });
    expect(unknownApp.status).toBe(400);
    const unknownAction = await agentPost(env, "/api/auth/mandates/request", { request: await requestJwt(agent, { authorization_details: [{ ...ROOT_RIGHTS[0], actions: ["admin"] }], purpose: "x" }) });
    expect(unknownAction.status).toBe(400);
    const forged = (await requestJwt(agent, { authorization_details: ROOT_RIGHTS, purpose: "x" })).replace(/\.[^.]+$/, ".AAAA");
    expect((await agentPost(env, "/api/auth/mandates/request", { request: forged })).status).toBe(400);
  });

  it("shows the terms and the user code, then issues a root the passkey signed", async () => {
    const agent = await newKey();
    const r = await agentPost(env, "/api/auth/mandates/request", { request: await requestJwt(agent, { authorization_details: ROOT_RIGHTS, purpose: "Publish tonight's screenshots", ttl: 86400, del_max_depth: 2, budget: { bytes: 200_000_000 } }) });
    const req = (await r.json()) as { request_id: string; user_code: string; approve_url: string };
    expect(req.approve_url).toBe(`${ORIGIN}/mandates/approve?request=${req.request_id}`);
    expect(((await (await agentPost(env, "/api/auth/mandates/collect", { request_id: req.request_id })).json()) as { status: string }).status).toBe("pending");

    // Signed out: the approval page sends you to sign in first.
    const anon = await new Browser(env).fetch(`/mandates/approve?request=${req.request_id}`);
    expect(anon.status).toBe(302);
    expect(anon.headers.get("location")).toBe(`/sign-in?next=${encodeURIComponent(`/mandates/approve?request=${req.request_id}`)}`);
    const pageRes = await b.fetch(`/mandates/approve?request=${req.request_id}`);
    expect(pageRes.status).toBe(200);
    const html = await pageRes.text();
    expect(html).toContain(req.user_code);
    expect(html).toContain("Publish tonight&#39;s screenshots");
    expect(html).toContain("Upload files");

    const prep = (await (await b.json("/api/auth/mandates/prepare", { request_id: req.request_id })).json()) as { mandate: Record<string, unknown>; publicKey: { challenge: string; allowCredentials: { id: string }[] } };
    expect(prep.publicKey.allowCredentials.map((c) => c.id)).toEqual([pk.id]);
    expect(prep.publicKey.challenge).toBe(await rootChallenge(prep.mandate));

    // A passkey that signed something else, or without user verification, doesn't count.
    expect((await b.json("/api/auth/mandates/approve", { request_id: req.request_id, response: pk.assert(b64u(randomBytes(32))) })).status).toBe(400);
    const noUv = new Passkey(false);
    noUv.enrol(env, user.id);
    expect((await b.json("/api/auth/mandates/approve", { request_id: req.request_id, response: noUv.assert(prep.publicKey.challenge) })).status).toBe(400);

    expect((await b.json("/api/auth/mandates/approve", { request_id: req.request_id, response: pk.assert(prep.publicKey.challenge) })).status).toBe(200);
    // Answered once is answered.
    expect((await b.json("/api/auth/mandates/approve", { request_id: req.request_id, response: pk.assert(prep.publicKey.challenge) })).status).toBe(400);
    const c = (await (await agentPost(env, "/api/auth/mandates/collect", { request_id: req.request_id })).json()) as { mandate: string };
    const root = decodeJwt(c.mandate);
    expect(root).toMatchObject({ iss: ORIGIN, sub: user.id, del_depth: 0, del_max_depth: 2, authorization_details: ROOT_RIGHTS, budget: { bytes: 200_000_000 } });
    expect(root.cnf).toEqual({ jwk: agent.pub });
  });

  it("lets a sub-agent upload inside its folder and refuses it outside", async () => {
    const root = await approvedMandate(env, b, pk);
    const sub = await newKey();
    const t1 = await derive(root, { holder: sub.pub, rights: [{ type: "stem_mandate", locations: [DROP], actions: ["upload"], path_prefix: "screens/2026-11/", max_bytes: 1_000_000 }], ttl: 600 });
    const wallet = { chain: [...root.chain, t1], key: sub };
    const url = `${DROP}/api/upload`;
    const call = async (path: string, bytes = 1000, action = "upload") => {
      const h = await headers(wallet, "POST", url);
      return gw.authorize({ chain: parseAuthorization(h.authorization)!, pop: h["mandate-pop"], method: "POST", url, action, path, bytes });
    };
    const ok = await call("screens/2026-11/a.png");
    expect(ok).toMatchObject({ allowed: true, mandate: root.id, depth: 1 });
    expect(await call("private/b.png")).toMatchObject({ allowed: false, reason: "outside_mandate" });
    expect(await call("screens/2026-11/big.png", 2_000_000)).toMatchObject({ allowed: false, reason: "outside_mandate" });
    expect(await call("screens/2026-11/a.png", 10, "delete")).toMatchObject({ allowed: false, reason: "outside_mandate" });

    // The same proof twice is a replay.
    const h = await headers(wallet, "POST", url);
    const once = { chain: parseAuthorization(h.authorization)!, pop: h["mandate-pop"], method: "POST", url, action: "upload", path: "screens/2026-11/c.png", bytes: 1 };
    expect(await gw.authorize(once)).toMatchObject({ allowed: true });
    expect(await gw.authorize(once)).toMatchObject({ allowed: false, reason: "replayed" });
    // A proof for another URL or method doesn't fit.
    const other = await headers(wallet, "POST", `${DROP}/api/list`);
    expect(await gw.authorize({ ...once, pop: other["mandate-pop"] })).toMatchObject({ allowed: false, reason: "invalid_pop" });
    // A proof signed by the parent instead of the leaf doesn't fit either.
    expect(await gw.authorize({ ...once, pop: await proof(root, "POST", url) })).toMatchObject({ allowed: false, reason: "invalid_pop" });
  });

  it("refuses children that are wider, deeper or longer-lived than their parent", async () => {
    const root = await approvedMandate(env, b, pk, { del_max_depth: 1 });
    const url = `${DROP}/api/upload`;
    const tryChain = async (wallet: { chain: string[]; key: { pub: JWK; priv: JWK } }) => {
      const h = await headers(wallet, "POST", url);
      return gw.authorize({ chain: parseAuthorization(h.authorization)!, pop: h["mandate-pop"], method: "POST", url, action: "upload", path: "screens/x", bytes: 1 });
    };
    const a = await newKey();
    const wider = await derive(root, { holder: a.pub, rights: [{ ...ROOT_RIGHTS[0], actions: ["upload", "admin"] }] });
    expect(await tryChain({ chain: [...root.chain, wider], key: a })).toMatchObject({ allowed: false, reason: "wider_than_parent" });
    const noPrefix = await derive(root, { holder: a.pub, rights: [{ type: "stem_mandate", locations: [DROP], actions: ["upload"] }] });
    expect(await tryChain({ chain: [...root.chain, noPrefix], key: a })).toMatchObject({ allowed: false, reason: "wider_than_parent" });
    const ok = await derive(root, { holder: a.pub, rights: [{ ...ROOT_RIGHTS[0], actions: ["upload"] }] });
    const b2 = await newKey();
    const tooDeep = await derive({ chain: [...root.chain, ok], key: a }, { holder: b2.pub, rights: [{ ...ROOT_RIGHTS[0], actions: ["upload"] }] });
    expect(await tryChain({ chain: [...root.chain, ok, tooDeep], key: b2 })).toMatchObject({ allowed: false, reason: "too_deep" });
    // A child that doesn't name its real parent.
    const other = await approvedMandate(env, b, pk);
    const foreign = await derive(other, { holder: a.pub, rights: [{ ...ROOT_RIGHTS[0], actions: ["upload"] }] });
    expect(await tryChain({ chain: [...root.chain, foreign], key: a })).toMatchObject({ allowed: false, reason: "invalid_chain" });
    expect(await tryChain({ chain: [...root.chain, ok], key: a })).toMatchObject({ allowed: true });
  });

  it("shares one budget across every branch", async () => {
    const root = await approvedMandate(env, b, pk, { budget: { calls: 3, bytes: 5000 } });
    const url = `${DROP}/api/upload`;
    const branch = async () => {
      const k = await newKey();
      return { chain: [...root.chain, await derive(root, { holder: k.pub, rights: [{ ...ROOT_RIGHTS[0], actions: ["upload"] }] })], key: k };
    };
    const [x, y] = [await branch(), await branch()];
    const up = async (w: typeof x, bytes: number) => {
      const h = await headers(w, "POST", url);
      return gw.authorize({ chain: parseAuthorization(h.authorization)!, pop: h["mandate-pop"], method: "POST", url, action: "upload", path: "screens/a", bytes });
    };
    expect(await up(x, 2000)).toMatchObject({ allowed: true, remaining: { calls: 2, bytes: 3000 } });
    expect(await up(y, 2000)).toMatchObject({ allowed: true, remaining: { calls: 1, bytes: 1000 } });
    expect(await up(x, 2000)).toMatchObject({ allowed: false, reason: "over_budget" });
    expect(await up(y, 500)).toMatchObject({ allowed: true, remaining: { calls: 0, bytes: 500 } });
    expect(await up(x, 1)).toMatchObject({ allowed: false, reason: "over_budget" });
  });

  it("stop kills the root and every branch on the next call; the account page shows it all", async () => {
    const root = await approvedMandate(env, b, pk);
    const k = await newKey();
    const sub = { chain: [...root.chain, await derive(root, { holder: k.pub, rights: [{ ...ROOT_RIGHTS[0], actions: ["upload"] }] })], key: k };
    const url = `${DROP}/api/upload`;
    const up = async (w: { chain: string[]; key: { pub: JWK; priv: JWK } }) => {
      const h = await headers(w, "POST", url);
      return gw.authorize({ chain: parseAuthorization(h.authorization)!, pop: h["mandate-pop"], method: "POST", url, action: "upload", path: "screens/z", bytes: 5 });
    };
    expect(await up(root)).toMatchObject({ allowed: true });
    expect(await up(sub)).toMatchObject({ allowed: true });
    // Someone else can't stop it.
    const eve = new Browser(env);
    await signIn(eve, "eve@example.com");
    expect((await eve.json("/api/auth/mandates/revoke", { id: root.id })).status).toBe(404);
    expect((await b.json("/api/auth/mandates/revoke", { id: root.id })).status).toBe(200);
    expect(await up(root)).toMatchObject({ allowed: false, reason: "revoked" });
    expect(await up(sub)).toMatchObject({ allowed: false, reason: "revoked" });

    const list = (await (await b.fetch("/api/auth/mandates/list")).json()) as { id: string; status: string; rights: { apps: string[] }[] }[];
    const mine = list.find((m) => m.id === root.id)!;
    expect(mine.status).toBe("revoked");
    expect(mine.rights[0].apps).toEqual(["drop"]);
    expect(((await (await eve.fetch("/api/auth/mandates/list")).json()) as unknown[]).length).toBe(0);
    const trail = (await (await b.fetch(`/api/auth/mandates/trail?id=${root.id}`)).json()) as { seq: number; at: number; holder: string; depth: number; location: string; action: string; path: string | null; bytes: number; outcome: string; hash: string }[];
    expect(trail.map((t) => t.outcome)).toEqual(["revoked", "revoked", "allowed", "allowed"]);
    // The trail is hash-chained: anyone can recompute it.
    let prev = "";
    for (const t of [...trail].reverse()) {
      expect(t.hash).toBe(await trailHash(prev, t as never));
      prev = t.hash;
    }
    expect((await eve.fetch(`/api/auth/mandates/trail?id=${root.id}`)).status).toBe(404);
    // The account page has the section.
    expect(await (await b.fetch("/account")).text()).toContain("Your agents");
  });

  it("answers over HTTP for apps without a service binding", async () => {
    const root = await approvedMandate(env, b, pk);
    const url = `${DROP}/api/list`;
    const h = await headers(root, "GET", url);
    const res = await agentPost(env, "/api/mandates/authorize", { chain: parseAuthorization(h.authorization), pop: h["mandate-pop"], method: "GET", url, action: "list", path: "screens/" });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ allowed: true, mandate: root.id });
    const bad = await agentPost(env, "/api/mandates/authorize", { chain: ["x"], pop: "y", method: "GET", url, action: "list" });
    expect(bad.status).toBe(403);
  });

  it("asks people without a passkey to add one first, and lets them say no", async () => {
    const env2 = makeEnv();
    const c = new Browser(env2);
    await signIn(c, "no-passkey@example.com");
    const agent = await newKey();
    const req = (await (await agentPost(env2, "/api/auth/mandates/request", { request: await requestJwt(agent, { authorization_details: ROOT_RIGHTS, purpose: "x" }) })).json()) as { request_id: string };
    expect(await (await c.fetch(`/mandates/approve?request=${req.request_id}`)).text()).toContain("Add a passkey first");
    const prep = await c.json("/api/auth/mandates/prepare", { request_id: req.request_id });
    expect(prep.status).toBe(400);
    expect(((await prep.json()) as { code: string }).code).toBe("NO_PASSKEY");
    expect((await c.json("/api/auth/mandates/deny", { request_id: req.request_id })).status).toBe(200);
    expect(((await (await agentPost(env2, "/api/auth/mandates/collect", { request_id: req.request_id })).json()) as { status: string }).status).toBe("denied");
  });

  it("is off without the Durable Object binding or app list", async () => {
    const off = makeEnv({ MANDATE: undefined, MANDATE_APPS: undefined });
    const agent = await newKey();
    expect((await agentPost(off, "/api/auth/mandates/request", { request: await requestJwt(agent, { authorization_details: ROOT_RIGHTS, purpose: "x" }) })).status).toBe(404);
    expect((await new Browser(off).fetch("/mandates/approve?request=x")).status).toBe(404);
  });

  it("refuses mandates for sealed apps: a mandate names the person by stem's shared id", async () => {
    const operator = "op_" + "y".repeat(40);
    const sealed = makeEnv({ OPERATOR_TOKEN: operator, SEALED_APPS: "drop", PAIRWISE_SECRET: "p".repeat(40) });
    const reg = await new Browser(sealed).fetch("/api/v1/operator/clients", {
      method: "POST",
      headers: { authorization: `Bearer ${operator}`, "content-type": "application/json" },
      body: JSON.stringify({ app: "drop", name: "drop", redirect_uris: [`${DROP}/cb`], skip_consent: true }),
    });
    expect(reg.status).toBe(201);
    const agent = await newKey();
    const r = await agentPost(sealed, "/api/auth/mandates/request", { request: await requestJwt(agent, { authorization_details: ROOT_RIGHTS, purpose: "x" }) });
    expect(r.status).toBe(400);
    expect(((await r.json()) as { code: string }).code).toBe("SEALED_APP");
  });
});

describe("mandates: the verifier on its own", () => {
  // A stem of our own, to forge what a stolen signing key could produce.
  async function setup(uv = true) {
    const stem = await generateKeyPair("EdDSA", { extractable: true });
    const jwk = { ...(await exportJWK(stem.publicKey)), kid: "k1", alg: "EdDSA" };
    const jwks: JSONWebKeySet = { keys: [jwk] };
    const agent = await newKey();
    const pk = new Passkey(uv);
    const now = Math.floor(Date.now() / 1000);
    const core = { iss: ORIGIN, sub: "u1", aud: [DROP], jti: crypto.randomUUID(), iat: now, exp: now + 3600, cnf: { jwk: agent.pub }, authorization_details: ROOT_RIGHTS, del_depth: 0, del_max_depth: 1, purpose: "p" };
    const a = pk.assert(await rootChallenge(core));
    const jwkPk = (await import("node:crypto")).createPublicKey(pk.key).export({ format: "jwk" });
    const hp = { id: pk.id, jwk: { kty: "EC", crv: "P-256", x: jwkPk.x, y: jwkPk.y }, ...a.response };
    const signRoot = (payload: object) => new SignJWT(payload as never).setProtectedHeader({ alg: "EdDSA", typ: "mandate+jwt", kid: "k1" }).sign(stem.privateKey);
    return { jwks, agent, core, hp, signRoot };
  }
  const url = `${DROP}/api/upload`;

  it("verifies a good root and refuses one stem widened after the passkey signed", async () => {
    const s = await setup();
    const good = { chain: [await s.signRoot({ ...s.core, hp: s.hp })], key: s.agent };
    const v = await verifyMandate(good.chain, await proof(good, "POST", url), { jwks: s.jwks, issuer: ORIGIN, method: "POST", url });
    expect(v.rights).toEqual(ROOT_RIGHTS);
    const widened = { chain: [await s.signRoot({ ...s.core, authorization_details: [{ ...ROOT_RIGHTS[0], actions: ["upload", "list", "delete", "admin"] }], hp: s.hp })], key: s.agent };
    await expect(verifyMandate(widened.chain, await proof(widened, "POST", url), { jwks: s.jwks, issuer: ORIGIN, method: "POST", url })).rejects.toMatchObject({ code: "invalid_human_proof" });
    // Another issuer's key, or a root without its human proof.
    const noHp = { chain: [await s.signRoot(s.core)], key: s.agent };
    await expect(verifyMandate(noHp.chain, await proof(noHp, "POST", url), { jwks: s.jwks, issuer: ORIGIN, method: "POST", url })).rejects.toBeInstanceOf(MandateError);
    const other = await generateKeyPair("EdDSA", { extractable: true });
    await expect(verifyMandate(good.chain, await proof(good, "POST", url), { jwks: { keys: [{ ...(await exportJWK(other.publicKey)), kid: "k1", alg: "EdDSA" }] }, issuer: ORIGIN, method: "POST", url })).rejects.toMatchObject({ code: "invalid_chain" });
    // Too old a proof.
    const later = Math.floor(Date.now() / 1000) + 200;
    await expect(verifyMandate(good.chain, await proof(good, "POST", url), { jwks: s.jwks, issuer: ORIGIN, method: "POST", url, now: later })).rejects.toMatchObject({ code: "invalid_pop" });
  });

  it("refuses a passkey assertion without user verification", async () => {
    const s = await setup(false);
    const w = { chain: [await s.signRoot({ ...s.core, hp: s.hp })], key: s.agent };
    await expect(verifyMandate(w.chain, await proof(w, "POST", url), { jwks: s.jwks, issuer: ORIGIN, method: "POST", url })).rejects.toMatchObject({ code: "invalid_human_proof", message: "user was not verified" });
  });

  it("canonicalizes like RFC 8785 and checks narrowing", () => {
    expect(canonicalize({ b: 1, a: [true, null, "x"], c: { z: 1.5, y: -0 } })).toBe('{"a":[true,null,"x"],"b":1,"c":{"y":0,"z":1.5}}');
    const r = (o: Partial<Right>): Right => ({ type: "stem_mandate", locations: [DROP], actions: ["upload"], ...o });
    expect(narrower([r({ path_prefix: "a/b/" })], [r({ path_prefix: "a/" })])).toBe(true);
    expect(narrower([r({})], [r({ path_prefix: "a/" })])).toBe(false);
    expect(narrower([r({ max_bytes: 10 })], [r({ max_bytes: 5 })])).toBe(false);
    expect(narrower([r({ locations: ["https://x.test"] })], [r({})])).toBe(false);
    expect(allows([r({ path_prefix: "a/" })], { location: DROP, action: "upload" })).toBe(false);
    expect(allows([r({ path_prefix: "a/" })], { location: DROP, action: "upload", path: "a/1" })).toBe(true);
    expect(parseAuthorization("Mandate a~b~c")).toEqual(["a", "b", "c"]);
    expect(parseAuthorization("Bearer abc")).toBeNull();
  });
});
