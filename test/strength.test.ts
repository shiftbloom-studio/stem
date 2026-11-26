// Sign-in strength: sessions remember how they were signed in, tokens carry it as auth_method,
// and an app's step-up request (prompt=login) offers the person's passkey first.
// Passkey sign-ins use a software authenticator, so the real WebAuthn verification runs.
import { describe, it, expect, beforeAll } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { createHash, randomBytes, generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { decodeJwt } from "jose";
import app from "../src/index";
import { strengthClaims, wantsStepUp, SIGN_IN_METHODS } from "../src/strength";
import type { Env } from "../src/env";

const ORIGIN = "https://stem.test";
const API = "https://app.test/api";
const CALLBACK = "https://app.test/auth/callback";
const OPERATOR = "op_" + "y".repeat(40);

const sent: { to: string; text: string }[] = [];
const pending: Promise<unknown>[] = [];
const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {}, props: {} };

function makeEnv(): { env: Env; db: DatabaseSync } {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  for (const f of readdirSync("migrations").filter((f) => f.endsWith(".sql")).sort()) db.exec(readFileSync(`migrations/${f}`, "utf8"));
  const env = {
    DB: db as unknown as D1Database,
    ASSETS: { fetch: async () => new Response("") } as unknown as Fetcher,
    EMAIL: { send: async (m: { to: string; text: string }) => { sent.push(m); return { messageId: "m" }; } } as unknown as SendEmail,
    EMAIL_FROM: "stem <login@stem.test>",
    STEM_URL: ORIGIN,
    BETTER_AUTH_SECRET: randomBytes(32).toString("base64url"),
    OPERATOR_TOKEN: OPERATOR,
    RESOURCES: API,
  } as Env;
  return { env, db };
}

let nextIp = 1;
class Browser {
  cookies = new Map<string, string>();
  constructor(private env: Env, public ip = `203.0.113.${nextIp++}`) {}
  async fetch(path: string, init: RequestInit = {}) {
    const headers = new Headers(init.headers);
    headers.set("origin", ORIGIN);
    headers.set("cf-connecting-ip", this.ip);
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
  json(path: string, body: unknown) {
    return this.fetch(path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
  }
}

async function codeSignIn(b: Browser, email: string) {
  expect((await b.json("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" })).status).toBe(200);
  const code = /(\d{6})/.exec(sent.filter((m) => m.to === email).at(-1)!.text)![1];
  const r = await b.json("/api/auth/sign-in/email-otp", { email, otp: code });
  expect(r.status).toBe(200);
  return ((await r.json()) as { user: { id: string } }).user.id;
}

const b64url = (b: Buffer | Uint8Array) => Buffer.from(b).toString("base64url");

/** A software passkey: a P-256 key whose public half is stored the way the passkey plugin stores it. */
class SoftPasskey {
  id = b64url(randomBytes(16));
  private key: KeyObject;
  private counter = 0;
  constructor(db: DatabaseSync, userId: string, public synced: boolean) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.key = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    const x = Buffer.from(jwk.x!, "base64url"), y = Buffer.from(jwk.y!, "base64url");
    // COSE_Key {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
    const cose = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), x, Buffer.from([0x22, 0x58, 0x20]), y]);
    db.prepare(`insert into "passkey" ("id", "name", "publicKey", "userId", "credentialID", "counter", "deviceType", "backedUp", "transports", "createdAt") values (?, ?, ?, ?, ?, 0, ?, ?, 'internal', ?)`)
      .run(crypto.randomUUID(), "Test key", cose.toString("base64"), userId, this.id, synced ? "multiDevice" : "singleDevice", synced ? 1 : 0, new Date().toISOString());
  }
  async signIn(b: Browser, oauthQuery?: string) {
    const opts = await b.fetch("/api/auth/passkey/generate-authenticate-options");
    expect(opts.status).toBe(200);
    const { challenge } = (await opts.json()) as { challenge: string };
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: ORIGIN, crossOrigin: false }));
    // flags: user present, user verified, plus backup eligible and backed up for synced keys
    const flags = 0x01 | 0x04 | (this.synced ? 0x08 | 0x10 : 0);
    const count = Buffer.alloc(4); count.writeUInt32BE(++this.counter);
    const authData = Buffer.concat([createHash("sha256").update("stem.test").digest(), Buffer.from([flags]), count]);
    const signature = sign("sha256", Buffer.concat([authData, createHash("sha256").update(clientData).digest()]), this.key);
    return b.json("/api/auth/passkey/verify-authentication", {
      response: { id: this.id, rawId: this.id, type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: b64url(clientData), authenticatorData: b64url(authData), signature: b64url(signature) } },
      ...(oauthQuery ? { oauth_query: oauthQuery } : {}),
    });
  }
}

const pkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

describe("wantsStepUp", () => {
  it.each([
    ["prompt=login", true],
    ["prompt=consent%20login", true],
    ["max_age=300", true],
    ["max_age=0", true],
    ["acr_values=phr", true],
    ["acr_values=urn%3Aexample%20phrh", true],
    ["prompt=consent", false],
    ["acr_values=0", false],
    ["", false],
  ])("%s → %s", (q, want) => expect(wantsStepUp(new URLSearchParams(q))).toBe(want));
});

describe("strengthClaims", () => {
  const db = (row: Record<string, unknown> | null) => ({ findOne: async () => row, update: async () => null }) as never;
  const live = { id: "s", createdAt: new Date(1_700_000_000_000), expiresAt: new Date(Date.now() + 60_000) };
  it("is unknown without a session", async () => expect(await strengthClaims(db(null), undefined)).toEqual({ auth_method: "unknown" }));
  it("is unknown for a session that has expired", async () => expect(await strengthClaims(db({ ...live, authMethod: "passkey", expiresAt: new Date(Date.now() - 1) }), "s")).toEqual({ auth_method: "unknown" }));
  it("is unknown for sessions from before the marker", async () => expect(await strengthClaims(db({ ...live, authMethod: null }), "s")).toEqual({ auth_method: "unknown", signed_in_at: 1_700_000_000 }));
  it("never trusts an unexpected stored value", async () => expect((await strengthClaims(db({ ...live, authMethod: "hardware" }), "s")).auth_method).toBe("unknown"));
  it("reports passkeys with their sync state", async () => expect(await strengthClaims(db({ ...live, authMethod: "passkey", passkeySynced: 0 }), "s")).toEqual({ auth_method: "passkey", passkey_synced: false, signed_in_at: 1_700_000_000 }));
  it("covers each sign-in endpoint", () => expect(SIGN_IN_METHODS).toEqual({ "/sign-in/email-otp": "email_code", "/email-otp/verify-email": "email_code", "/passkey/verify-authentication": "passkey" }));
});

describe("sign-in strength in tokens", () => {
  let env: Env, db: DatabaseSync;
  let client: { client_id: string; client_secret: string };
  let basic: string;

  async function authorize(b: Browser, extra: Record<string, string> = {}) {
    const { verifier, challenge } = pkce();
    const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CALLBACK, scope: "openid email offline_access", state: "s", nonce: "n", code_challenge: challenge, code_challenge_method: "S256", resource: API, ...extra });
    const r = await b.fetch(`/api/auth/oauth2/authorize?${q}`);
    return { r, verifier };
  }
  async function exchange(b: Browser, location: string, verifier: string) {
    const code = new URL(location).searchParams.get("code")!;
    const tr = await b.fetch("/api/auth/oauth2/token", {
      method: "POST",
      headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CALLBACK, code_verifier: verifier, resource: API }),
    });
    expect(tr.status).toBe(200);
    return (await tr.json()) as { access_token: string; id_token: string; refresh_token: string };
  }
  async function tokensFor(b: Browser) {
    const { r, verifier } = await authorize(b);
    expect([302, 303]).toContain(r.status);
    return exchange(b, r.headers.get("location")!, verifier);
  }

  beforeAll(async () => {
    ({ env, db } = makeEnv());
    const b = new Browser(env);
    const rc = await b.fetch("/api/v1/operator/clients", { method: "POST", headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" }, body: JSON.stringify({ app: "demo", name: "Demo App", redirect_uris: [CALLBACK], resources: [API], skip_consent: true }) });
    expect(rc.status).toBe(201);
    client = (await rc.json()) as typeof client;
    basic = "Basic " + btoa(`${client.client_id}:${client.client_secret}`);
  });

  it("says email_code after a code sign-in, in access and ID tokens", async () => {
    const b = new Browser(env);
    await codeSignIn(b, "code@example.com");
    const t = await tokensFor(b);
    const at = decodeJwt(t.access_token), idt = decodeJwt(t.id_token);
    expect(at.auth_method).toBe("email_code");
    expect(at.passkey_synced).toBeUndefined();
    expect(typeof at.signed_in_at).toBe("number");
    expect(Math.abs((at.signed_in_at as number) - Date.now() / 1000)).toBeLessThan(60);
    expect(idt.auth_method).toBe("email_code");
    expect(idt.signed_in_at).toBe(idt.auth_time);
    // The authorization server still owns acr.
    expect(idt.acr).toBe("0");
  });

  it("says passkey after a passkey sign-in, with whether the passkey is synced", async () => {
    const setup = new Browser(env);
    const userId = await codeSignIn(setup, "keys@example.com");
    const synced = new SoftPasskey(db, userId, true);
    const bound = new SoftPasskey(db, userId, false);

    const b1 = new Browser(env);
    expect((await synced.signIn(b1)).status).toBe(200);
    const t1 = await tokensFor(b1);
    expect(decodeJwt(t1.access_token)).toMatchObject({ sub: userId, auth_method: "passkey", passkey_synced: true });
    expect(decodeJwt(t1.id_token)).toMatchObject({ auth_method: "passkey", passkey_synced: true });

    const b2 = new Browser(env);
    expect((await bound.signIn(b2)).status).toBe(200);
    const t2 = await tokensFor(b2);
    expect(decodeJwt(t2.access_token)).toMatchObject({ auth_method: "passkey", passkey_synced: false });

    // Refreshing keeps the session's method.
    const rr = await b2.fetch("/api/auth/oauth2/token", {
      method: "POST",
      headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: t2.refresh_token, resource: API }),
    });
    expect(rr.status).toBe(200);
    expect(decodeJwt(((await rr.json()) as { access_token: string }).access_token)).toMatchObject({ auth_method: "passkey", passkey_synced: false });

    // The data export shows the method per session.
    const exp = (await (await b2.fetch("/api/auth/stem/export")).json()) as { sessions: { sign_in_method: string | null }[] };
    expect(exp.sessions.map((s) => s.sign_in_method).sort()).toEqual(["email_code", "passkey", "passkey"]);
  });

  it("reports unknown for a session that has no method", async () => {
    const b = new Browser(env);
    await codeSignIn(b, "old@example.com");
    db.exec(`update "session" set "authMethod" = null where "userId" = (select "id" from "user" where "email" = 'old@example.com')`);
    const t = await tokensFor(b);
    expect(decodeJwt(t.access_token).auth_method).toBe("unknown");
  });

  it("doesn't let a person set their own method", async () => {
    const b = new Browser(env);
    await codeSignIn(b, "sneaky@example.com");
    const r = await b.json("/api/auth/update-session", { authMethod: "passkey", passkeySynced: false });
    expect(r.status).not.toBe(500);
    const t = await tokensFor(b);
    expect(decodeJwt(t.access_token).auth_method).toBe("email_code");
  });

  it("leaves client-credentials tokens alone", async () => {
    const r = await new Browser(env).fetch("/api/auth/oauth2/token", {
      method: "POST",
      headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", scope: "directory", resource: `${ORIGIN}/api/v1` }),
    });
    expect(r.status).toBe(200);
    expect(decodeJwt(((await r.json()) as { access_token: string }).access_token).auth_method).toBeUndefined();
  });

  it("offers the passkey first when an app asks for a fresh sign-in, and the new token shows it", async () => {
    const b = new Browser(env);
    const userId = await codeSignIn(b, "admin@example.com");
    const key = new SoftPasskey(db, userId, true);

    const { r, verifier } = await authorize(b, { prompt: "login" });
    const login = new URL(r.headers.get("location")!, ORIGIN);
    expect(login.pathname).toBe("/sign-in");
    const page = await (await b.fetch(login.pathname + login.search)).text();
    expect(page).toContain("Confirm with your passkey");
    expect(page).toContain("data-step-up");
    expect(page).toContain('value="admin@example.com"');
    expect(page).toContain("Demo App");

    // Same person, now with a passkey. The OAuth flow continues from the sign-in response.
    const res = await key.signIn(b, login.search.slice(1));
    expect(res.status).toBe(200);
    const body = (await res.json()) as { url?: string };
    expect(body.url).toBeTruthy();
    const t = await exchange(b, body.url!, verifier);
    const at = decodeJwt(t.access_token);
    expect(at).toMatchObject({ sub: userId, auth_method: "passkey" });
    expect(Math.abs((at.signed_in_at as number) - Date.now() / 1000)).toBeLessThan(60);
  });

  it("keeps the normal sign-in page for people without a passkey, or without a step-up request", async () => {
    const b = new Browser(env);
    await codeSignIn(b, "nokey@example.com");
    const { r } = await authorize(b, { prompt: "login" });
    const login = new URL(r.headers.get("location")!, ORIGIN);
    const page = await (await b.fetch(login.pathname + login.search)).text();
    expect(page).toContain("Sign in with a passkey");
    expect(page).not.toContain("data-step-up");
    expect(page).not.toContain("nokey@example.com");

    const fresh = new Browser(env);
    const { r: r2 } = await authorize(fresh);
    const login2 = new URL(r2.headers.get("location")!, ORIGIN);
    expect(await (await fresh.fetch(login2.pathname + login2.search)).text()).not.toContain("data-step-up");
  });
});
