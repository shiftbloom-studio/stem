// End-to-end: operator setup, email-code sign-in, OpenID Connect code flow with PKCE, token claims,
// and the directory API. Runs the real Worker app on an in-memory SQLite database.
import { describe, it, expect, beforeAll } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { createLocalJWKSet, jwtVerify, decodeJwt, type JSONWebKeySet } from "jose";
import app from "../src/index";
import { UNUSED_PATHS, createAuth } from "../src/auth";
import { cleanup } from "../src/cleanup";
import type { Env } from "../src/env";

const ORIGIN = "https://stem.test";
const API = "https://app.test/api";
const CALLBACK = "https://app.test/auth/callback";
const OPERATOR = "op_" + "x".repeat(40);

const sent: { to: string; subject: string; text: string }[] = [];
const pending: Promise<unknown>[] = [];
const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {}, props: {} };

function makeEnv(extra: Partial<Env> = {}): Env {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  for (const f of readdirSync("migrations").filter((f) => f.endsWith(".sql")).sort()) db.exec(readFileSync(`migrations/${f}`, "utf8"));
  return {
    DB: db as unknown as D1Database,
    ASSETS: { fetch: async () => new Response("/* app */", { headers: { "content-type": "application/javascript" } }) } as unknown as Fetcher,
    EMAIL: { send: async (m: { to: string; subject: string; text: string }) => { sent.push(m); return { messageId: "m" }; } } as unknown as SendEmail,
    EMAIL_FROM: "stem <login@stem.test>",
    STEM_URL: ORIGIN,
    BETTER_AUTH_SECRET: randomBytes(32).toString("base64url"),
    OPERATOR_TOKEN: OPERATOR,
    ORG_ROLES: "dispatcher,pilot",
    RESOURCES: API,
    ...extra,
  };
}

class Browser {
  cookies = new Map<string, string>();
  constructor(private env: Env, public ip = "203.0.113.7") {}
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
  json(path: string, body: unknown, headers: Record<string, string> = {}) {
    return this.fetch(path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json", ...headers } });
  }
}

const op = (b: Browser, path: string, body?: unknown) =>
  b.fetch(`/api/v1/operator${path}`, { method: body ? "POST" : "GET", body: body ? JSON.stringify(body) : undefined, headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" } });

async function signIn(b: Browser, email: string) {
  const r1 = await b.json("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" });
  expect(r1.status).toBe(200);
  const mail = sent.filter((m) => m.to === email).at(-1)!;
  const code = /(\d{6})/.exec(mail.text)![1];
  const r2 = await b.json("/api/auth/sign-in/email-otp", { email, otp: code });
  expect(r2.status).toBe(200);
  return (await r2.json()) as { user: { id: string; email: string } };
}

const pkce = () => {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
};

describe("stem", () => {
  let env: Env;
  let browser: Browser;
  let client: { client_id: string; client_secret: string };
  let orgId: string;
  let ownerId: string;
  let refreshToken: string;

  beforeAll(async () => {
    env = makeEnv();
    browser = new Browser(env);
  });

  it("serves robots.txt that blocks AI training and sets security headers", async () => {
    const r = await browser.fetch("/robots.txt");
    const t = await r.text();
    expect(t).toContain("ai-train=no");
    expect(t).toContain("User-agent: GPTBot\n");
    const home = await browser.fetch("/");
    expect(home.headers.get("content-security-policy")).toContain("frame-ancestors 'none'");
    expect(home.headers.get("strict-transport-security")).toContain("max-age=");
    expect(await home.text()).not.toMatch(/<script>(?!<\/script>)/);
  });

  it("hides legal pages until operator details are configured", async () => {
    expect((await browser.fetch("/impressum")).status).toBe(404);
    const legal = JSON.stringify({ name: "Test Operator", street: "Street 1", city: "12345 Town", country: { en: "Germany", de: "Deutschland" }, email: "hi@example.com", authority: "Some authority" });
    const b2 = new Browser({ ...env, LEGAL: legal });
    for (const p of ["/privacy", "/datenschutz", "/imprint", "/impressum"]) {
      const r = await b2.fetch(p);
      expect(r.status).toBe(200);
      expect(await r.text()).toContain("Test Operator");
    }
  });

  it("refuses the operator API without the token", async () => {
    const r = await browser.fetch("/api/v1/operator/orgs", { headers: { authorization: "Bearer nope" } });
    expect(r.status).toBe(401);
  });

  it("registers a client and an organization with an owner", async () => {
    const rc = await op(browser, "/clients", { app: "demo", name: "Demo App", uri: "https://app.test", redirect_uris: [CALLBACK], post_logout_redirect_uris: ["https://app.test/"], resources: [API], skip_consent: true });
    expect(rc.status).toBe(201);
    client = (await rc.json()) as typeof client;
    expect(client.client_id).toBeTruthy();
    expect(client.client_secret).toBeTruthy();

    const ro = await op(browser, "/orgs", { app: "demo", name: "Virtual Airline", slug: "va", owner_email: "owner@example.com" });
    expect(ro.status).toBe(201);
    const org = (await ro.json()) as { id: string; owner: { id: string } };
    orgId = org.id;
    ownerId = org.owner.id;
    expect((await op(browser, "/orgs", { app: "demo", name: "Again", slug: "va" })).status).toBe(409);
  });

  it("signs in with an email code", async () => {
    const { user } = await signIn(browser, "owner@example.com");
    expect(user.id).toBe(ownerId);
    expect([...browser.cookies.keys()].some((k) => k.startsWith("__Secure-stem."))).toBe(true);
    expect((await browser.fetch("/account")).status).toBe(200);
  });

  it("limits codes per address, whatever the IP", async () => {
    const email = "target@example.com";
    const first = await new Browser(env, "198.51.100.1").json("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" });
    expect(first.status).toBe(200);
    const second = await new Browser(env, "198.51.100.2").json("/api/auth/email-otp/send-verification-otp", { email: "Target@Example.com", type: "sign-in" });
    expect(second.status).toBe(429);
    const statuses: number[] = [];
    for (let i = 0; i < 16; i++) {
      const r = await new Browser(env, `198.51.100.${10 + i}`).json("/api/auth/sign-in/email-otp", { email, otp: String(100000 + i) });
      statuses.push(r.status);
    }
    expect(statuses.slice(0, 15).every((st) => st !== 429 && st >= 400)).toBe(true);
    expect(statuses[15]).toBe(429);
    // Even the right code is refused once the address is locked for the day.
    const code = /(\d{6})/.exec(sent.filter((m) => m.to === email).at(-1)!.text)![1];
    expect((await new Browser(env, "198.51.100.99").json("/api/auth/sign-in/email-otp", { email, otp: code })).status).toBe(429);
  });

  it("doesn't count guesses when no code was sent", async () => {
    const email = "nocode@example.com";
    for (let i = 0; i < 20; i++) {
      const r = await new Browser(env, `198.51.101.${10 + i}`).json("/api/auth/sign-in/email-otp", { email, otp: String(200000 + i) });
      expect(r.status).not.toBe(429);
    }
    const send = await new Browser(env, "198.51.101.99").json("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" });
    expect(send.status).toBe(200);
  });

  it("keeps organizations in the app's hands", async () => {
    for (const path of ["update", "delete", "invite-member", "update-member-role", "remove-member", "create", "set-active", "leave"]) {
      const r = await browser.json(`/api/auth/organization/${path}`, { organizationId: orgId, data: { slug: "renamed" } });
      expect(r.status, path).toBe(404);
    }
    const list = await browser.fetch("/api/auth/organization/list");
    expect(list.status).toBe(200);
    expect(((await list.json()) as { slug: string }[]).map((o) => o.slug)).toEqual(["va"]);
  });

  it("doesn't hand out session JWTs", async () => {
    expect((await browser.fetch("/api/auth/token")).status).toBe(404);
  });

  it("switches off password, email-change and social endpoints", async () => {
    const before = sent.length;
    for (const path of UNUSED_PATHS) {
      const r = await new Browser(env, "198.51.102.1").json(`/api/auth${path}`, { email: "owner@example.com", newEmail: "new@example.com", otp: "123456", password: "a-long-password-1", provider: "github" });
      expect(r.status, path).toBe(404);
    }
    // Password-reset codes would skip the bot check and the per-address limits.
    const r = await new Browser(env, "198.51.102.2").json("/api/auth/email-otp/send-verification-otp", { email: "owner@example.com", type: "forget-password" });
    expect(r.status).toBe(400);
    expect(sent.length).toBe(before);
  });

  it("rejects a wrong code", async () => {
    const b = new Browser(env);
    await b.json("/api/auth/email-otp/send-verification-otp", { email: "someone@example.com", type: "sign-in" });
    const r = await b.json("/api/auth/sign-in/email-otp", { email: "someone@example.com", otp: "000000" });
    expect(r.status).toBeGreaterThanOrEqual(400);
  });

  it("runs the authorization code flow and issues a JWT with org claims", async () => {
    const { verifier, challenge } = pkce();
    const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CALLBACK, scope: "openid profile email offline_access orgs", state: "st4te", nonce: "n0nce", code_challenge: challenge, code_challenge_method: "S256", resource: API });
    const r = await browser.fetch(`/api/auth/oauth2/authorize?${q}`);
    expect([302, 303]).toContain(r.status);
    const loc = new URL(r.headers.get("location")!);
    expect(loc.origin + loc.pathname).toBe(CALLBACK);
    expect(loc.searchParams.get("state")).toBe("st4te");
    const code = loc.searchParams.get("code")!;

    const basic = "Basic " + btoa(`${client.client_id}:${client.client_secret}`);
    const tr = await browser.fetch("/api/auth/oauth2/token", {
      method: "POST",
      headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: CALLBACK, code_verifier: verifier, resource: API }),
    });
    const tokens = (await tr.json()) as { access_token: string; id_token: string; refresh_token: string };
    expect(tr.status, JSON.stringify(tokens)).toBe(200);
    expect(tokens.refresh_token).toBeTruthy();

    const disco = (await (await browser.fetch("/.well-known/openid-configuration")).json()) as { issuer: string; jwks_uri: string };
    expect(disco.issuer).toBe(ORIGIN);
    const jwks = (await (await browser.fetch(new URL(disco.jwks_uri).pathname)).json()) as JSONWebKeySet;
    const { payload, protectedHeader } = await jwtVerify(tokens.access_token, createLocalJWKSet(jwks), { issuer: ORIGIN, audience: API });
    expect(protectedHeader.alg).toBe("EdDSA");
    expect(protectedHeader.typ).toBe("at+jwt");
    expect(payload.sub).toBe(ownerId);
    expect(payload.email).toBe("owner@example.com");
    expect(payload.orgs).toEqual({ [orgId]: "owner" });

    const idt = decodeJwt(tokens.id_token);
    expect(idt.nonce).toBe("n0nce");
    expect(idt.orgs).toEqual({ [orgId]: "owner" });

    const rr = await browser.fetch("/api/auth/oauth2/token", {
      method: "POST",
      headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, resource: API }),
    });
    expect(rr.status).toBe(200);
    const refreshed = (await rr.json()) as { refresh_token: string };
    expect(refreshed.refresh_token).not.toBe(tokens.refresh_token);
    const again = await browser.fetch("/api/auth/oauth2/token", {
      method: "POST",
      headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tokens.refresh_token, resource: API }),
    });
    expect(again.status).toBe(200);
    expect(((await again.json()) as { refresh_token: string }).refresh_token).toBe(refreshed.refresh_token);
    refreshToken = refreshed.refresh_token;
  });

  it("exports a person's data without secrets", async () => {
    const r = await browser.fetch("/api/auth/stem/export");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-disposition")).toMatch(/^attachment; filename="stem-data-/);
    const text = await r.text();
    const data = JSON.parse(text) as { account: { email: string }; teams: { organization: { id: string }; role: string }[]; sessions: unknown[]; apps: { client_id: string }[] };
    expect(data.account.email).toBe("owner@example.com");
    expect(data.teams).toEqual([expect.objectContaining({ organization: expect.objectContaining({ id: orgId, app: "demo" }), role: "owner" })]);
    expect(data.sessions.length).toBeGreaterThan(0);
    expect(data.apps.map((a) => a.client_id)).toContain(client.client_id);
    expect(text).not.toContain(refreshToken);
    expect(text).not.toMatch(/"(token|publicKey|privateKey|clientSecret|value)"/);
    expect((await new Browser(env).fetch("/api/auth/stem/export")).status).toBe(401);
  });

  it("lets a person remove an app's access", async () => {
    const list = (await (await browser.fetch("/api/auth/stem/apps")).json()) as { client_id: string; name: string }[];
    expect(list).toEqual([expect.objectContaining({ client_id: client.client_id, name: "Demo App" })]);
    // Another site can't do it for them.
    const cookie = [...browser.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    const forged = await app.fetch(new Request(`${ORIGIN}/api/auth/stem/apps/remove`, { method: "POST", body: JSON.stringify({ client_id: client.client_id }), headers: { "content-type": "application/json", origin: "https://evil.test", cookie } }), env, ctx as never);
    expect(forged.status).toBe(403);
    const forgedRename = await app.fetch(new Request(`${ORIGIN}/api/auth/update-user`, { method: "POST", body: JSON.stringify({ name: "pwned" }), headers: { "content-type": "application/json", origin: "https://evil.test", cookie } }), env, ctx as never);
    expect(forgedRename.status).toBe(403);
    expect((await browser.json("/api/auth/stem/apps/remove", { client_id: client.client_id })).status).toBe(200);
    expect(await (await browser.fetch("/api/auth/stem/apps")).json()).toEqual([]);
    const basic = "Basic " + btoa(`${client.client_id}:${client.client_secret}`);
    const rr = await browser.fetch("/api/auth/oauth2/token", {
      method: "POST",
      headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, resource: API }),
    });
    expect(rr.status).toBeGreaterThanOrEqual(400);
  });

  it("sends a signed-out person to sign in and back to the app", async () => {
    const { challenge } = pkce();
    const b = new Browser(env);
    const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CALLBACK, scope: "openid email orgs", state: "s2", code_challenge: challenge, code_challenge_method: "S256", resource: API });
    const r = await b.fetch(`/api/auth/oauth2/authorize?${q}`);
    const login = new URL(r.headers.get("location")!, ORIGIN);
    expect(login.pathname).toBe("/sign-in");
    const page = await b.fetch(login.pathname + login.search);
    expect(await page.text()).toContain("Demo App");
    await b.json("/api/auth/email-otp/send-verification-otp", { email: "new@example.com", type: "sign-in" });
    const code = /(\d{6})/.exec(sent.filter((m) => m.to === "new@example.com").at(-1)!.text)![1];
    const oauthQuery = login.search.slice(1);
    const res = await b.json("/api/auth/sign-in/email-otp", { email: "new@example.com", otp: code, oauth_query: oauthQuery });
    const data = (await res.json()) as { redirect?: boolean; url?: string };
    expect(data.redirect).toBe(true);
    const back = new URL(data.url!);
    expect(back.origin + back.pathname).toBe(CALLBACK);
    expect(back.searchParams.get("code")).toBeTruthy();
    expect(back.searchParams.get("state")).toBe("s2");
  });

  it("doesn't let signed-in users register OAuth clients", async () => {
    const r = await browser.json("/api/auth/oauth2/create-client", { redirect_uris: ["https://evil.test/cb"], client_name: "Evil" });
    expect(r.status).toBeGreaterThanOrEqual(400);
    const r2 = await browser.json("/api/auth/admin/oauth2/create-client", { redirect_uris: ["https://evil.test/cb"] }, { "x-stem-operator": "guess" });
    expect(r2.status).toBeGreaterThanOrEqual(400);
  });

  it("rejects a redirect URI that isn't registered", async () => {
    const { challenge } = pkce();
    const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: "https://evil.test/cb", scope: "openid", code_challenge: challenge, code_challenge_method: "S256" });
    const r = await browser.fetch(`/api/auth/oauth2/authorize?${q}`);
    const loc = r.headers.get("location") || "";
    expect(loc.startsWith("https://evil.test")).toBe(false);
  });

  describe("directory API", () => {
    let token: string;
    const call = (path: string, init: RequestInit = {}) =>
      browser.fetch(`/api/v1${path}`, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init.headers || {}) } });

    beforeAll(async () => {
      const r = await browser.fetch("/api/auth/oauth2/token", {
        method: "POST",
        headers: { authorization: "Basic " + btoa(`${client.client_id}:${client.client_secret}`), "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "client_credentials", scope: "directory", resource: `${ORIGIN}/api/v1` }),
      });
      const j = (await r.json()) as { access_token: string };
      expect(r.status, JSON.stringify(j)).toBe(200);
      token = j.access_token;
    });

    it("needs a client-credentials token", async () => {
      expect((await browser.fetch("/api/v1/orgs")).status).toBe(401);
      expect((await browser.fetch("/api/v1/orgs", { headers: { authorization: "Bearer abc.def.ghi" } })).status).toBe(401);
    });

    it("rejects user access tokens", async () => {
      const { verifier, challenge } = pkce();
      const q = new URLSearchParams({ response_type: "code", client_id: client.client_id, redirect_uri: CALLBACK, scope: "openid orgs", code_challenge: challenge, code_challenge_method: "S256", resource: API });
      const loc = new URL((await browser.fetch(`/api/auth/oauth2/authorize?${q}`)).headers.get("location")!);
      const tr = await browser.fetch("/api/auth/oauth2/token", {
        method: "POST",
        headers: { authorization: "Basic " + btoa(`${client.client_id}:${client.client_secret}`), "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ grant_type: "authorization_code", code: loc.searchParams.get("code")!, redirect_uri: CALLBACK, code_verifier: verifier, resource: API }),
      });
      const { access_token } = (await tr.json()) as { access_token: string };
      expect((await browser.fetch("/api/v1/orgs", { headers: { authorization: `Bearer ${access_token}` } })).status).toBe(401);
    });

    it("lists only the app's organizations", async () => {
      await op(browser, "/orgs", { app: "other", name: "Other", slug: "other" });
      const r = await call("/orgs");
      const { data } = (await r.json()) as { data: { id: string; app: string }[] };
      expect(data.map((o) => o.id)).toEqual([orgId]);
      const other = ((await (await op(browser, "/orgs?app=other")).json()) as { data: { id: string }[] }).data[0];
      expect((await call(`/orgs/${other.id}`)).status).toBe(404);
      expect((await call(`/orgs/${other.id}/members`)).status).toBe(404);
    });

    it("invites, and the invited person accepts after signing in", async () => {
      expect((await call(`/orgs/${orgId}/invitations`, { method: "POST", body: JSON.stringify({ email: "pilot@example.com", role: "pilot", redirect_to: "https://evil.test/" }) })).status).toBe(400);
      expect((await call(`/orgs/${orgId}/invitations`, { method: "POST", body: JSON.stringify({ email: "pilot@example.com", role: "captain" }) })).status).toBe(400);
      const r = await call(`/orgs/${orgId}/invitations`, { method: "POST", body: JSON.stringify({ email: "Pilot@Example.com", role: "pilot", inviter_id: ownerId, redirect_to: "https://app.test/va" }) });
      expect(r.status).toBe(201);
      const inv = (await r.json()) as { id: string; email: string };
      expect(inv.email).toBe("pilot@example.com");
      const mail = sent.filter((m) => m.to === "pilot@example.com").at(-1)!;
      expect(mail.text).toContain(`${ORIGIN}/invite/${inv.id}`);

      const pilot = new Browser(env);
      expect((await pilot.fetch(`/invite/${inv.id}`)).status).toBe(200);
      await signIn(pilot, "pilot@example.com");
      const acc = await pilot.json("/api/auth/organization/accept-invitation", { invitationId: inv.id });
      expect(acc.status).toBe(200);
      const cont = await pilot.fetch(`/invite/${inv.id}/continue`);
      expect(cont.headers.get("location")).toBe("https://app.test/va");

      const members = (await (await call(`/orgs/${orgId}/members`)).json()) as { data: { user_id: string; role: string; user: { email: string } }[]; total: number };
      expect(members.total).toBe(2);
      expect(members.data.find((m) => m.user.email === "pilot@example.com")?.role).toBe("pilot");
    });

    it("changes roles but protects the last owner", async () => {
      expect((await call(`/orgs/${orgId}/members/${ownerId}`, { method: "PATCH", body: JSON.stringify({ role: "admin" }) })).status).toBe(409);
      expect((await call(`/orgs/${orgId}/members/${ownerId}`, { method: "DELETE" })).status).toBe(409);
      const add = await call(`/orgs/${orgId}/members`, { method: "POST", body: JSON.stringify({ email: "dispatcher@example.com", role: "dispatcher" }) });
      expect(add.status).toBe(201);
      const { user_id } = (await add.json()) as { user_id: string };
      expect((await call(`/orgs/${orgId}/members/${user_id}`, { method: "PATCH", body: JSON.stringify({ role: "admin" }) })).status).toBe(200);
      expect((await call(`/users/${user_id}`)).status).toBe(200);
      expect((await call(`/orgs/${orgId}/members/${user_id}`, { method: "DELETE" })).status).toBe(204);
      expect((await call(`/users/${user_id}`)).status).toBe(404);
    });

    it("updates the organization", async () => {
      const r = await call(`/orgs/${orgId}`, { method: "PATCH", body: JSON.stringify({ name: "Virtual Airline Two", metadata: { icao: "VAT" } }) });
      const o = (await r.json()) as { name: string; metadata: { icao: string } };
      expect(o.name).toBe("Virtual Airline Two");
      expect(o.metadata.icao).toBe("VAT");
    });
  });
});

describe("cleanup", () => {
  it("deletes expired and unneeded personal data, and keeps the rest", async () => {
    const env = makeEnv();
    const b = new Browser(env, "203.0.113.50");
    const ro = await op(b, "/orgs", { app: "demo", name: "Kept Team", slug: "kept", owner_email: "keep@example.com" });
    expect(ro.status).toBe(201);
    await signIn(b, "active@example.com");
    // An abandoned code for someone who never signed in.
    await new Browser(env, "203.0.113.51").json("/api/auth/email-otp/send-verification-otp", { email: "abandoned@example.com", type: "sign-in" });
    const db = (await createAuth(env).$context).adapter;
    const old = new Date(Date.now() - 40 * 24 * 3600 * 1000);
    await db.create({ model: "user", data: { email: "gone@example.com", name: "", emailVerified: false, createdAt: old, updatedAt: old } });

    // Nothing is due yet.
    const now = await cleanup(db as never);
    expect(now.unconfirmedAccounts).toBe(1);
    expect(now.sessions).toBe(0);
    const emails = async () => (await db.findMany<{ email: string }>({ model: "user", limit: 100 })).map((u) => u.email).sort();
    expect(await emails()).toEqual(["active@example.com", "keep@example.com"]);

    // 31 days on, sessions, codes, counters and the unconfirmed member's limbo are handled.
    const later = await cleanup(db as never, Date.now() + 31 * 24 * 3600 * 1000);
    expect(later.sessions).toBeGreaterThan(0);
    expect(later.verifications).toBeGreaterThan(0);
    expect(later.rateLimits).toBeGreaterThan(0);
    expect(later.emailLimits).toBeGreaterThan(0);
    expect(await db.count({ model: "session" })).toBe(0);
    expect(await db.count({ model: "verification" })).toBe(0);
    // A confirmed account and an unconfirmed one that is still in a team stay.
    expect(await emails()).toEqual(["active@example.com", "keep@example.com"]);
  });
});
