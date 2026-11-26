// Sealed apps (docs/sealed-apps.md): pairwise sub, no email, no directory access to people, coarse sessions.
import { describe, it, expect, beforeAll } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { decodeJwt } from "jose";
import app, { AppGateway } from "../src/index";
import type { Env } from "../src/env";
import { coarseIp, coarseUserAgent, sealedApps } from "../src/sealed";

const ORIGIN = "https://stem.test";
const OPERATOR = "op_" + "x".repeat(40);
const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36";

const sent: { to: string; text: string }[] = [];
const pending: Promise<unknown>[] = [];
const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {}, props: {} };

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
    OPERATOR_TOKEN: OPERATOR,
    RESOURCES: "https://shared.test/api",
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

const op = (b: Browser, path: string, body?: unknown) =>
  b.fetch(`/api/v1/operator${path}`, { method: body ? "POST" : "GET", body: body ? JSON.stringify(body) : undefined, headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" } });

async function signIn(b: Browser, email: string) {
  expect((await b.json("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" })).status).toBe(200);
  const code = /(\d{6})/.exec(sent.filter((m) => m.to === email).at(-1)!.text)![1];
  const r = await b.json("/api/auth/sign-in/email-otp", { email, otp: code });
  expect(r.status).toBe(200);
  return ((await r.json()) as { user: { id: string } }).user;
}

type Client = { client_id: string; client_secret: string; subject_type?: string; scope?: string };

/** Code flow without a resource: opaque access token, ID token, then userinfo. */
async function login(b: Browser, client: Client, callback: string, scope: string, resource?: string) {
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

describe("sealed apps", () => {
  let env: Env;
  let browser: Browser;
  let drop: Client;
  let leaf: Client;
  let shared: Client;
  let userId: string;

  beforeAll(async () => {
    env = makeEnv({ SEALED_APPS: "drop, leaf", PAIRWISE_SECRET: "p".repeat(40) });
    browser = new Browser(env);
    const reg = async (app: string, host: string, extra: Record<string, unknown> = {}) => {
      const r = await op(browser, "/clients", { app, name: app, redirect_uris: [`https://${host}/cb`], skip_consent: true, ...extra });
      expect(r.status, await r.clone().text()).toBe(201);
      return (await r.json()) as Client;
    };
    drop = await reg("drop", "drop.test");
    leaf = await reg("leaf", "leaf.test");
    shared = await reg("va", "va.test");
    userId = (await signIn(browser, "person@example.com")).id;
  });

  it("is off without both settings", () => {
    expect(sealedApps({ SEALED_APPS: "drop" }).size).toBe(0);
    expect(sealedApps({ SEALED_APPS: "drop", PAIRWISE_SECRET: "short" }).size).toBe(0);
    expect(sealedApps({ PAIRWISE_SECRET: "p".repeat(40) }).size).toBe(0);
    expect([...sealedApps({ SEALED_APPS: "drop, leaf,", PAIRWISE_SECRET: "p".repeat(40) })]).toEqual(["drop", "leaf"]);
  });

  it("registers sealed clients as pairwise, without the email scope", () => {
    expect(drop.subject_type).toBe("pairwise");
    expect(drop.scope?.split(" ")).not.toContain("email");
    expect(shared.subject_type ?? "public").toBe("public");
    expect(shared.scope?.split(" ")).toContain("email");
  });

  it("refuses signed access tokens for sealed apps", async () => {
    const r = await op(browser, "/clients", { app: "drop", name: "drop 2", redirect_uris: ["https://drop.test/cb2"], resources: ["https://shared.test/api"] });
    expect(r.status).toBe(400);
  });

  it("gives each sealed app its own id and no address", async () => {
    const a = await login(browser, drop, "https://drop.test/cb", "openid profile offline_access");
    const b = await login(browser, leaf, "https://leaf.test/cb", "openid profile offline_access");
    const c = await login(browser, shared, "https://va.test/cb", "openid profile email");
    expect(c.idToken.sub).toBe(userId);
    expect(c.userinfo.email).toBe("person@example.com");
    for (const x of [a, b]) {
      expect(x.idToken.sub).not.toBe(userId);
      expect(x.userinfo.sub).toBe(x.idToken.sub);
      expect(x.userinfo.email).toBeUndefined();
      expect(JSON.stringify(x.idToken)).not.toContain("person@example.com");
      // Opaque, so it can't carry stem's shared id.
      expect(x.accessToken.split(".").length).not.toBe(3);
    }
    expect(a.idToken.sub).not.toBe(b.idToken.sub);
    // Stable across sign-ins.
    const again = await login(browser, drop, "https://drop.test/cb", "openid");
    expect(again.idToken.sub).toBe(a.idToken.sub);
  });

  it("refuses a resource from a sealed client, the userinfo endpoint too", async () => {
    // Better Auth signs a JWT access token for any resource, and its sub is stem's shared user id.
    await expect(login(browser, drop, "https://drop.test/cb", "openid", `${ORIGIN}/api/auth/oauth2/userinfo`)).rejects.toThrow(/invalid_target/);
    // A shared client still gets one.
    const c = await login(browser, shared, "https://va.test/cb", "openid", `${ORIGIN}/api/auth/oauth2/userinfo`);
    expect(decodeJwt(c.accessToken).sub).toBe(userId);
    // At the token endpoint too, with the client in the body or in Basic auth.
    for (const auth of ["basic", "body"]) {
      const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
      const form = new URLSearchParams({ grant_type: "refresh_token", refresh_token: "x", resource: `${ORIGIN}/api/auth/oauth2/userinfo` });
      if (auth === "basic") headers.authorization = "Basic " + btoa(`${drop.client_id}:${drop.client_secret}`);
      else { form.set("client_id", drop.client_id); form.set("client_secret", drop.client_secret); }
      const r = await browser.fetch("/api/auth/oauth2/token", { method: "POST", headers, body: form });
      expect(r.status).toBe(400);
      expect(await r.text()).toContain("invalid_target");
    }
  });

  it("won't grant the email scope to a sealed app", async () => {
    await expect(login(browser, drop, "https://drop.test/cb", "openid email")).rejects.toThrow(/invalid_scope/);
  });

  it("keeps people out of a sealed app's directory, through the gateway too", async () => {
    const gw = new AppGateway({ ...ctx, props: { app: "drop" } } as never, env);
    const g = gw as unknown as { listOrgs(): Promise<unknown>; listMembers(id: string): Promise<unknown>; getUser(id: string): Promise<unknown> };
    await expect(g.listOrgs()).resolves.toBeTruthy();
    await expect(g.listMembers("any")).rejects.toThrow(/sealed_app/);
    await expect(g.getUser(userId)).rejects.toThrow(/sealed_app/);
    const va = new AppGateway({ ...ctx, props: { app: "va" } } as never, env) as unknown as typeof g;
    await expect(va.listMembers("missing")).rejects.toThrow(/not_found/);
  });

  it("stores sessions with network and browser only", async () => {
    const r = await browser.fetch("/api/auth/stem/sessions");
    const rows = (await r.json()) as { ipAddress: string | null; userAgent: string | null }[];
    expect(rows.length).toBeGreaterThan(0);
    for (const s of rows) {
      expect(s.ipAddress).toBe("203.0.113.0/24");
      expect(s.userAgent).toBe("Chrome on macOS");
    }
  });
  it("says so in the privacy policy", async () => {
    const legal = JSON.stringify({ name: "Op", street: "S 1", city: "1 T", country: { en: "Germany", de: "Deutschland" }, email: "hi@example.com", authority: "A" });
    const on = await (await new Browser({ ...env, LEGAL: legal }).fetch("/privacy")).text();
    expect(on).toContain("the network of your IP address");
    expect(on).toContain("Some of our apps are sealed");
    const off = await (await new Browser({ ...env, LEGAL: legal, SEALED_APPS: undefined }).fetch("/datenschutz")).text();
    expect(off).toContain("deiner IP-Adresse und dem User-Agent");
    expect(off).not.toContain("versiegelt");
  });

  it("changes nothing when off: public sub, email scope, full session data", async () => {
    // Same database (resources are seeded once per process), without the settings.
    const off = { ...env, SEALED_APPS: undefined, PAIRWISE_SECRET: undefined };
    const b = new Browser(off, "198.51.100.23");
    const r = await op(b, "/clients", { app: "drop", name: "drop", redirect_uris: ["https://drop2.test/cb"], skip_consent: true });
    expect(r.status).toBe(201);
    const client = (await r.json()) as Client;
    expect(client.subject_type ?? "public").toBe("public");
    expect(client.scope?.split(" ")).toContain("email");
    const id = (await signIn(b, "plain@example.com")).id;
    const x = await login(b, client, "https://drop2.test/cb", "openid email");
    expect(x.idToken.sub).toBe(id);
    expect(x.userinfo.email).toBe("plain@example.com");
    const rows = (await (await b.fetch("/api/auth/stem/sessions")).json()) as { ipAddress: string; userAgent: string }[];
    expect(rows[0].ipAddress).toBe("198.51.100.23");
    expect(rows[0].userAgent).toBe(UA);
  });
});

describe("coarse session data", () => {
  it("keeps the network of an address", () => {
    expect(coarseIp("203.0.113.77")).toBe("203.0.113.0/24");
    expect(coarseIp("2001:db8:85a3::8a2e:370:7334")).toBe("2001:db8:85a3::/48");
    expect(coarseIp("2001:0db8::1")).toBe("2001:db8:0::/48");
    expect(coarseIp("::1")).toBe("0:0:0::/48");
    expect(coarseIp("not an ip")).toBeNull();
    expect(coarseIp(null)).toBeNull();
  });
  it("keeps browser and system of a user agent", () => {
    expect(coarseUserAgent(UA)).toBe("Chrome on macOS");
    expect(coarseUserAgent("Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0")).toBe("Firefox on Windows");
    expect(coarseUserAgent("curl/8.0")).toBe("Browser");
    expect(coarseUserAgent(undefined)).toBeNull();
  });
});
