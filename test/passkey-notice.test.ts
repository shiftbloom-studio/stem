// An email whenever a passkey is added (src/passkey-notice.ts), through a real registration:
// a P-256 software authenticator with "none" attestation, the bytes a browser would send.
import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import app from "../src/index";
import type { Env } from "../src/env";
import { passkeyAddedMail } from "../src/email";

const ORIGIN = "https://stem.test";
const sent: { to: string; subject: string; text: string; html: string }[] = [];
const pending: Promise<unknown>[] = [];
const ctx = { waitUntil: (p: Promise<unknown>) => void pending.push(p), passThroughOnException() {}, props: {} };

function makeEnv(extra: Partial<Env> = {}): Env {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  for (const f of readdirSync("migrations").filter((f) => f.endsWith(".sql")).sort()) db.exec(readFileSync(`migrations/${f}`, "utf8"));
  return {
    DB: db as unknown as D1Database,
    ASSETS: { fetch: async () => new Response("") } as unknown as Fetcher,
    EMAIL: { send: async (m: (typeof sent)[number]) => { sent.push(m); return { messageId: "m" }; } } as unknown as SendEmail,
    EMAIL_FROM: "stem <login@stem.test>",
    STEM_URL: ORIGIN,
    BETTER_AUTH_SECRET: randomBytes(32).toString("base64url"),
    ...extra,
  };
}

function browser(env: Env) {
  const cookies = new Map<string, string>();
  return async (path: string, body?: unknown) => {
    const headers: Record<string, string> = { origin: ORIGIN, "cf-connecting-ip": "203.0.113.9", "content-type": "application/json" };
    if (cookies.size) headers.cookie = [...cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    const res = await app.fetch(new Request(ORIGIN + path, { method: body ? "POST" : "GET", body: body ? JSON.stringify(body) : undefined, headers }), env, ctx as never);
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(";");
      const i = pair.indexOf("=");
      if (pair.slice(i + 1)) cookies.set(pair.slice(0, i), pair.slice(i + 1)); else cookies.delete(pair.slice(0, i));
    }
    await Promise.all(pending.splice(0));
    return res;
  };
}

// Just enough CBOR for an attestation object: maps, text, bytes and small integers.
function cbor(v: unknown): Buffer {
  const head = (major: number, n: number) => {
    if (n < 24) return Buffer.from([(major << 5) | n]);
    if (n < 256) return Buffer.from([(major << 5) | 24, n]);
    return Buffer.from([(major << 5) | 25, n >> 8, n & 255]);
  };
  if (typeof v === "number") return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === "string") { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (v instanceof Uint8Array) { const b = Buffer.from(v); return Buffer.concat([head(2, b.length), b]); }
  if (v instanceof Map) return Buffer.concat([head(5, v.size), ...[...v].flatMap(([k, x]) => [cbor(k), cbor(x)])]);
  throw new Error("cbor: unsupported");
}

async function addPasskey(f: ReturnType<typeof browser>, name: string) {
  const opts = (await (await f("/api/auth/passkey/generate-register-options")).json()) as { challenge: string; rp: { id: string } };
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const cose = cbor(new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]]));
  const credId = randomBytes(16);
  const authData = Buffer.concat([
    createHash("sha256").update(opts.rp.id).digest(),
    Buffer.from([0x45]), // user present, user verified, attested credential data
    Buffer.alloc(4),
    Buffer.alloc(16),
    Buffer.from([0, credId.length]),
    credId,
    cose,
  ]);
  const attestationObject = cbor(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
  const clientDataJSON = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: opts.challenge, origin: ORIGIN, crossOrigin: false }));
  const id = credId.toString("base64url");
  return f("/api/auth/passkey/verify-registration", {
    name,
    response: { id, rawId: id, type: "public-key", clientExtensionResults: {}, authenticatorAttachment: "platform", response: { clientDataJSON: clientDataJSON.toString("base64url"), attestationObject: attestationObject.toString("base64url"), transports: ["internal"] } },
  });
}

async function signIn(env: Env, email: string) {
  const f = browser(env);
  await f("/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" });
  const code = /(\d{6})/.exec(sent.filter((m) => m.to === email).at(-1)!.text)![1];
  expect((await f("/api/auth/sign-in/email-otp", { email, otp: code })).status).toBe(200);
  return f;
}

/** Moves the account's creation back, out of the grace period for new accounts. */
const age = (env: Env, email: string) =>
  (env.DB as unknown as DatabaseSync).prepare(`update "user" set "createdAt" = ? where "email" = ?`).run(new Date(Date.now() - 3600_000).toISOString(), email);

const notices = (to: string) => sent.filter((m) => m.to === to && m.subject.startsWith("A passkey was added"));

describe("passkey notice", () => {
  it("emails the person when a passkey is added", async () => {
    const env = makeEnv({ NOTIFY_NEW_PASSKEY: "true" });
    const f = await signIn(env, "notice@example.com");
    age(env, "notice@example.com");
    const r = await addPasskey(f, "Mac <b>, added 26 Nov 2026");
    expect(r.status, await r.clone().text()).toBe(200);
    const [mail] = notices("notice@example.com");
    expect(mail).toBeTruthy();
    expect(mail.text).toContain('"Mac <b>, added 26 Nov 2026" was added to your stem account');
    expect(mail.text).toContain(`${ORIGIN}/account`);
    expect(mail.html).toContain("Mac &lt;b&gt;, added 26 Nov 2026");
    expect(mail.html).not.toContain("you can ignore it");
  });

  it("stays quiet right after sign-up", async () => {
    const env = makeEnv({ NOTIFY_NEW_PASSKEY: "true" });
    const f = await signIn(env, "fresh@example.com");
    expect((await addPasskey(f, "Phone")).status).toBe(200);
    expect(notices("fresh@example.com")).toHaveLength(0);
    // A second passkey inside the window is not the sign-up any more.
    expect((await addPasskey(f, "Laptop")).status).toBe(200);
    expect(notices("fresh@example.com")).toHaveLength(1);
  });

  it("is off by default", async () => {
    const env = makeEnv();
    const f = await signIn(env, "quiet@example.com");
    age(env, "quiet@example.com");
    expect((await addPasskey(f, "Laptop")).status).toBe(200);
    expect(notices("quiet@example.com")).toHaveLength(0);
  });

  it("sends nothing for a registration that fails", async () => {
    const env = makeEnv({ NOTIFY_NEW_PASSKEY: "true" });
    const f = await signIn(env, "failed@example.com");
    age(env, "failed@example.com");
    const r = await f("/api/auth/passkey/verify-registration", { response: { id: "x", rawId: "x", type: "public-key", clientExtensionResults: {}, response: { clientDataJSON: "e30", attestationObject: "oA" } } });
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(notices("failed@example.com")).toHaveLength(0);
  });

  it("mentions the notice in the privacy policy only when it's on", async () => {
    const legal = JSON.stringify({ name: "Op", street: "S 1", city: "1 T", country: { en: "Germany", de: "Deutschland" }, email: "hi@example.com", authority: "A" });
    const on = await (await browser(makeEnv({ LEGAL: legal, NOTIFY_NEW_PASSKEY: "true" }))("/privacy")).text();
    expect(on).toContain("When a passkey is added to your account, we email you");
    const off = await (await browser(makeEnv({ LEGAL: legal }))("/datenschutz")).text();
    expect(off).not.toContain("Passkey hinzugefügt");
  });

  it("names synced passkeys and works without a name", () => {
    const m = passkeyAddedMail("a@example.com", { name: null, synced: true, at: new Date("2026-11-26T12:00:00Z"), account: `${ORIGIN}/account` });
    expect(m.text).toMatch(/^A passkey, synced through a password manager, was added/);
    expect(m.text).toContain("26 November 2026");
  });
});
