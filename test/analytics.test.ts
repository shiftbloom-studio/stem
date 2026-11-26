// Anonymous usage events (src/analytics.ts): sent only with POSTHOG_KEY, never with ids, addresses or codes.
import { afterEach, describe, expect, it, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import app from "../src/index";
import { EVENTS, signInEvent } from "../src/analytics";
import { legalPage } from "../src/ui/legal";
import type { Env } from "../src/env";

const ORIGIN = "https://stem.test";
const KEY = "phc_testtoken1234567890";
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
    ...extra,
  };
}

async function post(env: Env, path: string, body: unknown) {
  const res = await app.fetch(new Request(ORIGIN + path, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json", origin: ORIGIN, "cf-connecting-ip": "203.0.113.7" } }), env, ctx as never);
  await Promise.all(pending.splice(0));
  return res;
}

function capture() {
  const events: { event: string; properties: Record<string, unknown>; distinct_id: string }[] = [];
  const raw: string[] = [];
  const real = globalThis.fetch;
  vi.stubGlobal("fetch", vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    if (String(url).endsWith("/batch/")) {
      raw.push(String(init?.body));
      events.push(...JSON.parse(String(init?.body)).batch);
      return new Response("ok");
    }
    return real(url as never, init);
  }));
  return { events, raw };
}

afterEach(() => vi.unstubAllGlobals());

describe("usage events", () => {
  it("counts a code and a first sign-in without the address, code or user id", async () => {
    const { events, raw } = capture();
    const env = makeEnv({ POSTHOG_KEY: KEY });
    const email = "new.person@example.com";
    expect((await post(env, "/api/auth/email-otp/send-verification-otp", { email, type: "sign-in" })).status).toBe(200);
    const code = /(\d{6})/.exec(sent.filter((m) => m.to === email).at(-1)!.text)![1];
    expect((await post(env, "/api/auth/sign-in/email-otp", { email, otp: code === "000000" ? "111111" : "000000" })).status).not.toBe(200);
    const r = await post(env, "/api/auth/sign-in/email-otp", { email, otp: code });
    expect(r.status).toBe(200);
    const user = ((await r.json()) as { user: { id: string } }).user;

    expect(events.map((e) => e.event)).toEqual(["code_sent", "signed_in"]);
    expect(events[0].properties).toMatchObject({ type: "sign-in", $process_person_profile: false });
    expect(events[1].properties).toMatchObject({ method: "email_code", first_sign_in: true });
    expect(events[0].distinct_id).not.toBe(events[1].distinct_id);
    const all = raw.join("\n");
    for (const secret of [email, code, user.id, "203.0.113.7"]) expect(all).not.toContain(secret);
  });

  it("sends nothing without POSTHOG_KEY", async () => {
    const { events } = capture();
    const env = makeEnv();
    await post(env, "/api/auth/email-otp/send-verification-otp", { email: "x@example.com", type: "sign-in" });
    expect(events).toHaveLength(0);
  });

  it("names the app of a finished sign-in, not the person", () => {
    const basic = "Basic " + btoa("client_abc:secret");
    const ev = EVENTS["/oauth2/token"]({ path: "/oauth2/token", body: { grant_type: "authorization_code", code: "c0de" }, headers: new Headers({ authorization: basic }), context: {} });
    expect(ev).toEqual(["app_signed_in", { client: "client_abc" }]);
    expect(EVENTS["/oauth2/token"]({ path: "/oauth2/token", body: { grant_type: "refresh_token" }, context: {} })).toBeNull();
    expect(EVENTS["/email-otp/send-verification-otp"]({ path: "", body: { type: "<script>" }, context: {} })).toEqual(["code_sent", { type: null }]);
    expect(signInEvent({ path: "/passkey/verify-authentication", context: { newSession: { user: { createdAt: new Date(0) } } } })).toEqual(["signed_in", { method: "passkey", first_sign_in: false }]);
  });

  it("describes the statistics in the privacy policy only when on", () => {
    const l = { name: "T", street: "S 1", city: "1 Town", country: { en: "Germany", de: "Deutschland" }, email: "hi@example.com", authority: "A" } as never;
    expect(legalPage("privacy", l, { turnstile: false })).not.toContain("Usage statistics");
    const on = legalPage("privacy", l, { turnstile: false, analytics: true });
    expect(on).toContain("<h2>Usage statistics</h2>");
    expect(on).toContain("Data Privacy Framework");
    expect(on).not.toContain("no analysis of your behavior");
    expect(legalPage("datenschutz", l, { turnstile: false, analytics: true })).toContain("<h2>Nutzungsstatistik</h2>");
  });
});
