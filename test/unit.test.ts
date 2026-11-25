import { describe, it, expect } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { getMigrations } from "better-auth/db/migration";
import { safeNext, parseLegal, robotsTxt } from "../src/util";
import { parseFrom, sendMail, isLocal } from "../src/email";
import { roleNames, isRole } from "../src/roles";
import { createAuth } from "../src/auth";

describe("safeNext", () => {
  it("keeps same-origin paths", () => expect(safeNext("/invite/abc?x=1")).toBe("/invite/abc?x=1"));
  it.each(["https://evil.test", "//evil.test", "/\\evil.test", "javascript:alert(1)", "", null, "/a\nb"])("drops %s", (v) => expect(safeNext(v as string)).toBe("/account"));
});

describe("parseFrom", () => {
  it("splits name and address", () => expect(parseFrom("stem <login@example.com>")).toEqual({ name: "stem", email: "login@example.com" }));
  it("takes a bare address", () => expect(parseFrom("login@example.com")).toBe("login@example.com"));
});

describe("sendMail", () => {
  const mail = { to: "a@example.com", subject: "123456 is your stem code", text: "123456", html: "" };
  it("knows local development", () => {
    expect(isLocal({ STEM_URL: "http://localhost:8787" })).toBe(true);
    expect(isLocal({ STEM_URL: "https://stem.example.com" })).toBe(false);
  });
  it("never logs codes outside localhost", async () => {
    await expect(sendMail({ STEM_URL: "https://stem.example.com", DEV_LOG_EMAIL: "true" } as never, mail)).rejects.toThrow(/not configured/);
    await expect(sendMail({ STEM_URL: "http://localhost:8787" } as never, mail)).resolves.toBeUndefined();
  });
  it("ignores DEV_LOG_EMAIL in production", async () => {
    const out: unknown[] = [];
    const env = { STEM_URL: "https://stem.example.com", DEV_LOG_EMAIL: "true", EMAIL_FROM: "stem <login@example.com>", EMAIL: { send: async (m: unknown) => void out.push(m) } };
    await sendMail(env as never, mail);
    expect(out).toHaveLength(1);
  });
});

describe("roles", () => {
  it("adds valid app roles once", () => expect(roleNames("dispatcher, pilot,pilot,Owner,bad role")).toEqual(["owner", "admin", "member", "dispatcher", "pilot"]));
  it("checks roles", () => { expect(isRole("pilot", "pilot")).toBe(true); expect(isRole("captain", "pilot")).toBe(false); });
});

describe("legal", () => {
  it("needs the required fields", () => {
    expect(parseLegal('{"name":"x"}')).toBeNull();
    expect(parseLegal("not json")).toBeNull();
  });
  it("robots.txt blocks training bots", () => expect(robotsTxt()).toMatch(/User-agent: CCBot\nUser-agent: [\s\S]*Disallow: \//));
});

describe("schema", () => {
  it("migrations match the Better Auth config", async () => {
    const db = new DatabaseSync(":memory:");
    for (const f of readdirSync("migrations").filter((f) => f.endsWith(".sql")).sort()) db.exec(readFileSync(`migrations/${f}`, "utf8"));
    const auth = createAuth({ STEM_URL: "https://stem.example.com", BETTER_AUTH_SECRET: "s".repeat(40), DB: db } as never);
    const { toBeCreated, toBeAdded } = await getMigrations({ ...auth.options, database: db } as never);
    expect({ toBeCreated: toBeCreated.map((t) => t.table), toBeAdded: toBeAdded.map((t) => t.table) }).toEqual({ toBeCreated: [], toBeAdded: [] });
  });
});
