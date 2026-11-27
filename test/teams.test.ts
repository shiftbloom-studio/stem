// Teams: stem-wide teams, the primary team, and what each app sees of them.
import { describe, it, expect, beforeAll } from "vitest";
import { decodeJwt } from "jose";
import type { Env } from "../src/env";
import { ORIGIN, OPERATOR, makeEnv, Browser, op, signIn, login, type Client } from "./support";

const API = "https://demo.test/api";
const put = (b: Browser, path: string, body: unknown) =>
  b.fetch(`/api/v1/operator${path}`, { method: "PUT", body: JSON.stringify(body), headers: { authorization: `Bearer ${OPERATOR}`, "content-type": "application/json" } });

describe("teams", () => {
  let env: Env;
  let browser: Browser;
  let demo: Client;
  let sealed: Client;
  let studio: string;
  let demoTeam: string;
  let otherTeam: string;
  let dir: string;

  beforeAll(async () => {
    env = makeEnv({ SEALED_APPS: "leaf", PAIRWISE_SECRET: "p".repeat(40), RESOURCES: API });
    browser = new Browser(env);
    const reg = async (app: string, host: string, extra: Record<string, unknown> = {}) => {
      const r = await op(browser, "/clients", { app, name: app, redirect_uris: [`https://${host}/cb`], skip_consent: true, ...extra });
      expect(r.status, await r.clone().text()).toBe(201);
      return (await r.json()) as Client;
    };
    demo = await reg("demo", "demo.test", { resources: [API] });
    sealed = await reg("leaf", "leaf.test");
    const org = async (b: Record<string, unknown>) => {
      const r = await op(browser, "/orgs", b);
      expect(r.status, await r.clone().text()).toBe(201);
      return (await r.json()) as { id: string; app: string | null; stem_wide: boolean };
    };
    const s = await org({ stem_wide: true, name: "Studio", slug: "studio", owner_email: "person@example.com", owner_primary: true });
    expect(s).toMatchObject({ app: null, stem_wide: true });
    studio = s.id;
    demoTeam = (await org({ app: "demo", name: "Demo team", slug: "demo-team", owner_email: "person@example.com" })).id;
    otherTeam = (await org({ app: "other", name: "Other team", slug: "other-team", owner_email: "person@example.com" })).id;
    await signIn(browser, "person@example.com");
    const basic = "Basic " + btoa(`${demo.client_id}:${demo.client_secret}`);
    const tr = await browser.fetch("/api/auth/oauth2/token", {
      method: "POST",
      headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", scope: "directory", resource: `${ORIGIN}/api/v1` }),
    });
    dir = ((await tr.json()) as { access_token: string }).access_token;
  });

  it("needs an app or stem_wide, not both", async () => {
    expect((await op(browser, "/orgs", { name: "X", slug: "x1" })).status).toBe(400);
    expect((await op(browser, "/orgs", { stem_wide: true, app: "demo", name: "X", slug: "x2" })).status).toBe(400);
  });

  it("puts stem-wide teams and the primary team in a normal app's tokens", async () => {
    const { idToken, accessToken } = await login(browser, demo, "https://demo.test/cb", "openid orgs", API);
    expect(idToken.orgs).toEqual({ [studio]: "owner", [demoTeam]: "owner" });
    expect(idToken.primary_org).toBe(studio);
    const at = decodeJwt(accessToken);
    expect(at.orgs).toEqual({ [studio]: "owner", [demoTeam]: "owner" });
    expect(at.primary_org).toBe(studio);
    expect(Object.keys(at.orgs as object)[0]).toBe(studio);
  });

  it("keeps stem-wide teams out of sealed apps", async () => {
    const { idToken } = await login(browser, sealed, "https://leaf.test/cb", "openid orgs");
    expect(idToken.orgs).toEqual({});
    expect(idToken.primary_org).toBeUndefined();
  });

  it("lists the person's teams with the primary one first", async () => {
    const r = await browser.fetch("/api/auth/stem/teams");
    expect(r.status).toBe(200);
    const teams = (await r.json()) as { id: string; primary: boolean; stem_wide: boolean; role: string }[];
    expect(teams.map((t) => t.id)).toEqual([studio, demoTeam, otherTeam]);
    expect(teams.map((t) => t.primary)).toEqual([true, false, false]);
    expect(teams[0].stem_wide).toBe(true);
  });

  it("switches the primary team, and only to the person's own teams", async () => {
    expect((await browser.json("/api/auth/stem/teams/primary", { organization_id: demoTeam })).status).toBe(200);
    let t = await login(browser, demo, "https://demo.test/cb", "openid orgs");
    expect(t.idToken.primary_org).toBe(demoTeam);
    // A primary team the app can't see isn't named to it.
    expect((await browser.json("/api/auth/stem/teams/primary", { organization_id: otherTeam })).status).toBe(200);
    t = await login(browser, demo, "https://demo.test/cb", "openid orgs");
    expect(t.idToken.primary_org).toBeUndefined();
    const teams = (await (await browser.fetch("/api/auth/stem/teams")).json()) as { id: string; primary: boolean }[];
    expect(teams.filter((x) => x.primary).map((x) => x.id)).toEqual([otherTeam]);
    const stranger = (await op(browser, "/orgs", { app: "demo", name: "Not mine", slug: "not-mine" }).then((r) => r.json())) as { id: string };
    expect((await browser.json("/api/auth/stem/teams/primary", { organization_id: stranger.id })).status).toBe(404);
    expect((await browser.json("/api/auth/stem/teams/primary", { organization_id: 7 })).status).toBe(400);
    expect((await browser.json("/api/auth/stem/teams/primary", { organization_id: null })).status).toBe(200);
    const after = (await (await browser.fetch("/api/auth/stem/teams")).json()) as { primary: boolean }[];
    expect(after.some((x) => x.primary)).toBe(false);
    expect((await new Browser(env).json("/api/auth/stem/teams/primary", { organization_id: studio })).status).toBe(401);
  });

  it("lets the operator add people to a team and set their primary team", async () => {
    const r = await put(browser, `/orgs/${studio}/members`, { email: "new@example.com", role: "member", primary: true });
    expect(r.status).toBe(201);
    expect(await r.json()).toMatchObject({ organization_id: studio, role: "member", primary: true });
    const again = await put(browser, `/orgs/${studio}/members`, { email: "new@example.com", role: "admin" });
    expect(again.status).toBe(200);
    expect(await again.json()).toMatchObject({ role: "admin", primary: true });
    expect((await put(browser, `/orgs/${studio}/members`, { email: "new@example.com", role: "boss" })).status).toBe(400);
    expect((await put(browser, `/orgs/nope/members`, { email: "new@example.com", role: "member" })).status).toBe(404);
    // Moving the primary team clears the old one: never two per person.
    expect((await put(browser, `/orgs/${demoTeam}/members`, { email: "new@example.com", role: "member", primary: true })).status).toBe(201);
    const rows = (env.DB as unknown as { prepare(q: string): { all(): { organizationId: string }[] } }).prepare(`select m."organizationId" from "member" m join "user" u on u."id" = m."userId" where u."email" = 'new@example.com' and m."isPrimary" = 1`).all();
    expect(rows.map((x) => x.organizationId)).toEqual([demoTeam]);
  });

  it("shows stem-wide teams to the directory read-only", async () => {
    const auth = { authorization: `Bearer ${dir}`, "content-type": "application/json" };
    const list = (await (await browser.fetch("/api/v1/orgs", { headers: auth })).json()) as { data: { id: string }[] };
    expect(list.data.map((o) => o.id)).toEqual(expect.arrayContaining([demoTeam, studio]));
    expect(list.data.map((o) => o.id)).not.toContain(otherTeam);
    expect((await browser.fetch(`/api/v1/orgs/${studio}`, { headers: auth })).status).toBe(200);
    expect((await browser.fetch(`/api/v1/orgs/${studio}`, { method: "PATCH", body: JSON.stringify({ name: "Mine now" }), headers: auth })).status).toBe(404);
    expect((await browser.fetch(`/api/v1/orgs/${studio}/members`, { headers: auth })).status).toBe(404);
  });

  it("includes the primary flag in the data export", async () => {
    await browser.json("/api/auth/stem/teams/primary", { organization_id: studio });
    const data = (await (await browser.fetch("/api/auth/stem/export")).json()) as { teams: { organization: { id: string }; primary: boolean }[] };
    expect(data.teams.find((t) => t.organization.id === studio)?.primary).toBe(true);
  });
});
