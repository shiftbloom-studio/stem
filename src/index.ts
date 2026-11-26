// SPDX-License-Identifier: AGPL-3.0-or-later
// stem: passwordless sign-in, organizations and OpenID Connect for shiftbloom studio apps.
import { Hono } from "hono";
import { oauthProviderOpenIdConfigMetadata, oauthProviderAuthServerMetadata } from "@better-auth/oauth-provider";
import type { Env } from "./env";
import { createAuth, type Exec } from "./auth";
import { apiRoutes } from "./api";
import { handleFonts } from "./assets";
import { faviconSvg } from "./bloom";
import { robotsTxt, parseLegal, safeNext } from "./util";
import { landingPage, signInPage, accountPage, consentPage, invitePage, messagePage, type Ui, type StepUp } from "./ui/pages";
import { wantsStepUp } from "./strength";
import { legalPage, LEGAL_PATHS } from "./ui/legal";
import { cleanup } from "./cleanup";
import { createGateway } from "./gateway";
import { Mandate } from "./mandates/object";
import { MandateGatewayBase, authorize } from "./mandates/authorize";
import { approvePage, answeredPage } from "./mandates/page";
import { mandateApps, mandatesEnabled, type RequestRow, type RequestTerms } from "./mandates/plugin";
import { passRoutes, directory, passOrigins, DIRECTORY_PATH } from "./passes/routes";
import { cleanupPasses } from "./passes/issuer";

const TURNSTILE = "https://challenges.cloudflare.com";
const CSP = [
  "default-src 'none'",
  `script-src 'self' ${TURNSTILE}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  `frame-src ${TURNSTILE}`,
  "form-action 'self'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

/** Paths that count toward the per-IP sign-in limit, on top of Better Auth's own per-endpoint limits. */
const SIGN_IN_PATHS = /^\/api\/auth\/(email-otp\/|sign-in\/|passkey\/(generate-authenticate|verify-authentication))/;

type App = { Bindings: Env };
const app = new Hono<App>();

const ui = (env: Env): Ui => ({
  legal: !!parseLegal(env.LEGAL),
  turnstileSiteKey: env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET ? env.TURNSTILE_SITE_KEY : null,
  origin: new URL(env.STEM_URL).origin,
  mandates: mandatesEnabled(env),
});

const html = (body: string, status = 200, cache = "no-store") =>
  new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": cache } });

// Security headers on everything.
app.use("*", async (c, next) => {
  await next();
  // Responses from fetch, the cache or the assets binding have immutable headers.
  c.res = new Response(c.res.body, c.res);
  const h = c.res.headers;
  h.set("strict-transport-security", "max-age=63072000; includeSubDomains; preload");
  h.set("x-content-type-options", "nosniff");
  h.set("x-frame-options", "DENY");
  h.set("referrer-policy", "strict-origin-when-cross-origin");
  h.set("cross-origin-opener-policy", "same-origin");
  h.set("permissions-policy", "publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(), microphone=(), geolocation=()");
  if ((h.get("content-type") || "").startsWith("text/html")) h.set("content-security-policy", CSP);
  const p = new URL(c.req.url).pathname;
  if (!(p === "/" || p === "/robots.txt" || p === "/favicon.svg" || p.startsWith("/assets/") || LEGAL_PATHS[p])) h.set("x-robots-tag", "noindex, nofollow");
});

app.get("/robots.txt", () => new Response(robotsTxt(), { headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=3600" } }));
app.get("/favicon.svg", () => new Response(faviconSvg(), { headers: { "content-type": "image/svg+xml", "cache-control": "public, max-age=604800" } }));
app.get("/favicon.ico", () => new Response(faviconSvg(), { headers: { "content-type": "image/svg+xml", "cache-control": "public, max-age=604800" } }));
app.get("/health", (c) => c.json({ ok: true }));
app.get("/assets/app.js", (c) => c.env.ASSETS.fetch(c.req.raw));
app.get("/assets/*", async (c) => (await handleFonts(c.req.raw, c.executionCtx as never)) || c.notFound());

// OpenID Connect discovery lives at the issuer root.
app.get("/.well-known/openid-configuration", (c) => oauthProviderOpenIdConfigMetadata(createAuth(c.env, c.executionCtx as never))(c.req.raw));
app.get("/.well-known/oauth-authorization-server", (c) => oauthProviderAuthServerMetadata(createAuth(c.env, c.executionCtx as never))(c.req.raw));

app.on(["GET", "POST"], "/api/auth/*", async (c) => {
  const path = new URL(c.req.url).pathname;
  if (c.req.method === "POST" && SIGN_IN_PATHS.test(path) && c.env.AUTH_RL) {
    const { success } = await c.env.AUTH_RL.limit({ key: c.req.header("cf-connecting-ip") || "unknown" });
    if (!success) return c.json({ code: "RATE_LIMITED", message: "Too many attempts. Wait a minute, then try again." }, 429);
  }
  const res = await createAuth(c.env, c.executionCtx as never).handler(c.req.raw);
  if (!res.headers.has("cache-control")) {
    const r = new Response(res.body, res);
    r.headers.set("cache-control", "no-store");
    return r;
  }
  return res;
});

app.route("/api/v1", apiRoutes());

// Passes (src/passes): the issuer directory for apps, and issuing for browsers on app pages.
app.get(DIRECTORY_PATH, (c) => directory(c.env));
app.route("/api/passes", passRoutes());
/** Back to the app page that sent someone to sign in for passes. Only origins in PASS_ORIGINS. */
app.get("/passes/back", (c) => {
  const to = c.req.query("to") || "";
  try {
    const u = new URL(to);
    if (u.origin !== new URL(c.env.STEM_URL).origin && passOrigins(c.env).has(u.origin)) return c.redirect(u.toString(), 302);
  } catch {}
  return c.redirect("/account", 302);
});

for (const [path, kind] of Object.entries(LEGAL_PATHS)) {
  app.get(path, (c) => {
    const legal = parseLegal(c.env.LEGAL);
    if (!legal) return html(messagePage(ui(c.env), "Not here", "This page doesn't exist."), 404);
    return html(legalPage(kind, legal, { turnstile: !!ui(c.env).turnstileSiteKey }), 200, "public, max-age=3600");
  });
}

app.get("/", (c) => html(landingPage(ui(c.env)), 200, "public, max-age=300"));

async function session(env: Env, req: Request, exec: Exec) {
  try {
    return await createAuth(env, exec).api.getSession({ headers: req.headers });
  } catch {
    return null;
  }
}

app.get("/sign-in", async (c) => {
  const url = new URL(c.req.url);
  const oauth = url.searchParams.has("client_id") && url.searchParams.has("sig");
  if (!oauth && (await session(c.env, c.req.raw, c.executionCtx as never))) return c.redirect(safeNext(url.searchParams.get("next")), 302);
  let clientName: string | null = null;
  const clientId = url.searchParams.get("client_id");
  if (clientId) {
    const ctx = await createAuth(c.env, c.executionCtx as never).$context;
    const client = await ctx.adapter.findOne<{ name?: string }>({ model: "oauthClient", where: [{ field: "clientId", value: clientId }] });
    clientName = client?.name || null;
  }
  // The app asked the person to sign in again (prompt=login, max_age or a passkey acr_values).
  // If they're signed in here and have a passkey, offer it first. The email code stays as fallback.
  let stepUp: StepUp | null = null;
  if (oauth && wantsStepUp(url.searchParams)) {
    const s = await session(c.env, c.req.raw, c.executionCtx as never);
    if (s) {
      const ctx = await createAuth(c.env, c.executionCtx as never).$context;
      const pk = await ctx.adapter.findOne<{ id: string }>({ model: "passkey", where: [{ field: "userId", value: s.user.id }] });
      if (pk) stepUp = { email: s.user.email };
    }
  }
  const res = html(signInPage(ui(c.env), clientName, stepUp));
  res.headers.set("referrer-policy", "no-referrer");
  return res;
});

app.get("/account", async (c) => {
  if (!(await session(c.env, c.req.raw, c.executionCtx as never))) return c.redirect("/sign-in?next=%2Faccount", 302);
  return html(accountPage(ui(c.env)));
});

app.get("/consent", async (c) => {
  const url = new URL(c.req.url);
  if (!(await session(c.env, c.req.raw, c.executionCtx as never))) return c.redirect("/sign-in", 302);
  const clientId = url.searchParams.get("client_id");
  const ctx = await createAuth(c.env, c.executionCtx as never).$context;
  const client = clientId ? await ctx.adapter.findOne<{ name?: string; uri?: string | null; disabled?: boolean }>({ model: "oauthClient", where: [{ field: "clientId", value: clientId }] }) : null;
  if (!client || client.disabled) return html(messagePage(ui(c.env), "Unknown app", "We don't know the app that sent you here.", "error"), 400);
  let uri: string | null = null;
  try { if (client.uri && /^https:\/\//.test(client.uri)) uri = new URL(client.uri).toString(); } catch {}
  const scopes = (url.searchParams.get("scope") || "").split(" ").filter(Boolean);
  const res = html(consentPage(ui(c.env), { name: client.name || "An app", uri }, scopes));
  res.headers.set("referrer-policy", "no-referrer");
  return res;
});

app.get("/invite/:id", async (c) => {
  const id = c.req.param("id");
  const ctx = await createAuth(c.env, c.executionCtx as never).$context;
  const inv = /^[0-9a-f-]{36}$/i.test(id)
    ? await ctx.adapter.findOne<{ id: string; organizationId: string; email: string; status: string; expiresAt: Date; inviterId: string }>({ model: "invitation", where: [{ field: "id", value: id }] })
    : null;
  const live = inv && inv.status === "pending" && new Date(inv.expiresAt).getTime() > Date.now();
  if (!inv || !live) return html(invitePage(ui(c.env), null), 404);
  const [org, inviter] = await Promise.all([
    ctx.adapter.findOne<{ name: string }>({ model: "organization", where: [{ field: "id", value: inv.organizationId }] }),
    ctx.adapter.findOne<{ name: string }>({ model: "user", where: [{ field: "id", value: inv.inviterId }] }),
  ]);
  if (!org) return html(invitePage(ui(c.env), null), 404);
  const res = html(invitePage(ui(c.env), { id: inv.id, orgName: org.name, email: inv.email, inviter: inviter?.name || null }));
  res.headers.set("referrer-policy", "no-referrer");
  return res;
});

/** Where to go after accepting an invitation: the app's redirect, checked when the invitation was created. */
app.get("/invite/:id/continue", async (c) => {
  const ctx = await createAuth(c.env, c.executionCtx as never).$context;
  const s = await session(c.env, c.req.raw, c.executionCtx as never);
  if (!s) return c.redirect("/sign-in", 302);
  const inv = await ctx.adapter.findOne<{ email: string; status: string; redirectTo?: string | null }>({ model: "invitation", where: [{ field: "id", value: c.req.param("id") }] });
  if (inv && inv.status === "accepted" && inv.email.toLowerCase() === s.user.email.toLowerCase() && inv.redirectTo) return c.redirect(inv.redirectTo, 302);
  return c.redirect("/account", 302);
});

// ---------- mandates (docs/mandates.md) ----------

app.get("/mandates/approve", async (c) => {
  const url = new URL(c.req.url);
  if (!mandatesEnabled(c.env)) return html(messagePage(ui(c.env), "Not here", "This page doesn't exist."), 404);
  const s = await session(c.env, c.req.raw, c.executionCtx as never);
  if (!s) return c.redirect(`/sign-in?next=${encodeURIComponent(url.pathname + url.search)}`, 302);
  const ctx = await createAuth(c.env, c.executionCtx as never).$context;
  const id = url.searchParams.get("request") || "";
  const row = /^[0-9a-f-]{36}$/i.test(id) ? await ctx.adapter.findOne<RequestRow>({ model: "mandateRequest", where: [{ field: "id", value: id }] }) : null;
  const open = row && row.status === "pending" && new Date(row.expiresAt).getTime() > Date.now() && (!row.userId || row.userId === s.user.id);
  const pk = await ctx.adapter.findOne<{ id: string }>({ model: "passkey", where: [{ field: "userId", value: s.user.id }] });
  const res = html(approvePage(ui(c.env), open ? { id: row.id, userCode: row.userCode, terms: JSON.parse(row.terms) as RequestTerms, expiresAt: row.expiresAt } : null, mandateApps(c.env), !!pk), open ? 200 : 404);
  res.headers.set("referrer-policy", "no-referrer");
  return res;
});

app.get("/mandates/done", (c) => html(answeredPage(ui(c.env))));

/** For apps that can't reach stem through a service binding. Same answer as MandateGateway.authorize. */
app.post("/api/mandates/authorize", async (c) => {
  if (c.env.API_RL) {
    const { success } = await c.env.API_RL.limit({ key: c.req.header("cf-connecting-ip") || "unknown" });
    if (!success) return c.json({ allowed: false, reason: "rate_limited", message: "Too many requests." }, 429);
  }
  const body = await c.req.json().catch(() => null);
  const r = await authorize(c.env, body);
  return c.json(r, r.allowed ? 200 : r.reason === "invalid_request" ? 400 : 403);
});

app.notFound((c) => html(messagePage(ui(c.env), "Not here", "This page doesn't exist. Maybe the link is old or has a typo."), 404));
app.onError((e, c) => {
  console.error("[stem] unhandled", e);
  return c.req.path.startsWith("/api/") ? c.json({ error: "server_error" }, 500) : html(messagePage(ui(c.env), "Something broke", "That's on us. Try again in a moment.", "error"), 500);
});

/** Daily: delete expired sessions, codes, counters, tokens and invitations (see src/cleanup.ts). */
async function scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
  ctx.waitUntil(
    (async () => {
      const db = (await createAuth(env, ctx).$context).adapter;
      console.log("[stem] cleanup", JSON.stringify({ ...(await cleanup(db as never)), ...(await cleanupPasses(env)) }));
    })().catch((e) => console.error("[stem] cleanup failed", e)),
  );
}

export default { fetch: app.fetch, scheduled } satisfies ExportedHandler<Env>;

/** Named entrypoint for app Workers on the same account (service binding with entrypoint "AppGateway"). */
export class AppGateway extends createGateway(app.fetch) {}

/** Mandates: the Durable Object class (binding MANDATE) and the entrypoint apps bind to (entrypoint "MandateGateway"). */
export { Mandate };
export class MandateGateway extends MandateGatewayBase {}
