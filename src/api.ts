// SPDX-License-Identifier: AGPL-3.0-or-later
// Two server-to-server APIs:
// - /api/v1/operator/*: the person running stem sets up apps, OAuth clients and organizations (OPERATOR_TOKEN).
// - /api/v1/*: an app manages its own organizations, members and invitations with a client-credentials
//   access token (scope "directory"). An app only ever sees organizations whose `app` matches its client.
import { Hono, type Context } from "hono";
import { jwtVerify, createLocalJWKSet, type JSONWebKeySet } from "jose";
import type { Env } from "./env";
import { createAuth, directoryAudience, resourceList, SCOPES, DIRECTORY_SCOPE, OPERATOR_HEADER, type Auth } from "./auth";
import { isRole, roleNames } from "./roles";
import { inviteMail, sendMail } from "./email";
import { timingSafeEqual } from "./util";

type Vars = { auth: Auth; app: string; clientId: string };
type C = Context<{ Bindings: Env; Variables: Vars }>;

const APP_ID = /^[a-z][a-z0-9-]{1,39}$/;
const SLUG = /^[a-z0-9][a-z0-9-]{0,62}$/;
const EMAIL = /^[^\s@<>]{1,64}@[^\s@<>]{1,190}\.[^\s@<>]{2,}$/;
const DAY_MS = 24 * 3600 * 1000;

const err = (c: C, status: 400 | 401 | 403 | 404 | 409 | 422 | 429, error: string, detail?: string) =>
  c.json({ error, ...(detail ? { detail } : {}) }, status);

const asJson = (v: unknown): Record<string, unknown> => {
  if (!v) return {};
  if (typeof v === "string") { try { return JSON.parse(v); } catch { return {}; } }
  return typeof v === "object" ? (v as Record<string, unknown>) : {};
};
const iso = (d: unknown) => (d instanceof Date ? d.toISOString() : d ? new Date(d as string).toISOString() : null);

async function body<T>(c: C): Promise<T | null> {
  if (Number(c.req.header("content-length") || 0) > 32768) return null;
  try { return (await c.req.json()) as T; } catch { return null; }
}

type Org = { id: string; name: string; slug: string; logo?: string | null; metadata?: unknown; app?: string | null; createdAt: Date };
type Member = { id: string; organizationId: string; userId: string; role: string; createdAt: Date };
type Invitation = { id: string; organizationId: string; email: string; role: string | null; status: string; expiresAt: Date; createdAt: Date; inviterId: string; redirectTo?: string | null };
type User = { id: string; email: string; name: string; emailVerified: boolean; createdAt: Date };

const orgOut = (o: Org) => ({ id: o.id, name: o.name, slug: o.slug, logo: o.logo || null, metadata: asJson(o.metadata), app: o.app || null, created_at: iso(o.createdAt) });
const invOut = (i: Invitation) => ({ id: i.id, organization_id: i.organizationId, email: i.email, role: i.role, status: i.status, expires_at: iso(i.expiresAt), created_at: iso(i.createdAt), inviter_id: i.inviterId, redirect_to: i.redirectTo || null });
const userOut = (u: User) => ({ id: u.id, email: u.email, name: u.name || null, email_verified: !!u.emailVerified });

const adapter = async (c: C) => (await c.get("auth").$context).adapter;
const internal = async (c: C) => (await c.get("auth").$context).internalAdapter;

async function findOrCreateUser(c: C, email: string, name = ""): Promise<User> {
  const ia = await internal(c);
  const found = await ia.findUserByEmail(email.toLowerCase());
  if (found) return found.user as User;
  return (await ia.createUser({ email: email.toLowerCase(), name, emailVerified: false }, { method: "admin" })) as unknown as User;
}

async function appOrg(c: C, id: string): Promise<Org | null> {
  const org = await (await adapter(c)).findOne<Org>({ model: "organization", where: [{ field: "id", value: id }] });
  return org && org.app === c.get("app") ? org : null;
}

/** Redirects after accepting an invitation must go back to the app: same origin as one of its clients' redirect URIs. */
async function appOrigins(c: C): Promise<Set<string>> {
  const clients = await (await adapter(c)).findMany<{ redirectUris: string[] | string; metadata: unknown }>({ model: "oauthClient", limit: 100 });
  const out = new Set<string>();
  for (const cl of clients) {
    if (asJson(cl.metadata).app !== c.get("app")) continue;
    const uris = Array.isArray(cl.redirectUris) ? cl.redirectUris : String(cl.redirectUris || "").split(/[\s,]+/);
    for (const u of uris) { try { out.add(new URL(u).origin); } catch {} }
  }
  return out;
}

export function apiRoutes() {
  const api = new Hono<{ Bindings: Env; Variables: Vars }>();

  api.use("*", async (c, next) => {
    if (c.env.API_RL && !(await c.env.API_RL.limit({ key: c.req.header("cf-connecting-ip") || "unknown" })).success) return err(c, 429, "rate_limited");
    c.set("auth", createAuth(c.env, c.executionCtx as never));
    c.header("cache-control", "no-store");
    await next();
  });

  // ---------- operator ----------
  const op = new Hono<{ Bindings: Env; Variables: Vars }>();
  op.use("*", async (c, next) => {
    const token = (c.req.header("authorization") || "").replace(/^Bearer\s+/i, "");
    if (!c.env.OPERATOR_TOKEN || c.env.OPERATOR_TOKEN.length < 32) return err(c, 404, "not_found");
    if (!token || !timingSafeEqual(token, c.env.OPERATOR_TOKEN)) return err(c, 401, "unauthorized");
    await next();
  });

  /** Registers a confidential web client for an app. The secret is shown once. */
  op.post("/clients", async (c) => {
    const b = await body<{ app?: string; name?: string; redirect_uris?: string[]; post_logout_redirect_uris?: string[]; resources?: string[]; uri?: string; logo_uri?: string; skip_consent?: boolean }>(c);
    if (!b || !b.app || !APP_ID.test(b.app)) return err(c, 400, "invalid_app", "app: lowercase letters, digits and dashes");
    if (!b.name || !Array.isArray(b.redirect_uris) || !b.redirect_uris.length) return err(c, 400, "invalid_request", "name and redirect_uris are required");
    const known = new Set(resourceList(c.env));
    const resources = (b.resources || []).filter((r) => known.has(r));
    if ((b.resources || []).length !== resources.length) return err(c, 400, "invalid_target", "every resource must be listed in the RESOURCES variable");
    const created = await c.get("auth").api.adminCreateOAuthClient({
      headers: new Headers({ [OPERATOR_HEADER]: c.env.OPERATOR_TOKEN! }),
      body: {
        client_name: b.name,
        client_uri: b.uri,
        logo_uri: b.logo_uri,
        redirect_uris: b.redirect_uris,
        post_logout_redirect_uris: b.post_logout_redirect_uris?.length ? b.post_logout_redirect_uris : undefined,
        token_endpoint_auth_method: "client_secret_basic",
        grant_types: ["authorization_code", "refresh_token", "client_credentials"],
        response_types: ["code"],
        scope: SCOPES.join(" "),
        client_credentials_scopes: [DIRECTORY_SCOPE],
        resources: [...resources, directoryAudience(c.env)],
        skip_consent: b.skip_consent === true,
        enable_end_session: true,
        require_pkce: true,
        metadata: { app: b.app },
      },
    });
    return c.json(created, 201);
  });

  /** Creates an organization for an app, optionally with a first owner (by email; the account is created if needed). */
  op.post("/orgs", async (c) => {
    const b = await body<{ app?: string; name?: string; slug?: string; owner_email?: string; metadata?: Record<string, unknown> }>(c);
    if (!b || !b.app || !APP_ID.test(b.app)) return err(c, 400, "invalid_app");
    if (!b.name || b.name.length > 120 || !b.slug || !SLUG.test(b.slug)) return err(c, 400, "invalid_request", "name (max 120) and slug (lowercase, digits, dashes) are required");
    if (b.owner_email && !EMAIL.test(b.owner_email)) return err(c, 400, "invalid_email");
    const db = await adapter(c);
    if (await db.findOne({ model: "organization", where: [{ field: "slug", value: b.slug }] })) return err(c, 409, "slug_taken");
    const org = await db.create<Record<string, unknown>, Org>({ model: "organization", data: { name: b.name, slug: b.slug, app: b.app, metadata: JSON.stringify(b.metadata || {}), createdAt: new Date() } });
    let owner: User | null = null;
    if (b.owner_email) {
      owner = await findOrCreateUser(c, b.owner_email);
      await db.create({ model: "member", data: { organizationId: org.id, userId: owner.id, role: "owner", createdAt: new Date() } });
    }
    return c.json({ ...orgOut(org), owner: owner ? userOut(owner) : null }, 201);
  });

  op.get("/orgs", async (c) => {
    const app = c.req.query("app");
    const where = app ? [{ field: "app", value: app }] : [];
    const orgs = await (await adapter(c)).findMany<Org>({ model: "organization", where, limit: 200, sortBy: { field: "createdAt", direction: "asc" } });
    return c.json({ data: orgs.map(orgOut) });
  });

  api.route("/operator", op);

  // ---------- directory (per app) ----------
  const dir = new Hono<{ Bindings: Env; Variables: Vars }>();
  dir.use("*", async (c, next) => {
    const token = (c.req.header("authorization") || "").replace(/^Bearer\s+/i, "");
    if (!token) return err(c, 401, "unauthorized");
    let clientId: string;
    try {
      const jwks = (await c.get("auth").api.getJwks()) as unknown as JSONWebKeySet;
      const { payload } = await jwtVerify(token, createLocalJWKSet(jwks), { issuer: new URL(c.env.STEM_URL).origin, audience: directoryAudience(c.env) });
      const scopes = String(payload.scope || "").split(" ");
      // Client-credentials tokens only: sub is the client itself, never a user.
      if (!scopes.includes(DIRECTORY_SCOPE) || !payload.client_id || payload.sub !== payload.client_id) return err(c, 403, "insufficient_scope");
      clientId = String(payload.client_id);
    } catch {
      return err(c, 401, "invalid_token");
    }
    const client = await (await adapter(c)).findOne<{ disabled?: boolean; metadata?: unknown }>({ model: "oauthClient", where: [{ field: "clientId", value: clientId }] });
    const app = client && !client.disabled ? asJson(client.metadata).app : null;
    if (typeof app !== "string" || !app) return err(c, 403, "client_has_no_app");
    c.set("app", app);
    c.set("clientId", clientId);
    await next();
  });

  dir.get("/roles", (c) => c.json({ data: roleNames(c.env.ORG_ROLES) }));

  dir.get("/orgs", async (c) => {
    const orgs = await (await adapter(c)).findMany<Org>({ model: "organization", where: [{ field: "app", value: c.get("app") }], limit: 200, sortBy: { field: "createdAt", direction: "asc" } });
    return c.json({ data: orgs.map(orgOut) });
  });

  dir.get("/orgs/:id", async (c) => {
    const org = await appOrg(c, c.req.param("id"));
    return org ? c.json(orgOut(org)) : err(c, 404, "not_found");
  });

  dir.patch("/orgs/:id", async (c) => {
    const org = await appOrg(c, c.req.param("id"));
    if (!org) return err(c, 404, "not_found");
    const b = await body<{ name?: string; logo?: string | null; metadata?: Record<string, unknown> }>(c);
    if (!b) return err(c, 400, "invalid_request");
    const update: Record<string, unknown> = {};
    if (b.name !== undefined) { if (!b.name || b.name.length > 120) return err(c, 400, "invalid_name"); update.name = b.name; }
    if (b.logo !== undefined) { if (b.logo && !/^https:\/\//.test(b.logo)) return err(c, 400, "invalid_logo"); update.logo = b.logo || null; }
    if (b.metadata !== undefined) { if (typeof b.metadata !== "object" || Array.isArray(b.metadata)) return err(c, 400, "invalid_metadata"); update.metadata = JSON.stringify(b.metadata); }
    if (!Object.keys(update).length) return c.json(orgOut(org));
    const out = await (await adapter(c)).update<Org>({ model: "organization", where: [{ field: "id", value: org.id }], update });
    return c.json(orgOut(out || org));
  });

  dir.get("/orgs/:id/members", async (c) => {
    const org = await appOrg(c, c.req.param("id"));
    if (!org) return err(c, 404, "not_found");
    const limit = Math.min(Math.max(Number(c.req.query("limit")) || 100, 1), 200);
    const offset = Math.max(Number(c.req.query("offset")) || 0, 0);
    const db = await adapter(c);
    const where = [{ field: "organizationId", value: org.id }];
    const [members, total] = await Promise.all([
      db.findMany<Member>({ model: "member", where, limit, offset, sortBy: { field: "createdAt", direction: "asc" } }),
      db.count({ model: "member", where }),
    ]);
    const users = members.length ? await db.findMany<User>({ model: "user", where: [{ field: "id", operator: "in", value: members.map((m) => m.userId) }] }) : [];
    const byId = new Map(users.map((u) => [u.id, u]));
    return c.json({
      data: members.map((m) => ({ user_id: m.userId, role: m.role, created_at: iso(m.createdAt), user: byId.has(m.userId) ? userOut(byId.get(m.userId)!) : null })),
      total, limit, offset,
    });
  });

  /** Adds a member directly, by user id or email (an account is created for unknown emails). */
  dir.post("/orgs/:id/members", async (c) => {
    const org = await appOrg(c, c.req.param("id"));
    if (!org) return err(c, 404, "not_found");
    const b = await body<{ user_id?: string; email?: string; role?: string }>(c);
    if (!b || !b.role || !isRole(b.role, c.env.ORG_ROLES)) return err(c, 400, "invalid_role");
    const db = await adapter(c);
    let user: User | null = null;
    if (b.user_id) user = await db.findOne<User>({ model: "user", where: [{ field: "id", value: b.user_id }] });
    else if (b.email && EMAIL.test(b.email)) user = await findOrCreateUser(c, b.email);
    if (!user) return err(c, 404, "user_not_found");
    if (await db.findOne({ model: "member", where: [{ field: "organizationId", value: org.id }, { field: "userId", value: user.id }] })) return err(c, 409, "already_member");
    const m = await db.create<Record<string, unknown>, Member>({ model: "member", data: { organizationId: org.id, userId: user.id, role: b.role, createdAt: new Date() } });
    return c.json({ user_id: m.userId, role: m.role, created_at: iso(m.createdAt), user: userOut(user) }, 201);
  });

  const lastOwner = async (c: C, orgId: string, userId: string) => {
    const db = await adapter(c);
    const owners = await db.findMany<Member>({ model: "member", where: [{ field: "organizationId", value: orgId }, { field: "role", value: "owner" }], limit: 2 });
    return owners.length === 1 && owners[0].userId === userId;
  };

  dir.patch("/orgs/:id/members/:userId", async (c) => {
    const org = await appOrg(c, c.req.param("id"));
    if (!org) return err(c, 404, "not_found");
    const b = await body<{ role?: string }>(c);
    if (!b || !b.role || !isRole(b.role, c.env.ORG_ROLES)) return err(c, 400, "invalid_role");
    const userId = c.req.param("userId");
    const db = await adapter(c);
    const where = [{ field: "organizationId", value: org.id }, { field: "userId", value: userId }];
    const m = await db.findOne<Member>({ model: "member", where });
    if (!m) return err(c, 404, "not_member");
    if (m.role === "owner" && b.role !== "owner" && (await lastOwner(c, org.id, userId))) return err(c, 409, "last_owner");
    const out = await db.update<Member>({ model: "member", where: [{ field: "id", value: m.id }], update: { role: b.role } });
    return c.json({ user_id: userId, role: out?.role || b.role });
  });

  dir.delete("/orgs/:id/members/:userId", async (c) => {
    const org = await appOrg(c, c.req.param("id"));
    if (!org) return err(c, 404, "not_found");
    const userId = c.req.param("userId");
    const db = await adapter(c);
    const m = await db.findOne<Member>({ model: "member", where: [{ field: "organizationId", value: org.id }, { field: "userId", value: userId }] });
    if (!m) return err(c, 404, "not_member");
    if (m.role === "owner" && (await lastOwner(c, org.id, userId))) return err(c, 409, "last_owner");
    await db.delete({ model: "member", where: [{ field: "id", value: m.id }] });
    return c.body(null, 204);
  });

  dir.get("/orgs/:id/invitations", async (c) => {
    const org = await appOrg(c, c.req.param("id"));
    if (!org) return err(c, 404, "not_found");
    const status = c.req.query("status") || "pending";
    const invs = await (await adapter(c)).findMany<Invitation>({ model: "invitation", where: [{ field: "organizationId", value: org.id }, { field: "status", value: status }], limit: 200, sortBy: { field: "createdAt", direction: "desc" } });
    return c.json({ data: invs.map(invOut) });
  });

  /** Invites by email. `inviter_id` is the stem user acting in the app (the `sub` of their token);
   * without it the first owner of the organization is named as inviter. */
  dir.post("/orgs/:id/invitations", async (c) => {
    const org = await appOrg(c, c.req.param("id"));
    if (!org) return err(c, 404, "not_found");
    const b = await body<{ email?: string; role?: string; inviter_id?: string; redirect_to?: string; expires_in_days?: number }>(c);
    if (!b || !b.email || !EMAIL.test(b.email)) return err(c, 400, "invalid_email");
    const days = b.expires_in_days ?? 7;
    if (!Number.isInteger(days) || days < 1 || days > 30) return err(c, 400, "invalid_expiry", "expires_in_days: whole days from 1 to 30");
    const role = b.role || "member";
    if (!isRole(role, c.env.ORG_ROLES) || role === "owner") return err(c, 400, "invalid_role");
    if (b.redirect_to) {
      let origin = "";
      try { origin = new URL(b.redirect_to).origin; } catch {}
      if (!(await appOrigins(c)).has(origin)) return err(c, 400, "invalid_redirect", "redirect_to must be on the origin of one of the app's redirect URIs");
    }
    const db = await adapter(c);
    const email = b.email.toLowerCase();
    let inviterId = b.inviter_id || "";
    if (inviterId && !(await db.findOne({ model: "member", where: [{ field: "organizationId", value: org.id }, { field: "userId", value: inviterId }] }))) return err(c, 422, "inviter_not_member");
    if (!inviterId) {
      const owner = (await db.findMany<Member>({ model: "member", where: [{ field: "organizationId", value: org.id }, { field: "role", value: "owner" }], limit: 1 }))[0];
      if (!owner) return err(c, 422, "inviter_required", "the organization has no owner; pass inviter_id");
      inviterId = owner.userId;
    }
    const existing = await db.findOne<User>({ model: "user", where: [{ field: "email", value: email }] });
    if (existing && (await db.findOne({ model: "member", where: [{ field: "organizationId", value: org.id }, { field: "userId", value: existing.id }] }))) return err(c, 409, "already_member");
    // A new invitation replaces any pending one for the same address.
    await db.updateMany({ model: "invitation", where: [{ field: "organizationId", value: org.id }, { field: "email", value: email }, { field: "status", value: "pending" }], update: { status: "canceled" } });
    const inv = await db.create<Record<string, unknown>, Invitation>({
      model: "invitation",
      data: { organizationId: org.id, email, role, status: "pending", inviterId, expiresAt: new Date(Date.now() + days * DAY_MS), createdAt: new Date(), redirectTo: b.redirect_to || null },
    });
    const inviter = await db.findOne<User>({ model: "user", where: [{ field: "id", value: inviterId }] });
    const link = `${new URL(c.env.STEM_URL).origin}/invite/${encodeURIComponent(inv.id)}`;
    c.executionCtx.waitUntil(sendMail(c.env, inviteMail(email, org.name, inviter?.name || null, link, days)).catch((e) => console.error("[mail] invitation failed", e)));
    return c.json(invOut(inv), 201);
  });

  dir.delete("/orgs/:id/invitations/:invId", async (c) => {
    const org = await appOrg(c, c.req.param("id"));
    if (!org) return err(c, 404, "not_found");
    const db = await adapter(c);
    const inv = await db.findOne<Invitation>({ model: "invitation", where: [{ field: "id", value: c.req.param("invId") }, { field: "organizationId", value: org.id }] });
    if (!inv) return err(c, 404, "not_found");
    if (inv.status === "pending") await db.update({ model: "invitation", where: [{ field: "id", value: inv.id }], update: { status: "canceled" } });
    return c.body(null, 204);
  });

  /** A user's public profile, only for members of one of the app's organizations. */
  dir.get("/users/:id", async (c) => {
    const id = c.req.param("id");
    const db = await adapter(c);
    const memberships = await db.findMany<Member>({ model: "member", where: [{ field: "userId", value: id }], limit: 200 });
    if (memberships.length) {
      const orgs = await db.findMany<Org>({ model: "organization", where: [{ field: "id", operator: "in", value: memberships.map((m) => m.organizationId) }, { field: "app", value: c.get("app") }], limit: 1 });
      if (orgs.length) {
        const user = await db.findOne<User>({ model: "user", where: [{ field: "id", value: id }] });
        if (user) return c.json(userOut(user));
      }
    }
    return err(c, 404, "not_found");
  });

  api.route("/", dir);
  return api;
}
