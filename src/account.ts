// SPDX-License-Identifier: AGPL-3.0-or-later
// What a signed-in person can do with their own data, besides what Better Auth already offers:
// download all of it (GDPR Art. 15 and 20), and see and remove the apps that can act for them.
import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint, sessionMiddleware, APIError } from "better-auth/api";
import { chunks } from "./claims";
import { emailKey } from "./limits";

type Db = {
  findOne<T>(q: { model: string; where: { field: string; value: unknown; operator?: "in" | "lt" | "gt" }[] }): Promise<T | null>;
  findMany<T>(q: { model: string; where?: { field: string; value: unknown; operator?: "in" | "lt" | "gt" }[]; limit?: number }): Promise<T[]>;
  updateMany(q: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }): Promise<unknown>;
  deleteMany(q: { model: string; where: { field: string; value: unknown }[] }): Promise<unknown>;
};

type Client = { clientId: string; name?: string | null; uri?: string | null };
type Refresh = { clientId: string; scopes: string[] | string; createdAt: Date; expiresAt: Date; revoked?: Date | null };
type Consent = { clientId: string; scopes: string[] | string; createdAt: Date; updatedAt: Date };

const iso = (d: unknown) => (d ? new Date(d as string).toISOString() : null);
const list = (v: string[] | string | null | undefined) => (Array.isArray(v) ? v : String(v || "").split(/[\s,]+/).filter(Boolean));

async function clients(db: Db, ids: string[]): Promise<Map<string, Client>> {
  const out = new Map<string, Client>();
  for (const part of chunks([...new Set(ids)], 90)) {
    if (!part.length) continue;
    for (const c of await db.findMany<Client>({ model: "oauthClient", where: [{ field: "clientId", operator: "in", value: part }], limit: part.length })) out.set(c.clientId, c);
  }
  return out;
}

/** Apps that can still act for the person: a consent, or a refresh token that hasn't expired or been revoked. */
export async function connectedApps(db: Db, userId: string, now = Date.now()) {
  const [tokens, consents] = await Promise.all([
    db.findMany<Refresh>({ model: "oauthRefreshToken", where: [{ field: "userId", value: userId }, { field: "expiresAt", operator: "gt", value: new Date(now) }], limit: 500 }),
    db.findMany<Consent>({ model: "oauthConsent", where: [{ field: "userId", value: userId }], limit: 200 }),
  ]);
  const live = tokens.filter((t) => !t.revoked);
  const byClient = new Map<string, { scopes: Set<string>; lastUsed: number }>();
  const add = (clientId: string, scopes: string[], at: unknown) => {
    const e = byClient.get(clientId) || { scopes: new Set<string>(), lastUsed: 0 };
    for (const s of scopes) e.scopes.add(s);
    e.lastUsed = Math.max(e.lastUsed, new Date(at as string).getTime() || 0);
    byClient.set(clientId, e);
  };
  for (const t of live) add(t.clientId, list(t.scopes), t.createdAt);
  for (const c of consents) add(c.clientId, list(c.scopes), c.updatedAt || c.createdAt);
  const info = await clients(db, [...byClient.keys()]);
  return [...byClient.entries()]
    .map(([clientId, e]) => ({ client_id: clientId, name: info.get(clientId)?.name || "An app", uri: info.get(clientId)?.uri || null, scopes: [...e.scopes], last_used: e.lastUsed ? new Date(e.lastUsed).toISOString() : null }))
    .sort((a, b) => (b.last_used || "").localeCompare(a.last_used || ""));
}

/** Ends an app's access: its refresh tokens stop working, stored access tokens and the consent are deleted.
 * Signed access tokens already handed out still verify until they expire, ten minutes at most. */
export async function removeApp(db: Db, userId: string, clientId: string) {
  const where = [{ field: "userId", value: userId }, { field: "clientId", value: clientId }];
  await db.updateMany({ model: "oauthRefreshToken", where, update: { revoked: new Date() } });
  await db.deleteMany({ model: "oauthAccessToken", where });
  await db.deleteMany({ model: "oauthConsent", where });
}

/** Everything stem stores about one person, without secrets (no tokens, no key material, no code hashes). */
export async function exportData(db: Db, user: { id: string; email: string }) {
  const u = await db.findOne<Record<string, unknown>>({ model: "user", where: [{ field: "id", value: user.id }] });
  const [sessions, passkeys, members, invitations, accounts, apps, limit] = await Promise.all([
    db.findMany<Record<string, unknown>>({ model: "session", where: [{ field: "userId", value: user.id }], limit: 500 }),
    db.findMany<Record<string, unknown>>({ model: "passkey", where: [{ field: "userId", value: user.id }], limit: 100 }),
    db.findMany<{ organizationId: string; role: string; createdAt: Date }>({ model: "member", where: [{ field: "userId", value: user.id }], limit: 500 }),
    db.findMany<Record<string, unknown>>({ model: "invitation", where: [{ field: "email", value: user.email.toLowerCase() }], limit: 500 }),
    db.findMany<Record<string, unknown>>({ model: "account", where: [{ field: "userId", value: user.id }], limit: 50 }),
    connectedApps(db, user.id),
    db.findOne<Record<string, unknown>>({ model: "emailLimit", where: [{ field: "key", value: await emailKey(user.email) }] }),
  ]);
  const orgIds = [...new Set([...members.map((m) => m.organizationId), ...invitations.map((i) => String(i.organizationId))])];
  const orgs = new Map<string, { name: string; slug: string; app?: string | null }>();
  for (const part of chunks(orgIds, 90)) {
    for (const o of await db.findMany<{ id: string; name: string; slug: string; app?: string | null }>({ model: "organization", where: [{ field: "id", operator: "in", value: part }], limit: part.length })) orgs.set(o.id, o);
  }
  const org = (id: unknown) => { const o = orgs.get(String(id)); return o ? { id: String(id), name: o.name, slug: o.slug, app: o.app || null } : { id: String(id) }; };
  return {
    exported_at: new Date().toISOString(),
    account: { id: u?.id, email: u?.email, name: u?.name || null, email_verified: !!u?.emailVerified, created_at: iso(u?.createdAt), updated_at: iso(u?.updatedAt) },
    sign_in_methods: accounts.map((a) => ({ provider: a.providerId, created_at: iso(a.createdAt) })),
    passkeys: passkeys.map((p) => ({ id: p.id, name: p.name || null, device_type: p.deviceType, synced: !!p.backedUp, authenticator_aaguid: p.aaguid || null, transports: p.transports || null, created_at: iso(p.createdAt) })),
    sessions: sessions.map((s) => ({ created_at: iso(s.createdAt), updated_at: iso(s.updatedAt), expires_at: iso(s.expiresAt), ip_address: s.ipAddress || null, user_agent: s.userAgent || null, sign_in_method: s.authMethod || null })),
    teams: members.map((m) => ({ organization: org(m.organizationId), role: m.role, joined_at: iso(m.createdAt) })),
    invitations: invitations.map((i) => ({ organization: org(i.organizationId), role: i.role || null, status: i.status, created_at: iso(i.createdAt), expires_at: iso(i.expiresAt) })),
    apps,
    code_limits: limit ? { window_start: iso(limit.windowStart), codes_sent: limit.sends, attempts: limit.verifies, last_code_at: iso(limit.lastSend) } : null,
  };
}

export const accountTools = () =>
  ({
    id: "stem-account",
    endpoints: {
      exportAccountData: createAuthEndpoint("/stem/export", { method: "GET", use: [sessionMiddleware] }, async (ctx) => {
        const data = await exportData(ctx.context.adapter as unknown as Db, ctx.context.session.user);
        ctx.setHeader("content-disposition", `attachment; filename="stem-data-${new Date().toISOString().slice(0, 10)}.json"`);
        ctx.setHeader("cache-control", "no-store");
        return ctx.json(data);
      }),
      // Better Auth's /list-sessions wants a session younger than freshAge (15 minutes), so the account
      // page showed nothing for anyone signed in longer. Seeing your own sessions isn't sensitive;
      // ending one (/revoke-session) only needs a valid session too.
      listOwnSessions: createAuthEndpoint("/stem/sessions", { method: "GET", use: [sessionMiddleware] }, async (ctx) => {
        ctx.setHeader("cache-control", "no-store");
        const now = Date.now();
        const rows = await ctx.context.internalAdapter.listSessions(ctx.context.session.user.id, { onlyActiveSessions: true });
        return ctx.json(
          rows
            .filter((s) => new Date(s.expiresAt).getTime() > now)
            .map((s) => ({ id: s.id, token: s.token, userAgent: s.userAgent || null, ipAddress: s.ipAddress || null, createdAt: s.createdAt, updatedAt: s.updatedAt, expiresAt: s.expiresAt })),
        );
      }),
      listConnectedApps: createAuthEndpoint("/stem/apps", { method: "GET", use: [sessionMiddleware] }, async (ctx) => {
        ctx.setHeader("cache-control", "no-store");
        return ctx.json(await connectedApps(ctx.context.adapter as unknown as Db, ctx.context.session.user.id));
      }),
      removeConnectedApp: createAuthEndpoint("/stem/apps/remove", { method: "POST", use: [sessionMiddleware] }, async (ctx) => {
        const clientId = typeof (ctx.body as { client_id?: unknown })?.client_id === "string" ? (ctx.body as { client_id: string }).client_id : "";
        if (!clientId || clientId.length > 200) throw new APIError("BAD_REQUEST", { message: "client_id is required" });
        await removeApp(ctx.context.adapter as unknown as Db, ctx.context.session.user.id, clientId);
        return ctx.json({ success: true });
      }),
    },
  }) satisfies BetterAuthPlugin;
