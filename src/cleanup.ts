// SPDX-License-Identifier: AGPL-3.0-or-later
// Daily cleanup (cron trigger): personal data that has done its job is deleted instead of piling up in D1.
// The periods here are the ones the privacy policy promises; change both together.

const DAY_MS = 24 * 3600 * 1000;
/** Unconfirmed accounts (made for an invitation or by an app) that belong to no team anymore. */
export const UNCONFIRMED_ACCOUNT_DAYS = 30;
/** Invitations, counted from when they expire. */
export const INVITATION_DAYS = 90;

type Where = { field: string; value: unknown; operator?: "lt" | "eq" | "in" };
type Db = {
  findMany<T>(q: { model: string; where?: Where[]; limit?: number }): Promise<T[]>;
  count(q: { model: string; where?: Where[] }): Promise<number>;
  deleteMany(q: { model: string; where: Where[] }): Promise<number | unknown>;
};

/** Deletes what's no longer needed and returns how many rows went, per kind. */
export async function cleanup(db: Db, now = Date.now()): Promise<Record<string, number>> {
  const before = (days: number) => new Date(now - days * DAY_MS);
  const n = (v: unknown) => (typeof v === "number" ? v : 0);
  const out: Record<string, number> = {};
  // Expired sessions, with their IP address and user agent.
  out.sessions = n(await db.deleteMany({ model: "session", where: [{ field: "expiresAt", operator: "lt", value: new Date(now) }] }));
  // Code hashes and other one-time values, a day after they expire (their identifier holds the address).
  out.verifications = n(await db.deleteMany({ model: "verification", where: [{ field: "expiresAt", operator: "lt", value: before(1) }] }));
  // Per-IP request counters (Better Auth stores milliseconds here).
  out.rateLimits = n(await db.deleteMany({ model: "rateLimit", where: [{ field: "lastRequest", operator: "lt", value: now - DAY_MS }] }));
  // Per-address code counters.
  out.emailLimits = n(await db.deleteMany({ model: "emailLimit", where: [{ field: "windowStart", operator: "lt", value: before(2) }] }));
  // App tokens a day after they expire. Revoked refresh tokens stay until then: they let stem spot a replayed token.
  out.accessTokens = n(await db.deleteMany({ model: "oauthAccessToken", where: [{ field: "expiresAt", operator: "lt", value: before(1) }] }));
  out.refreshTokens = n(await db.deleteMany({ model: "oauthRefreshToken", where: [{ field: "expiresAt", operator: "lt", value: before(1) }] }));
  out.clientAssertions = n(await db.deleteMany({ model: "oauthClientAssertion", where: [{ field: "expiresAt", operator: "lt", value: new Date(now) }] }));
  out.invitations = n(await db.deleteMany({ model: "invitation", where: [{ field: "expiresAt", operator: "lt", value: before(INVITATION_DAYS) }] }));
  out.unconfirmedAccounts = 0;
  const stale = await db.findMany<{ id: string }>({ model: "user", where: [{ field: "emailVerified", value: false }, { field: "createdAt", operator: "lt", value: before(UNCONFIRMED_ACCOUNT_DAYS) }], limit: 200 });
  for (const u of stale) {
    const counts = await Promise.all([
      db.count({ model: "member", where: [{ field: "userId", value: u.id }] }),
      db.count({ model: "invitation", where: [{ field: "inviterId", value: u.id }] }),
      db.count({ model: "passkey", where: [{ field: "userId", value: u.id }] }),
      db.count({ model: "session", where: [{ field: "userId", value: u.id }] }),
    ]);
    if (counts.some((c) => c > 0)) continue;
    await db.deleteMany({ model: "user", where: [{ field: "id", value: u.id }, { field: "emailVerified", value: false }] });
    out.unconfirmedAccounts++;
  }
  return out;
}
