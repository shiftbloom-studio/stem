// SPDX-License-Identifier: AGPL-3.0-or-later

/** Most organizations one token lists. Apps with more need the directory API. */
export const MAX_ORGS_IN_TOKEN = 50;

export type ClaimsAdapter = {
  findMany<T>(q: { model: string; where?: { field: string; value: unknown; operator?: "in" }[]; limit?: number }): Promise<T[]>;
};

/** The user's organizations in one app, as { organizationId: role }. */
export async function orgClaims(db: ClaimsAdapter, userId: string, app: string): Promise<Record<string, string>> {
  const members = await db.findMany<{ organizationId: string; role: string }>({ model: "member", where: [{ field: "userId", value: userId }], limit: 500 });
  if (!members.length) return {};
  const orgs = await db.findMany<{ id: string }>({
    model: "organization",
    where: [{ field: "id", operator: "in", value: members.map((m) => m.organizationId) }, { field: "app", value: app }],
    limit: MAX_ORGS_IN_TOKEN,
  });
  const inApp = new Set(orgs.map((o) => o.id));
  return Object.fromEntries(members.filter((m) => inApp.has(m.organizationId)).slice(0, MAX_ORGS_IN_TOKEN).map((m) => [m.organizationId, m.role]));
}
