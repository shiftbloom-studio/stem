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
  const inApp = new Set<string>();
  // D1 binds at most 100 parameters per query, so look organizations up in chunks.
  for (const ids of chunks(members.map((m) => m.organizationId), 90)) {
    const orgs = await db.findMany<{ id: string }>({ model: "organization", where: [{ field: "id", operator: "in", value: ids }, { field: "app", value: app }], limit: ids.length });
    for (const o of orgs) inApp.add(o.id);
  }
  return Object.fromEntries(members.filter((m) => inApp.has(m.organizationId)).slice(0, MAX_ORGS_IN_TOKEN).map((m) => [m.organizationId, m.role]));
}

export function chunks<T>(list: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}
