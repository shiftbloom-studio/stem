// SPDX-License-Identifier: AGPL-3.0-or-later

/** Most organizations one token lists. Apps with more need the directory API. */
export const MAX_ORGS_IN_TOKEN = 50;

type Where = { field: string; value: unknown; operator?: "in" };
export type ClaimsAdapter = {
  findMany<T>(q: { model: string; where?: Where[]; limit?: number }): Promise<T[]>;
};

type Membership = { organizationId: string; role: string; isPrimary?: boolean | number | null };
type TeamOrg = { id: string; app?: string | null };

/** A stem-wide team belongs to no app. Every app sees it, except sealed apps (`withStemTeams` false). */
export const isStemTeam = (o: { app?: string | null }) => !o.app;

/** Whether an app sees an organization: its own, or a stem-wide team when those are allowed. */
export const visibleTo = (o: TeamOrg, app: string, withStemTeams = true) => o.app === app || (withStemTeams && isStemTeam(o));

/** The user's teams that one app sees, with the primary team (if the app sees it) listed first. */
export async function teamClaims(db: ClaimsAdapter, userId: string, app: string, withStemTeams = true): Promise<{ orgs: Record<string, string>; primary: string | null }> {
  const members = await db.findMany<Membership>({ model: "member", where: [{ field: "userId", value: userId }], limit: 500 });
  if (!members.length) return { orgs: {}, primary: null };
  const seen = new Set<string>();
  // D1 binds at most 100 parameters per query, so look organizations up in chunks.
  for (const ids of chunks(members.map((m) => m.organizationId), 90)) {
    const orgs = await db.findMany<TeamOrg>({ model: "organization", where: [{ field: "id", operator: "in", value: ids }], limit: ids.length });
    for (const o of orgs) if (visibleTo(o, app, withStemTeams)) seen.add(o.id);
  }
  const visible = members.filter((m) => seen.has(m.organizationId));
  const primary = visible.find((m) => !!m.isPrimary) || null;
  const ordered = primary ? [primary, ...visible.filter((m) => m !== primary)] : visible;
  return { orgs: Object.fromEntries(ordered.slice(0, MAX_ORGS_IN_TOKEN).map((m) => [m.organizationId, m.role])), primary: primary?.organizationId || null };
}

/** The user's organizations in one app, as { organizationId: role }. */
export async function orgClaims(db: ClaimsAdapter, userId: string, app: string, withStemTeams = true): Promise<Record<string, string>> {
  return (await teamClaims(db, userId, app, withStemTeams)).orgs;
}

export function chunks<T>(list: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < list.length; i += size) out.push(list.slice(i, i + size));
  return out;
}
