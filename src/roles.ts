// SPDX-License-Identifier: AGPL-3.0-or-later
import { createAccessControl } from "better-auth/plugins/access";
import { defaultStatements, ownerAc, adminAc, memberAc } from "better-auth/plugins/organization/access";

const ROLE_NAME = /^[a-z][a-z0-9_-]{1,31}$/;
export const BUILTIN_ROLES = ["owner", "admin", "member"] as const;

/** owner, admin and member, plus the app roles from ORG_ROLES. App roles get member rights inside stem;
 * what they mean is up to the app, which reads them from the `orgs` claim. */
export function roleNames(extra?: string): string[] {
  const custom = (extra || "").split(",").map((r) => r.trim().toLowerCase()).filter((r) => ROLE_NAME.test(r) && !(BUILTIN_ROLES as readonly string[]).includes(r));
  return [...BUILTIN_ROLES, ...new Set(custom)];
}

export function accessControl(extra?: string) {
  const ac = createAccessControl(defaultStatements);
  const roles: Record<string, ReturnType<typeof ac.newRole>> = {
    owner: ac.newRole(ownerAc.statements),
    admin: ac.newRole(adminAc.statements),
    member: ac.newRole(memberAc.statements),
  };
  for (const r of roleNames(extra)) if (!roles[r]) roles[r] = ac.newRole(memberAc.statements);
  return { ac, roles };
}

export const isRole = (role: string, extra?: string) => roleNames(extra).includes(role);
