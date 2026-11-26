// SPDX-License-Identifier: AGPL-3.0-or-later
// An email whenever a passkey is added to an account. A passkey is a full way in, so someone who got hold
// of a session (or of the mailbox, through a code) could add their own and come back later. The notice
// tells the person in time to remove it. Off unless NOTIFY_NEW_PASSKEY is "true".
import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import type { Env } from "./env";
import { passkeyAddedMail, type Mail } from "./email";

/** No notice for a passkey added this soon after the account was created: that's the person's own
 * sign-up, and nobody else could have had the account yet. */
export const NEW_ACCOUNT_GRACE_MS = 15 * 60 * 1000;

export const passkeyNoticeEnabled = (env: Pick<Env, "NOTIFY_NEW_PASSKEY">) => env.NOTIFY_NEW_PASSKEY === "true";

type Added = { id?: unknown; userId?: unknown; name?: unknown; backedUp?: unknown; createdAt?: unknown };
type UserRow = { id: string; email: string; createdAt: Date | string };

export const passkeyNotice = (env: Env, send: (mail: Mail) => void) =>
  ({
    id: "stem-passkey-notice",
    hooks: {
      after: [
        {
          matcher: (ctx) => ctx.path === "/passkey/verify-registration" && passkeyNoticeEnabled(env),
          handler: createAuthMiddleware(async (ctx) => {
            const pk = ctx.context.returned as Added | undefined;
            if (!pk || typeof pk !== "object" || typeof pk.id !== "string" || typeof pk.userId !== "string") return;
            // Never fail a registration over the notice.
            try {
              const user = (await ctx.context.internalAdapter.findUserById(pk.userId)) as UserRow | null;
              if (!user?.email) return;
              const added = pk.createdAt ? new Date(pk.createdAt as string) : new Date();
              if (added.getTime() - new Date(user.createdAt).getTime() < NEW_ACCOUNT_GRACE_MS) return;
              send(passkeyAddedMail(user.email, {
                name: typeof pk.name === "string" && pk.name.trim() ? pk.name.trim().slice(0, 80) : null,
                synced: !!pk.backedUp,
                at: added,
                account: `${new URL(env.STEM_URL).origin}/account`,
              }));
            } catch (e) {
              console.error("[stem] passkey notice failed", e);
            }
          }),
        },
      ],
    },
  }) satisfies BetterAuthPlugin;
