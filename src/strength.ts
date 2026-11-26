// SPDX-License-Identifier: AGPL-3.0-or-later
// How strongly someone signed in, and how apps learn about it.
// Each session remembers its sign-in method; tokens carry it as `auth_method`, so an app can ask
// for a fresh passkey (prompt=login or max_age) before an admin action and check what happened.
import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";

export type AuthMethod = "passkey" | "email_code";
/** What tokens say: the session's method, or "unknown" for sessions that don't have one. */
export type AuthMethodClaim = AuthMethod | "unknown";

/** Endpoints that create a session, and the method each one proves. Paths not listed leave the
 * session without a method, which tokens report as "unknown": never stronger than an email code. */
export const SIGN_IN_METHODS: Record<string, AuthMethod> = {
  "/sign-in/email-otp": "email_code",
  // Confirming an address with a code signs the person in (autoSignInAfterVerification).
  "/email-otp/verify-email": "email_code",
  "/passkey/verify-authentication": "passkey",
};

type Db = {
  findOne<T>(q: { model: string; where: { field: string; value: unknown }[] }): Promise<T | null>;
  update<T>(q: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }): Promise<T | null>;
};

type SessionRow = { id: string; createdAt: Date | string; expiresAt: Date | string; authMethod?: string | null; passkeySynced?: boolean | number | null };

/** Records the sign-in method on the session the request just created. */
export const authStrength = () =>
  ({
    id: "stem-auth-strength",
    schema: {
      session: {
        fields: {
          authMethod: { type: "string", required: false, input: false },
          passkeySynced: { type: "boolean", required: false, input: false },
        },
      },
    },
    hooks: {
      after: [
        {
          matcher: (ctx) => !!ctx.path && Object.hasOwn(SIGN_IN_METHODS, ctx.path),
          handler: createAuthMiddleware(async (ctx) => {
            const created = ctx.context.newSession?.session;
            const method = SIGN_IN_METHODS[ctx.path];
            if (!created?.id || !method) return;
            const db = ctx.context.adapter as unknown as Db;
            // Never fail a sign-in over the marker: without it, tokens just say "unknown".
            try {
              const update: Record<string, unknown> = { authMethod: method, passkeySynced: null };
              if (method === "passkey") {
                const credentialID = (ctx.body as { response?: { id?: unknown } } | undefined)?.response?.id;
                const pk = typeof credentialID === "string" ? await db.findOne<{ backedUp?: boolean | number | null }>({ model: "passkey", where: [{ field: "credentialID", value: credentialID }] }) : null;
                // A synced passkey (iCloud Keychain, Google Password Manager, …) can be copied to other devices.
                update.passkeySynced = pk ? !!pk.backedUp : null;
              }
              await db.update({ model: "session", where: [{ field: "id", value: created.id }], update });
            } catch (e) {
              console.error("[stem] could not record the sign-in method", e);
            }
          }),
        },
      ],
    },
  }) satisfies BetterAuthPlugin;

export type StrengthClaims = { auth_method: AuthMethodClaim; passkey_synced?: boolean; signed_in_at?: number };

/** The claims for tokens issued on one session. Without a live session the method is "unknown". */
export async function strengthClaims(db: Db, sessionId: string | undefined, now = Date.now()): Promise<StrengthClaims> {
  const s = sessionId ? await db.findOne<SessionRow>({ model: "session", where: [{ field: "id", value: sessionId }] }) : null;
  if (!s || new Date(s.expiresAt).getTime() <= now) return { auth_method: "unknown" };
  const method: AuthMethodClaim = s.authMethod === "passkey" || s.authMethod === "email_code" ? s.authMethod : "unknown";
  const claims: StrengthClaims = { auth_method: method };
  if (method === "passkey" && s.passkeySynced != null) claims.passkey_synced = !!s.passkeySynced;
  const at = new Date(s.createdAt).getTime();
  // The moment of sign-in, like the ID token's auth_time. Access tokens can't carry auth_time itself.
  if (Number.isFinite(at)) claims.signed_in_at = Math.floor(at / 1000);
  return claims;
}

/** acr_values an app may send to ask for a passkey: OpenID EAP "phishing-resistant" (and its hardware-bound form). */
const PASSKEY_ACR = new Set(["phr", "phrh"]);

/** Whether an authorization request asks the person to prove themselves again, so the sign-in page
 * should offer their passkey first. */
export function wantsStepUp(query: URLSearchParams): boolean {
  const prompt = (query.get("prompt") || "").split(" ");
  if (prompt.includes("login")) return true;
  if (query.has("max_age")) return true;
  return (query.get("acr_values") || "").split(" ").some((v) => PASSKEY_ACR.has(v));
}
