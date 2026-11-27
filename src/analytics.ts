// SPDX-License-Identifier: AGPL-3.0-or-later
// Anonymous usage counts for PostHog (src/posthog.ts): which sign-in steps succeed, how people sign in, and
// which apps they sign in to. Off unless POSTHOG_KEY is set. Events carry no user id, email address, name,
// IP address, code or token, and every event gets a fresh random distinct_id, so none can be tied to a person.
import type { BetterAuthPlugin } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import type { Env } from "./env";
import { phCapture, phKey } from "./posthog";
import { SIGN_IN_METHODS } from "./strength";

type Exec = { waitUntil(p: Promise<unknown>): void } | undefined;
type Ctx = { path: string; body?: unknown; headers?: Headers; context: { returned?: unknown; newSession?: { user?: { createdAt?: Date | string } } | null } };
type Props = Record<string, string | number | boolean | null>;

/** A new account signs in for the first time within this window after it was created. */
const FIRST_SIGN_IN_MS = 15 * 60 * 1000;

const failed = (r: unknown) => r instanceof Error;
const str = (v: unknown, re: RegExp) => (typeof v === "string" && re.test(v) ? v : null);
const body = (ctx: Ctx) => (ctx.body && typeof ctx.body === "object" ? (ctx.body as Record<string, unknown>) : {});

function clientId(ctx: Ctx) {
  const fromBody = str(body(ctx).client_id, /^[A-Za-z0-9_-]{1,64}$/);
  if (fromBody) return fromBody;
  const basic = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(ctx.headers?.get("authorization") || "");
  if (!basic) return null;
  try {
    return str(decodeURIComponent(atob(basic[1]).split(":")[0]), /^[A-Za-z0-9_-]{1,64}$/);
  } catch {
    return null;
  }
}

/** Path -> event. Each returns the properties, or null to send nothing. Only values from fixed sets go out. */
export const EVENTS: Record<string, (ctx: Ctx) => [string, Props] | null> = {
  "/email-otp/send-verification-otp": (ctx) => ["code_sent", { type: str(body(ctx).type, /^(sign-in|email-verification)$/) }],
  "/passkey/verify-registration": (ctx) => {
    const pk = ctx.context.returned as { backedUp?: unknown } | undefined;
    return pk && typeof pk === "object" ? ["passkey_added", { synced: !!pk.backedUp }] : null;
  },
  "/passkey/delete-passkey": () => ["passkey_removed", {}],
  "/delete-user": () => ["account_deleted", {}],
  "/oauth2/consent": (ctx) => ["consent_answered", { accepted: body(ctx).accept === true }],
  "/organization/accept-invitation": () => ["invitation_accepted", {}],
  // An app finished a sign-in: the code from /oauth2/authorize was exchanged. client is the app's OAuth client id,
  // its public identifier. Refreshes are not counted.
  "/oauth2/token": (ctx) => (body(ctx).grant_type === "authorization_code" ? ["app_signed_in", { client: clientId(ctx) }] : null),
  "/mandates/approve": () => ["mandate_approved", {}],
  "/mandates/deny": () => ["mandate_denied", {}],
  "/mandates/revoke": () => ["mandate_revoked", {}],
};

export function signInEvent(ctx: Ctx, now = Date.now()): [string, Props] | null {
  const method = SIGN_IN_METHODS[ctx.path];
  const user = ctx.context.newSession?.user;
  if (!method || !user) return null;
  const created = user.createdAt ? new Date(user.createdAt).getTime() : Number.NaN;
  return ["signed_in", { method, first_sign_in: Number.isFinite(created) && now - created < FIRST_SIGN_IN_MS }];
}

export const usageEvents = (env: Env, exec: Exec) =>
  ({
    id: "stem-usage-events",
    hooks: {
      after: [
        {
          matcher: (ctx) => !!phKey(env) && !!ctx.path && (Object.hasOwn(SIGN_IN_METHODS, ctx.path) || Object.hasOwn(EVENTS, ctx.path)),
          handler: createAuthMiddleware(async (ctx) => {
            // Never fail a request over statistics.
            try {
              const c = ctx as unknown as Ctx;
              if (failed(c.context.returned)) return;
              const ev = Object.hasOwn(SIGN_IN_METHODS, c.path) ? signInEvent(c) : EVENTS[c.path](c);
              if (ev) void phCapture(env, exec, ev[0], ev[1]);
            } catch (e) {
              console.error("[stem] usage event failed", e);
            }
          }),
        },
      ],
    },
  }) satisfies BetterAuthPlugin;
