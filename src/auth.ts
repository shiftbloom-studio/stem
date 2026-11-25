// SPDX-License-Identifier: AGPL-3.0-or-later
// The Better Auth instance behind stem. One instance per isolate and environment.
import { betterAuth } from "better-auth";
import { createAuthMiddleware } from "better-auth/api";
import { emailOTP, organization, jwt, captcha } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import { oauthProvider } from "@better-auth/oauth-provider";
import type { Env } from "./env";
import { accessControl } from "./roles";
import { sendMail, codeMail, inviteMail } from "./email";
import { orgClaims, type ClaimsAdapter } from "./claims";
import { timingSafeEqual } from "./util";

/** Scopes clients may ask for. `orgs` adds the user's organizations in the client's app to the access token. */
export const SCOPES: string[] = ["openid", "profile", "email", "offline_access", "orgs"];
export const DIRECTORY_SCOPE = "directory";
export const ACCESS_TOKEN_TTL = 600;

export const resourceList = (env: Env) =>
  (env.RESOURCES || "").split(",").map((r) => r.trim()).filter(Boolean);
/** Audience of client-credentials tokens for the directory API. */
export const directoryAudience = (env: Env) => `${env.STEM_URL}/api/v1`;

let pending: Promise<unknown> | null = null;
function background(ctx: { waitUntil?: (p: Promise<unknown>) => void } | undefined, p: Promise<unknown>) {
  const safe = p.catch((e) => console.error("[mail] send failed", e));
  if (ctx?.waitUntil) ctx.waitUntil(safe);
  else pending = safe;
}
/** Tests await queued mail through this. */
export const flushMail = () => pending;

/** Only waitUntil is used, so tests can pass a stub. */
export type Exec = { waitUntil(p: Promise<unknown>): void };

/** Header the operator API sets on its own server-side calls. External requests can't know the token. */
export const OPERATOR_HEADER = "x-stem-operator";
const isOperator = (env: Env, headers?: Headers | null) => {
  const v = headers?.get(OPERATOR_HEADER);
  return !!(v && env.OPERATOR_TOKEN && env.OPERATOR_TOKEN.length >= 32 && timingSafeEqual(v, env.OPERATOR_TOKEN));
};

export function createAuth(env: Env, exec?: Exec) {
  const url = new URL(env.STEM_URL);
  const { ac, roles } = accessControl(env.ORG_ROLES);
  const turnstile = env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET;

  // Filled in once the instance exists; the claim callbacks only run on requests, after that.
  let adapter: () => Promise<ClaimsAdapter> = () => Promise.reject(new Error("auth not ready"));
  const auth = betterAuth({
    appName: "stem",
    baseURL: env.STEM_URL,
    basePath: "/api/auth",
    secret: env.BETTER_AUTH_SECRET,
    database: env.DB,
    trustedOrigins: [url.origin],
    // Passwordless: email codes and passkeys only. No password to phish, reuse or reset.
    emailAndPassword: { enabled: false },
    emailVerification: { autoSignInAfterVerification: true },
    user: {
      deleteUser: { enabled: true },
      changeEmail: { enabled: false },
    },
    session: {
      expiresIn: 60 * 60 * 24 * 30,
      updateAge: 60 * 60 * 24,
      freshAge: 60 * 15,
    },
    rateLimit: {
      enabled: true,
      storage: "database",
      window: 60,
      max: 60,
      customRules: {
        "/email-otp/send-verification-otp": { window: 600, max: 5 },
        "/sign-in/email-otp": { window: 300, max: 10 },
        "/email-otp/verify-email": { window: 300, max: 10 },
        "/passkey/*": { window: 60, max: 20 },
        "/oauth2/token": { window: 60, max: 60 },
      },
    },
    advanced: {
      useSecureCookies: url.protocol === "https:",
      cookiePrefix: "stem",
      // Host-only cookies on the stem origin. Apps never see them: they get tokens through OpenID Connect.
      crossSubDomainCookies: { enabled: false },
      defaultCookieAttributes: { sameSite: "lax", httpOnly: true, secure: url.protocol === "https:", path: "/" },
      ipAddress: { ipAddressHeaders: ["cf-connecting-ip"] },
      database: { generateId: () => crypto.randomUUID() },
    },
    hooks: {
      // The operator API registers clients through Better Auth's admin endpoint, which wants a session.
      // It gets a synthetic operator session, only for server-side calls that carry the operator token.
      before: createAuthMiddleware(async (ctx) => {
        if (ctx.path !== "/admin/oauth2/create-client" || !isOperator(env, ctx.headers)) return;
        const now = new Date();
        ctx.context.session = {
          session: { id: "operator", token: "operator", userId: "operator", expiresAt: new Date(now.getTime() + 60_000), createdAt: now, updatedAt: now },
          user: { id: "operator", email: "operator@stem.invalid", name: "stem operator", emailVerified: true, createdAt: now, updatedAt: now },
        } as never;
      }),
    },
    plugins: [
      ...(turnstile
        ? [captcha({ provider: "cloudflare-turnstile", secretKey: env.TURNSTILE_SECRET!, endpoints: ["/email-otp/send-verification-otp"], allowedHostnames: [url.hostname] })]
        : []),
      emailOTP({
        otpLength: 6,
        expiresIn: 600,
        allowedAttempts: 5,
        storeOTP: "hashed",
        sendVerificationOnSignUp: false,
        async sendVerificationOTP({ email, otp, type }) {
          background(exec, sendMail(env, codeMail(email, otp, type)));
        },
      }),
      passkey({
        rpID: url.hostname,
        rpName: "stem",
        origin: url.origin,
        authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      }),
      organization({
        ac,
        roles,
        creatorRole: "owner",
        // Organizations belong to an app and are created through the operator API.
        allowUserToCreateOrganization: false,
        invitationExpiresIn: 60 * 60 * 24 * 7,
        cancelPendingInvitationsOnReInvite: true,
        requireEmailVerificationOnInvitation: true,
        schema: {
          organization: { additionalFields: { app: { type: "string", required: false, input: false } } },
          invitation: { additionalFields: { redirectTo: { type: "string", required: false, input: false } } },
        },
        async sendInvitationEmail({ id, email, organization: org, inviter }) {
          const link = `${url.origin}/invite/${encodeURIComponent(id)}`;
          background(exec, sendMail(env, inviteMail(email, org.name, inviter?.user?.name || null, link)));
        },
      }),
      jwt({
        jwks: { keyPairConfig: { alg: "EdDSA", crv: "Ed25519" } },
        jwt: { issuer: url.origin, expirationTime: "10m" },
        // Clients use OpenID Connect tokens; the /token session-to-JWT shortcut is not needed.
        disableSettingJwtHeader: true,
      }),
      oauthProvider({
        loginPage: "/sign-in",
        consentPage: "/consent",
        scopes: [...SCOPES, DIRECTORY_SCOPE],
        clientRegistrationDefaultScopes: [...SCOPES],
        resources: [...resourceList(env), directoryAudience(env)],
        resourceSeedScope: "process",
        accessTokenExpiresIn: ACCESS_TOKEN_TTL,
        m2mAccessTokenExpiresIn: 300,
        refreshTokenExpiresIn: 60 * 60 * 24 * 30,
        storeClientSecret: "hashed",
        allowDynamicClientRegistration: false,
        // Only the operator registers clients; signed-in users can't.
        clientPrivileges: ({ headers }) => isOperator(env, headers),
        clientReference: () => "operator",
        async customAccessTokenClaims({ user, scopes, metadata }) {
          if (!user) return {};
          const claims: Record<string, unknown> = {};
          if (scopes.includes("email")) Object.assign(claims, { email: user.email, email_verified: user.emailVerified });
          if (scopes.includes("profile") && user.name) claims.name = user.name;
          const app = typeof metadata?.app === "string" ? metadata.app : null;
          if (app && scopes.includes("orgs")) claims.orgs = await orgClaims(await adapter(), user.id, app);
          return claims;
        },
        async customIdTokenClaims({ user, scopes, metadata }) {
          const app = typeof metadata?.app === "string" ? metadata.app : null;
          if (!app || !scopes.includes("orgs")) return {};
          return { orgs: await orgClaims(await adapter(), user.id, app) };
        },
      }),
    ],
  });
  adapter = async () => (await auth.$context).adapter as unknown as ClaimsAdapter;
  return auth;
}

export type Auth = ReturnType<typeof createAuth>;
