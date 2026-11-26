// SPDX-License-Identifier: AGPL-3.0-or-later

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  /** Cloudflare Email Sending. Without it, codes are only logged on localhost and sending fails elsewhere. */
  EMAIL?: SendEmail;
  /** Per IP and minute: sign-in attempts (codes, passkeys). */
  AUTH_RL?: RateLimit;
  /** Per IP and minute: directory and operator API calls. */
  API_RL?: RateLimit;

  /** Public origin of this deployment, e.g. https://stem.example.com. Also the OpenID Connect issuer. */
  STEM_URL: string;
  /** 32+ random bytes. Signs sessions and encrypts the JWKS private keys. */
  BETTER_AUTH_SECRET: string;
  /** Bearer token for the operator API (create apps, clients and organizations). Unset disables it. */
  OPERATOR_TOKEN?: string;
  /** Sender for sign-in codes and invitations, e.g. "stem <login@example.com>". */
  EMAIL_FROM?: string;
  /** Turnstile for the "send me a code" step. Both must be set to enable it. */
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET?: string;
  /** Extra organization roles besides owner, admin and member, comma separated (e.g. "dispatcher,pilot"). */
  ORG_ROLES?: string;
  /** Protected APIs that get signed JWT access tokens, comma separated absolute URIs. */
  RESOURCES?: string;
  /** Operator details for the imprint and privacy policy, as JSON. Legal pages are hidden when unset. */
  LEGAL?: string;
  /** Mandates (docs/mandates.md): one Durable Object per root mandate. Without it, mandates are off. */
  MANDATE?: DurableObjectNamespace<import("./mandates/object").Mandate>;
  /** Apps that take mandates and their actions, as JSON. See docs/mandates.md. Unset means mandates are off. */
  MANDATE_APPS?: string;
  /** Origins of app pages that may fetch passes for signed-in people, comma separated (e.g. "https://convert.example.com"). */
  PASS_ORIGINS?: string;
  /** Passes per account and UTC day. Default 50. */
  PASSES_PER_DAY?: string;
  /** "true" logs sign-in codes to the console instead of sending them. Only honored when STEM_URL is localhost. */
  DEV_LOG_EMAIL?: string;
}
