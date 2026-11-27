// SPDX-License-Identifier: AGPL-3.0-or-later
// One call that answers "may this request go ahead?" for apps: the offline chain check (./verify.ts),
// the call against the rights at the end of the chain, then the live check in the mandate's object.
// Apps on the same Cloudflare account call it over a service binding (MandateGateway); others over
// HTTP (POST /api/mandates/authorize). Apps may also run ./verify.ts themselves first.
import { WorkerEntrypoint } from "cloudflare:workers";
import type { JSONWebKeySet } from "jose";
import type { Env } from "../env";
import { createAuth } from "../auth";
import { verifyMandate, allows, MandateError, type Right, type Budget } from "./verify";
import type { Outcome, MandateStatus } from "./object";
import type { MandateRow } from "./plugin";

export type AuthorizeInput = {
  /** The tokens from "Authorization: Mandate a~b~c", in order. */
  chain: string[];
  /** The Mandate-PoP header. */
  pop: string;
  /** The request being authorized. */
  method: string;
  url: string;
  /** What the app maps the request to: one of its actions, the name or path it touches, its size. */
  action: string;
  path?: string;
  bytes?: number;
};

export type AuthorizeResult =
  | { allowed: true; mandate: string; sub: string; purpose: string; holder: string; depth: number; rights: Right[]; remaining: Budget; exp: number }
  | { allowed: false; reason: Outcome | "outside_mandate" | string; message: string; mandate?: string };

const MESSAGES: Record<string, string> = {
  revoked: "This mandate was stopped by the person who signed it.",
  expired: "This mandate has expired.",
  unknown: "stem doesn't know this mandate.",
  over_budget: "This would go over the budget the mandate shares across all its agents.",
  replayed: "This proof of possession was already used. Sign a new one for every request.",
  outside_mandate: "The mandate doesn't cover this request.",
};

let cached: { at: number; jwks: JSONWebKeySet } | null = null;
/** stem's own public keys. Cached per isolate for a minute; a rotation shows up within that. */
async function ownJwks(env: Env): Promise<JSONWebKeySet> {
  if (cached && Date.now() - cached.at < 60_000) return cached.jwks;
  const jwks = (await createAuth(env).api.getJwks()) as unknown as JSONWebKeySet;
  cached = { at: Date.now(), jwks };
  return jwks;
}

export async function authorize(env: Env, i: AuthorizeInput): Promise<AuthorizeResult> {
  if (!env.MANDATE) return { allowed: false, reason: "disabled", message: "Mandates are not enabled on this stem." };
  if (!i || !Array.isArray(i.chain) || typeof i.pop !== "string" || typeof i.method !== "string" || typeof i.url !== "string" || typeof i.action !== "string")
    return { allowed: false, reason: "invalid_request", message: "chain, pop, method, url and action are required" };
  const bytes = typeof i.bytes === "number" && Number.isFinite(i.bytes) && i.bytes >= 0 ? Math.ceil(i.bytes) : 0;
  let v;
  try {
    v = await verifyMandate(i.chain, i.pop, { jwks: await ownJwks(env), issuer: env.STEM_URL, method: i.method, url: i.url });
  } catch (e) {
    if (e instanceof MandateError) return { allowed: false, reason: e.code, message: e.message };
    throw e;
  }
  const location = new URL(i.url).origin;
  if (!allows(v.rights, { location, action: i.action, path: i.path, bytes })) return { allowed: false, reason: "outside_mandate", message: MESSAGES.outside_mandate, mandate: v.mandate };
  const live = await env.MANDATE.get(env.MANDATE.idFromName(v.mandate)).use({ holder: v.holder, depth: v.depth, action: i.action, path: i.path, bytes, popJti: v.pop.jti, popIat: v.pop.iat, location });
  if (live.outcome !== "allowed") return { allowed: false, reason: live.outcome, message: MESSAGES[live.outcome] || live.outcome, mandate: v.mandate };
  return { allowed: true, mandate: v.mandate, sub: v.sub, purpose: v.purpose, holder: v.holder, depth: v.depth, rights: v.rights, remaining: live.remaining, exp: v.exp };
}

export type StatusResult = { status: MandateStatus["status"]; created_at: string | null; expires_at: string | null; revoked_at: string | null };

const UNKNOWN: StatusResult = { status: "unknown", created_at: null, expires_at: null, revoked_at: null };

/** Whether a mandate still stands, for an app that kept its id from an earlier authorize() and wants
 * to show it: "signed on the 3rd, stopped on the 9th". No chain, no proof, nothing in the trail, and
 * nothing about the person. Never a reason to let a request through: that is what authorize() is for.
 * Starts from stem's own list, so asking about an id nobody issued doesn't create an object for it. */
export async function status(env: Env, id: unknown): Promise<StatusResult> {
  if (!env.MANDATE || typeof id !== "string" || !/^[0-9a-f-]{36}$/i.test(id)) return UNKNOWN;
  const db = (await createAuth(env).$context).adapter;
  const m = await db.findOne<MandateRow>({ model: "mandate", where: [{ field: "id", value: id }] });
  if (!m) return UNKNOWN;
  const iso = (d: Date | string | null | undefined) => (d ? new Date(d).toISOString() : null);
  let state: StatusResult["status"] = m.status === "revoked" ? "revoked" : new Date(m.expiresAt).getTime() < Date.now() ? "expired" : "active";
  // The object has the last word while the list says active: a stop reaches it first.
  if (state === "active") state = (await env.MANDATE.get(env.MANDATE.idFromName(m.id)).status().catch(() => null))?.status ?? state;
  return { status: state, created_at: iso(m.createdAt), expires_at: iso(m.expiresAt), revoked_at: iso(m.revokedAt) };
}

/** Named entrypoint for app Workers on the same account:
 * `services: [{ binding: "MANDATES", service: "stem", entrypoint: "MandateGateway" }]`. */
export class MandateGatewayBase extends WorkerEntrypoint<Env> {
  authorize(input: AuthorizeInput) {
    return authorize(this.env, input);
  }
  status(mandate: string) {
    return status(this.env, mandate);
  }
  jwks() {
    return ownJwks(this.env);
  }
}
