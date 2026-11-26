// SPDX-License-Identifier: AGPL-3.0-or-later
// mandates(): a power of attorney the person's passkey signs. An agent asks for exact rights, the
// person reads them on stem's approval page and signs with a passkey (the WebAuthn challenge is the
// hash of the mandate), stem checks that signature and countersigns. See docs/mandates.md.
import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint, sessionMiddleware, APIError } from "better-auth/api";
import { signJWT } from "better-auth/plugins/jwt";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import { decodeCredentialPublicKey } from "@simplewebauthn/server/helpers";
import { jwtVerify, EmbeddedJWK, calculateJwkThumbprint, decodeProtectedHeader, type JWK } from "jose";
import type { Env } from "../env";
import { MANDATE_TYP, parseRights, rootChallenge, verifyHumanProof, b64u, type Right, type Budget, type HumanProof } from "./verify";

export const REQUEST_TYP = "mandate-request+jwt";
/** How long a person has to approve a request. */
export const REQUEST_TTL_S = 600;
export const MAX_TTL_S = 60 * 60 * 24 * 30;
export const MAX_DEPTH = 4;
const CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ";

/** What an app accepts in a mandate, from MANDATE_APPS: {"https://drop.example.com": {"name": "drop",
 * "actions": {"upload": "Upload files", ...}}}. Requests for anything else are refused. */
export type MandateApps = Record<string, { name: string; actions: Record<string, string> }>;
export function mandateApps(env: Env): MandateApps {
  if (!env.MANDATE_APPS) return {};
  try {
    const raw = JSON.parse(env.MANDATE_APPS) as Record<string, { name?: unknown; actions?: unknown }>;
    const out: MandateApps = {};
    for (const [origin, v] of Object.entries(raw || {})) {
      let o: string;
      try { o = new URL(origin).origin; } catch { continue; }
      if (!v || typeof v.name !== "string" || !v.actions || typeof v.actions !== "object") continue;
      const actions: Record<string, string> = {};
      for (const [a, label] of Object.entries(v.actions as Record<string, unknown>)) if (typeof label === "string") actions[a] = label;
      out[o] = { name: v.name, actions };
    }
    return out;
  } catch {
    console.error("[stem] MANDATE_APPS is not valid JSON");
    return {};
  }
}

export const mandatesEnabled = (env: Env) => !!env.MANDATE && Object.keys(mandateApps(env)).length > 0;

type Db = {
  create<T>(q: { model: string; data: Record<string, unknown>; forceAllowId?: boolean }): Promise<T>;
  findOne<T>(q: { model: string; where: { field: string; value: unknown; operator?: "lt" | "gt" | "in" }[] }): Promise<T | null>;
  findMany<T>(q: { model: string; where?: { field: string; value: unknown; operator?: "lt" | "gt" | "in" }[]; limit?: number; sortBy?: { field: string; direction: "asc" | "desc" } }): Promise<T[]>;
  update<T>(q: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }): Promise<T | null>;
  deleteMany(q: { model: string; where: { field: string; value: unknown; operator?: "lt" | "gt" }[] }): Promise<unknown>;
};

export type RequestTerms = { rights: Right[]; purpose: string; ttl: number; del_max_depth: number; budget: Budget };
export type RequestRow = {
  id: string;
  userCode: string;
  agentJwk: string;
  agentThumbprint: string;
  terms: string;
  status: "pending" | "approved" | "denied";
  userId?: string | null;
  core?: string | null;
  token?: string | null;
  mandateId?: string | null;
  createdAt: Date;
  expiresAt: Date;
};
export type MandateRow = { id: string; userId: string; purpose: string; rights: string; agentThumbprint: string; passkeyId: string; status: string; createdAt: Date; expiresAt: Date; revokedAt?: Date | null };
type PasskeyRow = { id: string; userId: string; credentialID: string; publicKey: string; counter: number; transports?: string | null; name?: string | null };

const bad = (message: string, code = "INVALID_REQUEST") => new APIError("BAD_REQUEST", { code, message });
const str = (v: unknown, max = 200) => (typeof v === "string" && v.length > 0 && v.length <= max ? v : null);
const nat = (v: unknown) => (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : null);

function userCode() {
  const b = crypto.getRandomValues(new Uint8Array(8));
  const c = [...b].map((x) => CODE_ALPHABET[x % CODE_ALPHABET.length]).join("");
  return `${c.slice(0, 4)}-${c.slice(4)}`;
}

/** Checks what an agent asks for against MANDATE_APPS. */
export function parseTerms(apps: MandateApps, p: Record<string, unknown>): RequestTerms {
  let rights: Right[];
  try {
    rights = parseRights(p.authorization_details);
  } catch (e) {
    throw bad((e as Error).message);
  }
  for (const r of rights)
    for (const l of r.locations) {
      const app = apps[l];
      if (!app) throw bad(`${l} doesn't take mandates`, "UNKNOWN_APP");
      for (const a of r.actions) if (!app.actions[a]) throw bad(`${app.name} has no action "${a}"`, "UNKNOWN_ACTION");
    }
  const purpose = str(p.purpose);
  if (!purpose) throw bad("purpose is required (up to 200 characters): the person reads it before signing");
  const ttl = p.ttl === undefined ? 86400 : nat(p.ttl);
  if (ttl === null || ttl < 60 || ttl > MAX_TTL_S) throw bad(`ttl must be between 60 and ${MAX_TTL_S} seconds`);
  const depth = p.del_max_depth === undefined ? 0 : nat(p.del_max_depth);
  if (depth === null || depth > MAX_DEPTH) throw bad(`del_max_depth must be between 0 and ${MAX_DEPTH}`);
  const budget: Budget = {};
  const b = (p.budget || {}) as Record<string, unknown>;
  if (typeof b !== "object") throw bad("budget must be an object");
  for (const k of Object.keys(b)) if (k !== "bytes" && k !== "calls") throw bad(`unknown budget field ${k}`);
  if (b.bytes !== undefined) { const v = nat(b.bytes); if (v === null) throw bad("budget.bytes must be a whole number"); budget.bytes = v; }
  if (b.calls !== undefined) { const v = nat(b.calls); if (v === null) throw bad("budget.calls must be a whole number"); budget.calls = v; }
  return { rights, purpose, ttl, del_max_depth: depth, budget };
}

/** COSE public key (as Better Auth stores it, base64) → JWK, for the human proof inside the token. */
export function coseToJwk(stored: string): JWK {
  // COSE_Key (RFC 9052): 1 kty, -1 crv or n, -2 x or e, -3 y. kty 2 = EC2, 1 = OKP, 3 = RSA.
  const key = decodeCredentialPublicKey(Uint8Array.from(atob(stored), (c) => c.charCodeAt(0))) as unknown as Map<number, unknown>;
  const bytes = (k: number) => b64u(key.get(k) as Uint8Array);
  const kty = key.get(1), crv = key.get(-1);
  if (kty === 2 && crv === 1) return { kty: "EC", crv: "P-256", x: bytes(-2), y: bytes(-3) };
  if (kty === 1 && crv === 6) return { kty: "OKP", crv: "Ed25519", x: bytes(-2) };
  if (kty === 3) return { kty: "RSA", n: bytes(-1), e: bytes(-2) };
  throw new Error("unsupported passkey key type");
}

const mandateObject = (env: Env, id: string) => env.MANDATE!.get(env.MANDATE!.idFromName(id));

export const mandates = (env: Env) =>
  ({
    id: "stem-mandates",
    schema: {
      mandateRequest: {
        fields: {
          userCode: { type: "string", required: true },
          agentJwk: { type: "string", required: true },
          agentThumbprint: { type: "string", required: true },
          terms: { type: "string", required: true },
          status: { type: "string", required: true },
          userId: { type: "string", required: false, references: { model: "user", field: "id", onDelete: "cascade" } },
          core: { type: "string", required: false },
          token: { type: "string", required: false },
          mandateId: { type: "string", required: false },
          createdAt: { type: "date", required: true },
          expiresAt: { type: "date", required: true, index: true },
        },
      },
      mandate: {
        fields: {
          userId: { type: "string", required: true, references: { model: "user", field: "id", onDelete: "cascade" }, index: true },
          purpose: { type: "string", required: true },
          rights: { type: "string", required: true },
          agentThumbprint: { type: "string", required: true },
          passkeyId: { type: "string", required: true },
          status: { type: "string", required: true },
          createdAt: { type: "date", required: true },
          expiresAt: { type: "date", required: true },
          revokedAt: { type: "date", required: false },
        },
      },
    },
    endpoints: {
      /** An agent asks for a mandate. No session: the request is a JWT signed by the agent's own key. */
      requestMandate: createAuthEndpoint("/mandates/request", { method: "POST" }, async (ctx) => {
        if (!mandatesEnabled(env)) throw new APIError("NOT_FOUND", { message: "mandates are not enabled here" });
        const jwt = str((ctx.body as { request?: unknown })?.request, 16_384);
        if (!jwt) throw bad("send {request: <JWT signed by the agent key, with the public key in the jwk header>}");
        let header;
        try { header = decodeProtectedHeader(jwt); } catch { throw bad("request is not a JWT"); }
        if (header.typ !== REQUEST_TYP) throw bad(`request typ must be ${REQUEST_TYP}`);
        const { payload, protectedHeader } = await jwtVerify(jwt, EmbeddedJWK, { typ: REQUEST_TYP, algorithms: ["EdDSA", "ES256"], maxTokenAge: 300, clockTolerance: 30 }).catch((e) => {
          throw bad(`request signature: ${(e as Error).message}`);
        });
        const agentJwk = { ...(protectedHeader.jwk as JWK) };
        delete agentJwk.d;
        const terms = parseTerms(mandateApps(env), payload as Record<string, unknown>);
        const db = ctx.context.adapter as unknown as Db;
        const now = new Date();
        // Old requests go when new ones come; approved ones keep their token only until they expire.
        await db.deleteMany({ model: "mandateRequest", where: [{ field: "expiresAt", operator: "lt", value: now }] });
        const row = await db.create<RequestRow>({
          model: "mandateRequest",
          data: {
            userCode: userCode(),
            agentJwk: JSON.stringify(agentJwk),
            agentThumbprint: await calculateJwkThumbprint(agentJwk),
            terms: JSON.stringify(terms),
            status: "pending",
            createdAt: now,
            expiresAt: new Date(now.getTime() + REQUEST_TTL_S * 1000),
          },
        });
        const origin = new URL(env.STEM_URL).origin;
        return ctx.json({ request_id: row.id, user_code: row.userCode, approve_url: `${origin}/mandates/approve?request=${encodeURIComponent(row.id)}`, expires_in: REQUEST_TTL_S, interval: 3 });
      }),

      /** The agent picks up its mandate once the person signed. The token is bound to the agent's key,
       * so the request id alone is worth nothing to anyone else. */
      collectMandate: createAuthEndpoint("/mandates/collect", { method: "POST" }, async (ctx) => {
        const id = str((ctx.body as { request_id?: unknown })?.request_id, 64);
        if (!id) throw bad("request_id is required");
        const row = await (ctx.context.adapter as unknown as Db).findOne<RequestRow>({ model: "mandateRequest", where: [{ field: "id", value: id }] });
        if (!row || new Date(row.expiresAt).getTime() < Date.now()) return ctx.json({ status: "expired" });
        if (row.status === "approved" && row.token) return ctx.json({ status: "approved", mandate: row.token });
        return ctx.json({ status: row.status === "denied" ? "denied" : "pending" });
      }),

      /** The approval page asks for the exact mandate to sign: its hash becomes the WebAuthn challenge. */
      prepareMandate: createAuthEndpoint("/mandates/prepare", { method: "POST", use: [sessionMiddleware] }, async (ctx) => {
        const db = ctx.context.adapter as unknown as Db;
        const user = ctx.context.session.user;
        const row = await pendingRequest(db, (ctx.body as { request_id?: unknown })?.request_id, user.id);
        const passkeys = await db.findMany<PasskeyRow>({ model: "passkey", where: [{ field: "userId", value: user.id }], limit: 50 });
        if (!passkeys.length) throw bad("Add a passkey to your account first. A mandate is signed with one.", "NO_PASSKEY");
        const terms = JSON.parse(row.terms) as RequestTerms;
        const now = Math.floor(Date.now() / 1000);
        const origin = new URL(env.STEM_URL).origin;
        const core: Record<string, unknown> = {
          iss: origin,
          sub: user.id,
          aud: [...new Set(terms.rights.flatMap((r) => r.locations))],
          jti: crypto.randomUUID(),
          iat: now,
          exp: now + terms.ttl,
          cnf: { jwk: JSON.parse(row.agentJwk) },
          authorization_details: terms.rights,
          del_depth: 0,
          del_max_depth: terms.del_max_depth,
          purpose: terms.purpose,
        };
        if (Object.keys(terms.budget).length) core.budget = terms.budget;
        await db.update({ model: "mandateRequest", where: [{ field: "id", value: row.id }], update: { userId: user.id, core: JSON.stringify(core) } });
        return ctx.json({
          mandate: core,
          publicKey: {
            challenge: await rootChallenge(core),
            rpId: new URL(env.STEM_URL).hostname,
            allowCredentials: passkeys.map((p) => ({ id: p.credentialID, type: "public-key", transports: p.transports ? p.transports.split(",") : undefined })),
            userVerification: "required",
            timeout: 120_000,
          },
        });
      }),

      /** The person signed: check the passkey signed exactly this mandate, then countersign it. */
      approveMandate: createAuthEndpoint("/mandates/approve", { method: "POST", use: [sessionMiddleware] }, async (ctx) => {
        const db = ctx.context.adapter as unknown as Db;
        const user = ctx.context.session.user;
        const body = ctx.body as { request_id?: unknown; response?: { id?: unknown; response?: Record<string, unknown> } };
        const row = await pendingRequest(db, body?.request_id, user.id);
        if (!row.core || row.userId !== user.id) throw bad("Prepare the mandate first.", "NOT_PREPARED");
        const core = JSON.parse(row.core) as Record<string, unknown> & { jti: string; exp: number; budget?: Budget };
        const resp = body.response;
        const credentialId = str(resp?.id, 1024);
        if (!credentialId || !resp?.response) throw bad("response is the passkey assertion");
        const pk = await db.findOne<PasskeyRow>({ model: "passkey", where: [{ field: "credentialID", value: credentialId }] });
        if (!pk || pk.userId !== user.id) throw bad("That passkey isn't on your account.", "PASSKEY_NOT_FOUND");
        const challenge = await rootChallenge(core);
        const origin = new URL(env.STEM_URL).origin;
        const rpId = new URL(env.STEM_URL).hostname;
        const v = await verifyAuthenticationResponse({
          response: resp as never,
          expectedChallenge: challenge,
          expectedOrigin: origin,
          expectedRPID: rpId,
          credential: { id: pk.credentialID, publicKey: Uint8Array.from(atob(pk.publicKey), (c) => c.charCodeAt(0)), counter: pk.counter, transports: pk.transports ? (pk.transports.split(",") as never) : undefined },
          requireUserVerification: true,
        }).catch(() => ({ verified: false as const, authenticationInfo: undefined }));
        if (!v.verified || !v.authenticationInfo) throw bad("The passkey didn't sign this mandate.", "SIGNATURE_INVALID");
        await db.update({ model: "passkey", where: [{ field: "id", value: pk.id }], update: { counter: v.authenticationInfo.newCounter } });
        const a = resp.response as { authenticatorData: string; clientDataJSON: string; signature: string };
        const hp: HumanProof = { id: credentialId, jwk: coseToJwk(pk.publicKey), authenticatorData: a.authenticatorData, clientDataJSON: a.clientDataJSON, signature: a.signature };
        // The same check every app runs. If stem's own verifier refuses, nobody gets a token.
        await verifyHumanProof(hp, challenge, origin, rpId).catch((e) => {
          throw bad(`The passkey proof doesn't verify: ${(e as Error).message}`, "SIGNATURE_INVALID");
        });
        const jwtPlugin = ctx.context.getPlugin("jwt") as { options?: unknown } | null;
        const token = await signJWT(ctx as never, { options: jwtPlugin?.options as never, payload: { ...core, hp } as never, header: { typ: MANDATE_TYP } as never });
        const terms = JSON.parse(row.terms) as RequestTerms;
        await db.create({
          model: "mandate",
          data: { id: core.jti, userId: user.id, purpose: terms.purpose, rights: JSON.stringify(terms.rights), agentThumbprint: row.agentThumbprint, passkeyId: pk.id, status: "active", createdAt: new Date(), expiresAt: new Date(core.exp * 1000) },
          forceAllowId: true,
        });
        await mandateObject(env, core.jti).open(core.exp, core.budget || {});
        await db.update({ model: "mandateRequest", where: [{ field: "id", value: row.id }], update: { status: "approved", token, mandateId: core.jti } });
        return ctx.json({ approved: true, mandate_id: core.jti });
      }),

      denyMandate: createAuthEndpoint("/mandates/deny", { method: "POST", use: [sessionMiddleware] }, async (ctx) => {
        const db = ctx.context.adapter as unknown as Db;
        const row = await pendingRequest(db, (ctx.body as { request_id?: unknown })?.request_id, ctx.context.session.user.id);
        await db.update({ model: "mandateRequest", where: [{ field: "id", value: row.id }], update: { status: "denied", userId: ctx.context.session.user.id } });
        return ctx.json({ denied: true });
      }),

      /** "Your agents" on the account page: every mandate with its live state. */
      listMandates: createAuthEndpoint("/mandates/list", { method: "GET", use: [sessionMiddleware] }, async (ctx) => {
        ctx.setHeader("cache-control", "no-store");
        const db = ctx.context.adapter as unknown as Db;
        const rows = await db.findMany<MandateRow>({ model: "mandate", where: [{ field: "userId", value: ctx.context.session.user.id }], limit: 100, sortBy: { field: "createdAt", direction: "desc" } });
        const apps = mandateApps(env);
        const out = await Promise.all(
          rows.map(async (m) => {
            const rights = JSON.parse(m.rights) as Right[];
            const expired = new Date(m.expiresAt).getTime() < Date.now();
            const live = env.MANDATE && m.status === "active" && !expired ? await mandateObject(env, m.id).status().catch(() => null) : null;
            return {
              id: m.id,
              purpose: m.purpose,
              status: live?.status || (m.status === "active" && expired ? "expired" : m.status),
              created_at: new Date(m.createdAt).toISOString(),
              expires_at: new Date(m.expiresAt).toISOString(),
              remaining: live?.remaining || null,
              calls: live?.calls ?? null,
              rights: rights.map((r) => ({ ...r, apps: r.locations.map((l) => apps[l]?.name || new URL(l).host) })),
            };
          }),
        );
        return ctx.json(out);
      }),

      /** The stop button. Every token in the tree fails on its next call. */
      revokeMandate: createAuthEndpoint("/mandates/revoke", { method: "POST", use: [sessionMiddleware] }, async (ctx) => {
        const db = ctx.context.adapter as unknown as Db;
        const m = await ownMandate(db, (ctx.body as { id?: unknown })?.id, ctx.context.session.user.id);
        if (env.MANDATE) await mandateObject(env, m.id).revoke();
        await db.update({ model: "mandate", where: [{ field: "id", value: m.id }], update: { status: "revoked", revokedAt: new Date() } });
        return ctx.json({ revoked: true });
      }),

      mandateTrail: createAuthEndpoint("/mandates/trail", { method: "GET", use: [sessionMiddleware] }, async (ctx) => {
        ctx.setHeader("cache-control", "no-store");
        const db = ctx.context.adapter as unknown as Db;
        const m = await ownMandate(db, (ctx.query as { id?: unknown } | undefined)?.id, ctx.context.session.user.id);
        return ctx.json(env.MANDATE ? await mandateObject(env, m.id).trail(100) : []);
      }),
    },
    rateLimit: [
      { pathMatcher: (p: string) => p === "/mandates/request", window: 60, max: 10 },
      { pathMatcher: (p: string) => p === "/mandates/collect", window: 60, max: 40 },
    ],
  }) satisfies BetterAuthPlugin;

async function pendingRequest(db: Db, rawId: unknown, userId: string) {
  const id = str(rawId, 64);
  if (!id) throw bad("request_id is required");
  const row = await db.findOne<RequestRow>({ model: "mandateRequest", where: [{ field: "id", value: id }] });
  if (!row || new Date(row.expiresAt).getTime() < Date.now()) throw new APIError("NOT_FOUND", { code: "REQUEST_EXPIRED", message: "This request has expired. Ask the agent for a new link." });
  if (row.status !== "pending") throw bad("This request was already answered.", "ALREADY_ANSWERED");
  // Once someone opened it, it's theirs: nobody else can sign it in between.
  if (row.userId && row.userId !== userId) throw new APIError("NOT_FOUND", { code: "REQUEST_EXPIRED", message: "This request has expired. Ask the agent for a new link." });
  return row;
}

async function ownMandate(db: Db, rawId: unknown, userId: string) {
  const id = str(rawId, 64);
  if (!id) throw bad("id is required");
  const m = await db.findOne<MandateRow>({ model: "mandate", where: [{ field: "id", value: id }] });
  if (!m || m.userId !== userId) throw new APIError("NOT_FOUND", { message: "No such mandate." });
  return m;
}
