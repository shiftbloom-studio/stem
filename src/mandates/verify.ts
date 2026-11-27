// SPDX-License-Identifier: AGPL-3.0-or-later
// Mandates: what an app runs to check one. Needs stem's public keys (its JWKS) and nothing else:
// no database, no call to stem. Self-contained on purpose (jose and WebCrypto only), so an app can
// copy this file. The live half (stop button, shared budget, replay check) is in ./object.ts.
//
// A request carries a chain of JWTs and a proof of possession:
//   Authorization: Mandate <root>~<child>~<grandchild>
//   Mandate-PoP: <JWT signed by the key of the last token in the chain>
// The root is countersigned by stem and carries the person's passkey assertion over the hash of its
// own claims. Each child is signed by the key its parent names in `cnf` and may only carry less.
// Claim names follow the IETF individual drafts on attenuating agent tokens and agent delegation
// chains (October 2026): cnf, par_hash, del_depth, del_max_depth, authorization_details.
import { jwtVerify, createLocalJWKSet, importJWK, calculateJwkThumbprint, decodeProtectedHeader, type JWK, type JSONWebKeySet, type JWTPayload } from "jose";

export const MANDATE_TYP = "mandate+jwt";
export const POP_TYP = "mandate-pop+jwt";
export const RIGHT_TYPE = "stem_mandate";
/** How old a proof of possession may be, in seconds. stem's replay check remembers proofs this long. */
export const POP_MAX_AGE = 60;
/** Clock skew allowed on iat and exp, in seconds. */
const SKEW = 30;

/** One entry of authorization_details (RFC 9396). Everything a holder may do at one app. */
export type Right = {
  type: typeof RIGHT_TYPE;
  /** App origins, e.g. ["https://drop.example.com"]. */
  locations: string[];
  /** App-defined verbs, e.g. ["upload", "list", "delete"]. */
  actions: string[];
  /** Only names (paths, file names) that start with this. Unset means everything. */
  path_prefix?: string;
  /** Largest single request body or file, in bytes. Unset means the app's own limit. */
  max_bytes?: number;
};

/** Budget shared by every token in one tree. Kept by the mandate's Durable Object, not in the tokens. */
export type Budget = { bytes?: number; calls?: number };

/** The person's passkey assertion over the root's claims. */
export type HumanProof = {
  /** Credential id (base64url). */
  id: string;
  /** The passkey's public key as a JWK. */
  jwk: JWK;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
};

export type Verified = {
  /** Id of the root mandate (its jti). Every token in the tree shares it. */
  mandate: string;
  /** stem user id of the person who signed. */
  sub: string;
  purpose: string;
  /** Rights at the end of the chain. */
  rights: Right[];
  /** How many hops below the root. */
  depth: number;
  /** Expiry of the end of the chain (seconds). */
  exp: number;
  /** JWK thumbprint of the key that signed the proof of possession. */
  holder: string;
  budget: Budget;
  pop: { jti: string; iat: number; htm: string; htu: string };
};

export class MandateError extends Error {
  constructor(public code: string, message: string) {
    super(message);
  }
}
const fail = (code: string, message: string): never => {
  throw new MandateError(code, message);
};

const te = new TextEncoder();
export const b64u = (b: Uint8Array) => {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/={1,2}$/, "");
};
export const unb64u = (s: string) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
export const sha256 = async (d: Uint8Array | string) => new Uint8Array(await crypto.subtle.digest("SHA-256", typeof d === "string" ? te.encode(d) : d));
export const sha256b64u = async (d: Uint8Array | string) => b64u(await sha256(d));

/** JSON Canonicalization Scheme (RFC 8785) for the values mandates use: sorted keys, no whitespace,
 * ECMAScript number and string serialization. Non-finite numbers are refused. */
export function canonicalize(v: unknown): string {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("canonicalize: non-finite number");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .filter((k) => o[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalize(o[k])}`)
      .join(",")}}`;
  }
  throw new Error(`canonicalize: unsupported ${typeof v}`);
}

/** The WebAuthn challenge for a root: SHA-256 of its canonical claims, without the human proof. */
export const rootChallenge = (core: Record<string, unknown>) => sha256b64u(canonicalize(core));

// ---------- rights ----------

const isStr = (v: unknown): v is string => typeof v === "string";
const isNat = (v: unknown): v is number => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const KNOWN = new Set(["type", "locations", "actions", "path_prefix", "max_bytes"]);

/** Checks the shape of authorization_details. Unknown fields are refused: a verifier that ignored a
 * restriction it doesn't understand would grant more than the signer meant. */
export function parseRights(v: unknown): Right[] {
  if (!Array.isArray(v) || !v.length || v.length > 16) fail("invalid_rights", "authorization_details must be a list of 1 to 16 entries");
  return (v as unknown[]).map((r) => {
    const o = r as Record<string, unknown>;
    if (!o || typeof o !== "object" || o.type !== RIGHT_TYPE) fail("invalid_rights", `every entry needs type "${RIGHT_TYPE}"`);
    for (const k of Object.keys(o)) if (!KNOWN.has(k)) fail("invalid_rights", `unknown field ${k}`);
    const locations = o.locations, actions = o.actions;
    if (!Array.isArray(locations) || !locations.length || !locations.every((l) => isStr(l) && /^https?:\/\/[^/?#]+$/.test(l))) fail("invalid_rights", "locations must be app origins");
    if (!Array.isArray(actions) || !actions.length || !actions.every((a) => isStr(a) && /^[a-z][a-z0-9_:.-]{0,63}$/.test(a))) fail("invalid_rights", "actions must be short lowercase names");
    if (o.path_prefix !== undefined && (!isStr(o.path_prefix) || o.path_prefix.length > 512)) fail("invalid_rights", "path_prefix must be a string");
    if (o.max_bytes !== undefined && !isNat(o.max_bytes)) fail("invalid_rights", "max_bytes must be a whole number");
    const out: Right = { type: RIGHT_TYPE, locations: [...(locations as string[])], actions: [...(actions as string[])] };
    if (o.path_prefix !== undefined) out.path_prefix = o.path_prefix as string;
    if (o.max_bytes !== undefined) out.max_bytes = o.max_bytes as number;
    return out;
  });
}

/** Whether one right is inside another: same or fewer apps and actions, a longer prefix, a smaller size. */
export function within(child: Right, parent: Right): boolean {
  if (!child.locations.every((l) => parent.locations.includes(l))) return false;
  if (!child.actions.every((a) => parent.actions.includes(a))) return false;
  if (parent.path_prefix !== undefined && (child.path_prefix === undefined || !child.path_prefix.startsWith(parent.path_prefix))) return false;
  if (parent.max_bytes !== undefined && (child.max_bytes === undefined || child.max_bytes > parent.max_bytes)) return false;
  return true;
}

/** A child's rights are narrower when every entry fits inside some entry of the parent. */
export const narrower = (child: Right[], parent: Right[]) => child.every((c) => parent.some((p) => within(c, p)));

export type Call = { location: string; action: string; path?: string; bytes?: number };

/** Whether the rights at the end of a chain allow one call. An app passes the path or name the call
 * touches; when a right has a prefix, a call without a path is refused. */
export function allows(rights: Right[], call: Call): boolean {
  return rights.some(
    (r) =>
      r.locations.includes(call.location) &&
      r.actions.includes(call.action) &&
      (r.path_prefix === undefined || (call.path !== undefined && call.path.startsWith(r.path_prefix))) &&
      (r.max_bytes === undefined || (call.bytes ?? 0) <= r.max_bytes),
  );
}

// ---------- the human proof ----------

const COSE_ALG: Record<string, { import: Parameters<SubtleCrypto["importKey"]>[2]; verify: Parameters<SubtleCrypto["verify"]>[0] }> = {
  ES256: { import: { name: "ECDSA", namedCurve: "P-256" }, verify: { name: "ECDSA", hash: "SHA-256" } },
  EdDSA: { import: { name: "Ed25519" }, verify: { name: "Ed25519" } },
  RS256: { import: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, verify: { name: "RSASSA-PKCS1-v1_5" } },
};

/** ECDSA signatures in WebAuthn are DER encoded; WebCrypto wants r and s as 32 bytes each. */
function derToRaw(der: Uint8Array): Uint8Array<ArrayBuffer> {
  if (der[0] !== 0x30) fail("invalid_human_proof", "signature is not DER");
  let i = 2;
  const int = () => {
    if (der[i] !== 0x02) fail("invalid_human_proof", "signature is not DER");
    const len = der[i + 1];
    let v = der.slice(i + 2, i + 2 + len);
    i += 2 + len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) fail("invalid_human_proof", "signature is not DER");
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = int(), s = int();
  const raw = new Uint8Array(64);
  raw.set(r);
  raw.set(s, 32);
  return raw;
}

const algOfJwk = (jwk: JWK) => (jwk.kty === "EC" && jwk.crv === "P-256" ? "ES256" : jwk.kty === "OKP" && jwk.crv === "Ed25519" ? "EdDSA" : jwk.kty === "RSA" ? "RS256" : null);

/** Checks a WebAuthn assertion as a signature over `challenge`: right origin and RP, user present
 * and verified (PIN or biometric), and a valid signature by the passkey. */
export async function verifyHumanProof(hp: HumanProof, challenge: string, origin: string, rpId: string): Promise<void> {
  if (!hp || typeof hp !== "object" || !isStr(hp.id) || !isStr(hp.authenticatorData) || !isStr(hp.clientDataJSON) || !isStr(hp.signature) || !hp.jwk) fail("invalid_human_proof", "the passkey proof is incomplete");
  let client: { type?: string; challenge?: string; origin?: string; crossOrigin?: boolean };
  try {
    client = JSON.parse(new TextDecoder().decode(unb64u(hp.clientDataJSON)));
  } catch {
    return fail("invalid_human_proof", "clientDataJSON is not JSON");
  }
  if (client.type !== "webauthn.get") fail("invalid_human_proof", "not an assertion");
  if (client.challenge !== challenge) fail("invalid_human_proof", "the passkey signed something else");
  if (client.origin !== origin || client.crossOrigin) fail("invalid_human_proof", "signed on another site");
  const auth = unb64u(hp.authenticatorData);
  if (auth.length < 37) fail("invalid_human_proof", "authenticator data is too short");
  if (b64u(auth.slice(0, 32)) !== (await sha256b64u(rpId))) fail("invalid_human_proof", "signed for another relying party");
  const flags = auth[32];
  if (!(flags & 0x01)) fail("invalid_human_proof", "user was not present");
  if (!(flags & 0x04)) fail("invalid_human_proof", "user was not verified");
  const alg = algOfJwk(hp.jwk);
  if (!alg) fail("invalid_human_proof", "unsupported passkey type");
  const a = COSE_ALG[alg!];
  const key = await crypto.subtle.importKey("jwk", hp.jwk as JsonWebKey, a.import, false, ["verify"]);
  const data = new Uint8Array(auth.length + 32);
  data.set(auth);
  data.set(await sha256(unb64u(hp.clientDataJSON)), auth.length);
  let sig: Uint8Array<ArrayBuffer> = unb64u(hp.signature);
  if (alg === "ES256") sig = derToRaw(sig);
  if (!(await crypto.subtle.verify(a.verify, key, sig, data))) fail("invalid_human_proof", "the passkey signature is wrong");
}

// ---------- the chain ----------

const holderKey = (p: JWTPayload) => {
  const jwk = (p.cnf as { jwk?: JWK } | undefined)?.jwk;
  if (!jwk || typeof jwk !== "object" || jwk.d) fail("invalid_chain", "token names no public key in cnf");
  return jwk!;
};

export function parseAuthorization(header: string | null | undefined): string[] | null {
  const m = /^Mandate\s+(\S+)$/i.exec((header || "").trim());
  if (!m) return null;
  const chain = m[1].split("~").filter(Boolean);
  return chain.length && chain.length <= 8 ? chain : null;
}

export type VerifyOptions = {
  /** stem's JWKS (GET {issuer}/api/auth/jwks). */
  jwks: JSONWebKeySet;
  /** stem's origin, e.g. https://stem.example.com. */
  issuer: string;
  /** The request being authorized: method and full URL. The proof of possession must name both. */
  method: string;
  url: string;
  now?: number;
};

/** Verifies a whole chain and its proof of possession. Throws MandateError, or returns the rights
 * at the end of the chain. Does not check the live state: ask the mandate's object for that. */
export async function verifyMandate(chain: string[], pop: string, o: VerifyOptions): Promise<Verified> {
  const now = o.now ?? Math.floor(Date.now() / 1000);
  if (!chain.length || chain.length > 8) fail("invalid_chain", "a chain has 1 to 8 tokens");
  const issuer = new URL(o.issuer).origin;
  const keys = createLocalJWKSet(o.jwks);
  const opts = { typ: MANDATE_TYP, algorithms: ["EdDSA", "ES256"], currentDate: new Date(now * 1000), clockTolerance: SKEW };

  // The root: stem's signature, then the person's.
  const { payload: root } = await jwtVerify(chain[0], keys, { ...opts, issuer }).catch((e) => fail("invalid_chain", `root: ${(e as Error).message}`));
  const { hp, ...core } = root as JWTPayload & { hp?: HumanProof };
  await verifyHumanProof(hp as HumanProof, await rootChallenge(core), issuer, new URL(issuer).hostname);
  if (!isStr(root.jti) || !isStr(root.sub) || !isNat(root.exp)) fail("invalid_chain", "root lacks jti, sub or exp");
  if (root.del_depth !== 0 || !isNat(root.del_max_depth)) fail("invalid_chain", "root depth claims are wrong");
  let rights = parseRights(root.authorization_details);
  let holder = holderKey(root);
  let exp = root.exp as number;
  let prev = chain[0];

  // Each child: signed by its parent's key, bound to its parent, never wider, deeper or longer.
  for (let i = 1; i < chain.length; i++) {
    const alg = (() => {
      try {
        return decodeProtectedHeader(chain[i]).alg;
      } catch {
        return undefined;
      }
    })();
    const { payload: p } = await jwtVerify(chain[i], await importJWK(holder, alg), opts).catch((e) => fail("invalid_chain", `hop ${i}: ${(e as Error).message}`));
    if (p.par_hash !== (await sha256b64u(prev))) fail("invalid_chain", `hop ${i} is not bound to its parent`);
    if (p.del_depth !== i || i > (root.del_max_depth as number)) fail("too_deep", `hop ${i} is deeper than the mandate allows`);
    if (!isNat(p.exp) || (p.exp as number) > exp) fail("invalid_chain", `hop ${i} outlives its parent`);
    const r = parseRights(p.authorization_details);
    if (!narrower(r, rights)) fail("wider_than_parent", `hop ${i} asks for more than its parent holds`);
    rights = r;
    holder = holderKey(p);
    exp = p.exp as number;
    prev = chain[i];
  }

  // The proof of possession: the holder of the last key, for exactly this request, just now.
  let popAlg: string | undefined;
  try {
    popAlg = decodeProtectedHeader(pop).alg;
  } catch {
    fail("invalid_pop", "proof of possession is not a JWT");
  }
  const { payload: c } = await jwtVerify(pop, await importJWK(holder, popAlg), { typ: POP_TYP, currentDate: new Date(now * 1000), clockTolerance: SKEW }).catch(() =>
    fail("invalid_pop", "proof of possession is not signed by the holder of the chain"),
  );
  if (c.ath !== (await sha256b64u(prev))) fail("invalid_pop", "proof of possession is for another chain");
  if (!isStr(c.jti) || c.jti.length < 16 || c.jti.length > 128) fail("invalid_pop", "proof of possession needs a jti");
  if (!isNat(c.iat) || (c.iat as number) > now + SKEW || (c.iat as number) < now - POP_MAX_AGE) fail("invalid_pop", "proof of possession is too old or from the future");
  if (!isStr(c.htm) || c.htm.toUpperCase() !== o.method.toUpperCase()) fail("invalid_pop", "proof of possession is for another method");
  const u = new URL(o.url);
  if (!isStr(c.htu) || c.htu !== `${u.origin}${u.pathname}`) fail("invalid_pop", "proof of possession is for another URL");

  return {
    mandate: root.jti as string,
    sub: root.sub as string,
    purpose: isStr(root.purpose) ? root.purpose : "",
    rights,
    depth: chain.length - 1,
    exp,
    holder: await calculateJwkThumbprint(holder),
    budget: (root.budget as Budget) || {},
    pop: { jti: c.jti as string, iat: c.iat as number, htm: c.htm as string, htu: c.htu as string },
  };
}
