// SPDX-License-Identifier: AGPL-3.0-or-later
// Passes: stem as a Privacy Pass issuer (RFC 9576/9577/9578, token type 2, publicly verifiable blind RSA).
//
// A signed-in browser asks stem for a batch of passes. It blinds each token request first, so stem signs
// values it cannot read and can't recognize later. An app accepts a pass by checking stem's signature with
// the public key from the issuer directory and remembering the pass's nonce so it can't be spent twice.
// The app learns "stem vouches for this request" and nothing else; stem learns "this account took n passes
// today" and nothing about where they went.
//
// One key per statement and UTC day. Today's key signs; apps accept today's and yesterday's, so a pass
// lives for one to two days and lists of spent passes stay short.
import type { Env } from "../env";
import { b64u, unb64u, blindSign, loadPrivateKey, generateTokenKey, sha256, type PrivateKey } from "./rsa";

/** The only statement so far: "signed in at stem, within today's allowance". */
export const STATEMENT = "signed-in";
export const TOKEN_TYPE = 0x0002;
/** Blind RSA 2048: token request = type (2) + truncated key id (1) + blinded message (256). */
const NK = 256;
const REQUEST_BYTES = 2 + 1 + NK;
/** Passes per account and UTC day, unless PASSES_PER_DAY says otherwise. */
export const DEFAULT_PER_DAY = 50;
/** Most passes one request can ask for. */
export const MAX_BATCH = 50;
const DAY_MS = 24 * 3600 * 1000;

export const perDay = (env: Env) => {
  const n = Number(env.PASSES_PER_DAY);
  return Number.isInteger(n) && n >= 0 && n <= 1000 ? n : DEFAULT_PER_DAY;
};
export const epochOf = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const epochStart = (epoch: string) => Date.parse(`${epoch}T00:00:00Z`);

// ---------- SQL on D1 (and node:sqlite in tests) ----------

type Db = D1Database | { prepare(q: string): { all(...p: unknown[]): unknown[] } };
async function query<T>(db: Db, q: string, ...params: (string | number)[]): Promise<T[]> {
  if ("batch" in db) return (await (db as D1Database).prepare(q).bind(...params).all<T>()).results;
  return (db as { prepare(q: string): { all(...p: unknown[]): unknown[] } }).prepare(q).all(...params) as T[];
}

// ---------- keys ----------

type KeyRow = { id: string; statement: string; epoch: string; tokenKey: string; privateKey: string };
export type TokenKey = { id: Uint8Array; idB64: string; epoch: string; tokenKey: Uint8Array; notBefore: number; notAfter: number };

const wrapKeys = new Map<string, Promise<CryptoKey>>();
/** AES-GCM key for private keys at rest, derived from BETTER_AUTH_SECRET. */
function wrapKey(secret: string) {
  let k = wrapKeys.get(secret);
  if (!k) {
    k = crypto.subtle
      .importKey("raw", new TextEncoder().encode(secret), "HKDF", false, ["deriveKey"])
      .then((ikm) => crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("stem-passes"), info: new TextEncoder().encode("private-key-v1") }, ikm, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]));
    wrapKeys.set(secret, k);
  }
  return k;
}
async function seal(secret: string, data: Uint8Array, aad: string) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(aad) }, await wrapKey(secret), data));
  return `v1.${b64u(iv)}.${b64u(ct)}`;
}
async function open(secret: string, sealed: string, aad: string) {
  const [v, iv, ct] = sealed.split(".");
  if (v !== "v1" || !iv || !ct) throw new Error("unknown key format");
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64u(iv), additionalData: new TextEncoder().encode(aad) }, await wrapKey(secret), unb64u(ct)));
}

const toTokenKey = (r: KeyRow): TokenKey => {
  const start = epochStart(r.epoch);
  return { id: unb64u(r.id), idB64: r.id, epoch: r.epoch, tokenKey: unb64u(r.tokenKey), notBefore: start / 1000, notAfter: (start + 2 * DAY_MS) / 1000 };
};

/** Today's key, made on first use. Two isolates racing both generate one; the first insert wins. */
async function currentKey(env: Env, now: number): Promise<KeyRow> {
  const epoch = epochOf(now);
  const find = () => query<KeyRow>(env.DB, `select "id", "statement", "epoch", "tokenKey", "privateKey" from "passIssuerKey" where "statement" = ?1 and "epoch" = ?2`, STATEMENT, epoch);
  const [row] = await find();
  if (row) return row;
  const { pkcs8, tokenKey } = await generateTokenKey();
  const id = b64u(await sha256(tokenKey));
  await query(env.DB, `insert into "passIssuerKey" ("id", "statement", "epoch", "tokenKey", "privateKey", "createdAt") values (?1, ?2, ?3, ?4, ?5, ?6) on conflict do nothing`, id, STATEMENT, epoch, b64u(tokenKey), await seal(env.BETTER_AUTH_SECRET, pkcs8, id), now);
  const [won] = await find();
  if (!won) throw new Error("could not store the pass key");
  return won;
}

/** Keys apps should accept right now, newest first: today's and yesterday's. */
export async function activeKeys(env: Env, now = Date.now()): Promise<TokenKey[]> {
  await currentKey(env, now);
  const rows = await query<KeyRow>(env.DB, `select "id", "statement", "epoch", "tokenKey", "privateKey" from "passIssuerKey" where "statement" = ?1 and "epoch" in (?2, ?3) order by "epoch" desc`, STATEMENT, epochOf(now), epochOf(now - DAY_MS));
  return rows.map(toTokenKey);
}

const signers = new Map<string, Promise<PrivateKey>>();
function signer(env: Env, row: KeyRow) {
  let s = signers.get(row.id);
  if (!s) {
    s = open(env.BETTER_AUTH_SECRET, row.privateKey, row.id).then(loadPrivateKey);
    s.catch(() => signers.delete(row.id));
    signers.set(row.id, s);
  }
  return s;
}

// ---------- quota ----------

/**
 * Reserves up to `want` passes for an account today, in one statement so parallel requests can't
 * overdraw. Returns how many were granted and how many are left.
 */
async function reserve(env: Env, userId: string, want: number, now: number) {
  const max = perDay(env);
  const [row] = await query<{ used: number; granted: number }>(
    env.DB,
    `insert into "passQuota" ("userId", "day", "used", "granted") values (?1, ?2, min(?3, ?4), min(?3, ?4))
     on conflict ("userId", "day") do update set "granted" = min("used" + ?3, ?4) - "used", "used" = min("used" + ?3, ?4)
     returning "used", "granted"`,
    userId, epochOf(now), want, max,
  );
  return { granted: Math.max(0, row?.granted ?? 0), remaining: Math.max(0, max - (row?.used ?? max)) };
}
async function refund(env: Env, userId: string, n: number, now: number) {
  if (n > 0) await query(env.DB, `update "passQuota" set "used" = max(0, "used" - ?3) where "userId" = ?1 and "day" = ?2`, userId, epochOf(now), n);
}
export async function remaining(env: Env, userId: string, now = Date.now()) {
  const [row] = await query<{ used: number }>(env.DB, `select "used" from "passQuota" where "userId" = ?1 and "day" = ?2`, userId, epochOf(now));
  return Math.max(0, perDay(env) - (row?.used ?? 0));
}

// ---------- issuing ----------

export class PassError extends Error {
  constructor(public status: 400 | 429 | 500, public code: string, message: string) {
    super(message);
  }
}

/** Splits a token request (RFC 9578, section 6.1) and checks it is for `key`. */
function parseRequest(b: Uint8Array, key: TokenKey) {
  if (b.length !== REQUEST_BYTES) throw new PassError(400, "bad_request", "A token request is 259 bytes.");
  if (((b[0] << 8) | b[1]) !== TOKEN_TYPE) throw new PassError(400, "bad_request", "Only token type 2 (blind RSA) is supported.");
  if (b[2] !== key.id[31]) throw new PassError(400, "unknown_key", "The request is for a different key.");
  return b.subarray(3);
}

/**
 * Signs blinded token requests for a signed-in account, within its daily allowance.
 * `keyId` picks today's or yesterday's key (the browser may have fetched the key just before midnight).
 */
export async function issue(env: Env, userId: string, keyId: string | null, requests: Uint8Array[], now = Date.now()) {
  if (!requests.length || requests.length > MAX_BATCH) throw new PassError(400, "bad_request", `Ask for 1 to ${MAX_BATCH} passes at a time.`);
  await currentKey(env, now);
  const rows = await query<KeyRow>(env.DB, `select "id", "statement", "epoch", "tokenKey", "privateKey" from "passIssuerKey" where "statement" = ?1 and "epoch" in (?2, ?3) order by "epoch" desc`, STATEMENT, epochOf(now), epochOf(now - DAY_MS));
  // Without a key id (the plain RFC 9578 request), the truncated id in the request decides, newest key first.
  const row = keyId ? rows.find((r) => r.id === keyId) : rows.find((r) => unb64u(r.id)[31] === requests[0][2]);
  if (!row) throw new PassError(400, "unknown_key", "That key isn't in use anymore. Fetch the current one and try again.");
  const key = toTokenKey(row);
  const blinded = requests.map((r) => parseRequest(r, key));

  const { granted, remaining: left } = await reserve(env, userId, blinded.length, now);
  if (!granted) throw new PassError(429, "quota_used", "That's all passes for today. New ones from midnight UTC.");
  const out: Uint8Array[] = [];
  try {
    const sk = await signer(env, row);
    for (const m of blinded.slice(0, granted)) out.push(await blindSign(sk, m));
  } catch (e) {
    await refund(env, userId, granted - out.length, now);
    console.error("[stem] pass signing failed", e);
    if (!out.length) throw new PassError(e instanceof Error && /message length|input size/.test(e.message) ? 400 : 500, "sign_failed", "Couldn't sign these passes.");
  }
  return { key, responses: out, remaining: left, perDay: perDay(env), resetsAt: new Date(epochStart(epochOf(now)) + DAY_MS).toISOString() };
}

/** Daily cron: keys no app accepts anymore (older than yesterday) and quota counters of past days. */
export async function cleanupPasses(env: Env, now = Date.now()) {
  const keys = await query<{ id: string }>(env.DB, `delete from "passIssuerKey" where "epoch" < ?1 returning "id"`, epochOf(now - DAY_MS));
  const quota = await query<{ day: string }>(env.DB, `delete from "passQuota" where "day" < ?1 returning "day"`, epochOf(now - DAY_MS));
  for (const k of keys) signers.delete(k.id);
  return { passKeys: keys.length, passQuota: quota.length };
}

