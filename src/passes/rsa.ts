// SPDX-License-Identifier: AGPL-3.0-or-later
// The RSA pieces of Privacy Pass issuance (RFC 9578, token type 2, blind RSA per RFC 9474):
// key encoding, the blind signature itself and its check. No dependencies: WebCrypto and BigInt.

export const b64u = (b: Uint8Array) => {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export const unb64u = (s: string) => {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
};

export const bytesToInt = (b: Uint8Array) => {
  let hex = "";
  for (const x of b) hex += x.toString(16).padStart(2, "0");
  return hex ? BigInt("0x" + hex) : 0n;
};
export const intToBytes = (n: bigint, len: number) => {
  const hex = n.toString(16).padStart(len * 2, "0");
  if (hex.length > len * 2) throw new Error("integer too large");
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return r;
}

// ---------- DER: just enough for RSA public keys ----------

const derLen = (n: number) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
const der = (tag: number, ...parts: Uint8Array[]) => {
  const len = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(1 + derLen(len).length + len);
  out.set([tag, ...derLen(len)]);
  let i = 1 + derLen(len).length;
  for (const p of parts) { out.set(p, i); i += p.length; }
  return out;
};
const oid = (bytes: number[]) => der(0x06, Uint8Array.from(bytes));
const SHA384 = der(0x30, oid([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]));
const MGF1 = oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08]);
const RSASSA_PSS = oid([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a]);
/** AlgorithmIdentifier id-RSASSA-PSS with SHA-384, MGF1-SHA-384 and a 48-byte salt (RFC 9578, section 6.5). */
const PSS_ALG = der(0x30, RSASSA_PSS, der(0x30, der(0xa0, SHA384), der(0xa1, der(0x30, MGF1, SHA384)), der(0xa2, der(0x02, Uint8Array.of(48)))));

/** Reads one DER element at `at`: its tag, where its content starts and ends. */
function readDer(b: Uint8Array, at: number) {
  const tag = b[at];
  let len = b[at + 1];
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n < 1 || n > 2) throw new Error("bad DER length");
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | b[start + i];
    start += n;
  }
  if (start + len > b.length) throw new Error("truncated DER");
  return { tag, start, end: start + len };
}

const derInt = (n: bigint) => {
  let bytes = intToBytes(n, Math.max(1, Math.ceil(n.toString(16).length / 2)));
  if (bytes[0] & 0x80) bytes = Uint8Array.of(0, ...bytes);
  return der(0x02, bytes);
};

/** The token key as RFC 9578 publishes it: SubjectPublicKeyInfo with the RSASSA-PSS algorithm identifier. */
export function encodeTokenKey(n: bigint, e: bigint): Uint8Array {
  const rsaPublicKey = der(0x30, derInt(n), derInt(e));
  return der(0x30, PSS_ALG, der(0x03, Uint8Array.of(0), rsaPublicKey));
}

/** Modulus and exponent from any RSA SubjectPublicKeyInfo (rsaEncryption or RSASSA-PSS). */
export function parseSpki(spki: Uint8Array): { n: bigint; e: bigint; bytes: number } {
  const outer = readDer(spki, 0);
  if (outer.tag !== 0x30 || outer.end !== spki.length) throw new Error("not a public key");
  const alg = readDer(spki, outer.start);
  const bits = readDer(spki, alg.end);
  if (bits.tag !== 0x03 || spki[bits.start] !== 0) throw new Error("not a public key");
  const seq = readDer(spki, bits.start + 1);
  const ni = readDer(spki, seq.start);
  const ei = readDer(spki, ni.end);
  if (seq.tag !== 0x30 || ni.tag !== 0x02 || ei.tag !== 0x02) throw new Error("not an RSA key");
  const n = bytesToInt(spki.subarray(ni.start, ni.end));
  return { n, e: bytesToInt(spki.subarray(ei.start, ei.end)), bytes: Math.ceil(n.toString(16).length / 2) };
}

/** Byte-for-byte check that a key is published in the expected form, not just parsable. */
export const isTokenKey = (spki: Uint8Array) => {
  try {
    const { n, e } = parseSpki(spki);
    const want = encodeTokenKey(n, e);
    return want.length === spki.length && want.every((x, i) => x === spki[i]);
  } catch {
    return false;
  }
};

// ---------- the blind signature ----------

export type PrivateKey = {
  n: bigint; e: bigint; d: bigint; p: bigint; q: bigint; dp: bigint; dq: bigint; qi: bigint;
  /** Modulus length in bytes. */
  bytes: number;
  /** The same key imported as workerd's raw RSA algorithm, when the runtime has it. */
  raw?: CryptoKey;
};

const jwkInt = (v: string | undefined) => {
  if (!v) throw new Error("incomplete RSA key");
  return bytesToInt(unb64u(v));
};

let rawSupported: boolean | undefined;

/** Loads a PKCS #8 RSA key. On Workers the signing itself then runs natively ("RSA-RAW"); elsewhere in BigInt. */
export async function loadPrivateKey(pkcs8: Uint8Array): Promise<PrivateKey> {
  const k = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSA-PSS", hash: "SHA-384" }, true, ["sign"]);
  const j = (await crypto.subtle.exportKey("jwk", k)) as JsonWebKey;
  const n = jwkInt(j.n);
  const key: PrivateKey = { n, e: jwkInt(j.e), d: jwkInt(j.d), p: jwkInt(j.p), q: jwkInt(j.q), dp: jwkInt(j.dp), dq: jwkInt(j.dq), qi: jwkInt(j.qi), bytes: Math.ceil(n.toString(16).length / 2) };
  if (rawSupported !== false) {
    try {
      // Cloudflare's non-standard algorithm for exactly this job: m^d mod n without padding.
      key.raw = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSA-RAW", hash: "SHA-384" } as never, false, ["sign"]);
      rawSupported = true;
    } catch {
      rawSupported = false;
    }
  }
  return key;
}

/**
 * RSABSSA BlindSign (RFC 9474, section 4.3): s = m^d mod n for a blinded message the issuer cannot read.
 * The result is checked against the public key before it leaves, so a faulty computation never
 * hands out a value that could reveal the private key.
 */
export async function blindSign(key: PrivateKey, blinded: Uint8Array): Promise<Uint8Array> {
  if (blinded.length !== key.bytes) throw new Error("unexpected input size");
  const m = bytesToInt(blinded);
  if (m >= key.n) throw new Error("invalid message length");
  let s: bigint;
  if (key.raw) {
    s = bytesToInt(new Uint8Array(await crypto.subtle.sign({ name: "RSA-RAW" } as never, key.raw, blinded)));
  } else {
    // Chinese remainder theorem: two half-size exponentiations instead of one full one.
    const m1 = modPow(m, key.dp, key.p);
    const m2 = modPow(m, key.dq, key.q);
    const h = (((m1 - m2) % key.p) + key.p) % key.p * key.qi % key.p;
    s = m2 + h * key.q;
  }
  if (modPow(s, key.e, key.n) !== m) throw new Error("signing failure");
  return intToBytes(s, key.bytes);
}

/** A fresh RSA-2048 key pair: PKCS #8 private key and the published token key. */
export async function generateTokenKey(): Promise<{ pkcs8: Uint8Array; tokenKey: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-384" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
  const { n, e } = parseSpki(new Uint8Array((await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer));
  return { pkcs8, tokenKey: encodeTokenKey(n, e) };
}

export const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b));
