#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// A small helper for agent sessions: ask stem for a mandate, wait for the person to approve it, hand
// narrower copies to sub-agents (offline) and sign each request. Node 26+, needs only `jose`.
// Also usable as a module (import { requestMandate, derive, proof, headers } from "./mandate-agent.mjs").
//
//   node tools/mandate-agent.mjs request --stem https://stem.example.com --app https://drop.example.com \
//        --actions upload,list,delete --prefix screens/ --max-bytes 50000000 --ttl 86400 --depth 2 \
//        --budget-bytes 200000000 --purpose "Publish tonight's screenshots" --out agent.json
//   node tools/mandate-agent.mjs derive --from agent.json --out sub.json --actions upload --prefix screens/2026-11/ --ttl 600
//   node tools/mandate-agent.mjs call --from sub.json --method POST --url https://drop.example.com/api/upload?filename=screens/2026-11/a.png --file a.png
//
// A wallet file holds the chain and the holder's private key. Keep it like a password.
import { SignJWT, generateKeyPair, exportJWK, importJWK } from "jose";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const REQUEST_TYP = "mandate-request+jwt";
export const MANDATE_TYP = "mandate+jwt";
export const POP_TYP = "mandate-pop+jwt";

const b64u = (b) => Buffer.from(b).toString("base64url");
const sha256 = async (s) => b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s))));
const now = () => Math.floor(Date.now() / 1000);

/** A new Ed25519 key for an agent or sub-agent. Returns public and private JWKs. */
export async function newKey() {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  return { pub: await exportJWK(publicKey), priv: await exportJWK(privateKey) };
}

/** The signed request an agent sends to POST {stem}/api/auth/mandates/request. */
export async function requestJwt(key, terms) {
  return new SignJWT(terms).setProtectedHeader({ alg: "EdDSA", typ: REQUEST_TYP, jwk: key.pub }).setIssuedAt().sign(await importJWK(key.priv, "EdDSA"));
}

/** Asks stem for a mandate. Resolves with what to show the person (approve_url, user_code) and a wait() for the result. */
export async function requestMandate(stem, terms, { key, fetch: f = fetch } = {}) {
  key ||= await newKey();
  const res = await f(`${stem}/api/auth/mandates/request`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request: await requestJwt(key, terms) }) });
  const r = await res.json();
  if (!res.ok) throw new Error(`stem refused the request: ${r.message || res.status}`);
  return {
    ...r,
    key,
    /** Polls until the person answers. Resolves with a wallet { chain, key }. */
    async wait({ signal } = {}) {
      for (;;) {
        await new Promise((ok) => setTimeout(ok, (r.interval || 3) * 1000));
        if (signal?.aborted) throw new Error("aborted");
        const c = await (await f(`${stem}/api/auth/mandates/collect`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ request_id: r.request_id }) })).json();
        if (c.status === "approved") return { chain: [c.mandate], key };
        if (c.status !== "pending") throw new Error(`mandate ${c.status}`);
      }
    },
  };
}

/** Hands a narrower copy to a sub-agent, without calling stem. `holder` is the sub-agent's public JWK
 * (it keeps its own private key); `rights` must fit inside the parent's, `ttl` inside its lifetime. */
export async function derive(wallet, { holder, rights, ttl = 600 }) {
  const parent = wallet.chain[wallet.chain.length - 1];
  const p = JSON.parse(Buffer.from(parent.split(".")[1], "base64url").toString());
  const exp = Math.min(p.exp, now() + ttl);
  return new SignJWT({ par_hash: await sha256(parent), cnf: { jwk: holder }, authorization_details: rights, del_depth: wallet.chain.length })
    .setProtectedHeader({ alg: "EdDSA", typ: MANDATE_TYP })
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(await importJWK(wallet.key.priv, "EdDSA"));
}

/** The rights at the end of a wallet's chain. */
export const rightsOf = (wallet) => JSON.parse(Buffer.from(wallet.chain[wallet.chain.length - 1].split(".")[1], "base64url").toString()).authorization_details;

/** Proof of possession for one request (method and URL without query), valid for a minute. */
export async function proof(wallet, method, url) {
  const u = new URL(url);
  return new SignJWT({ htm: method.toUpperCase(), htu: `${u.origin}${u.pathname}`, ath: await sha256(wallet.chain[wallet.chain.length - 1]) })
    .setProtectedHeader({ alg: "EdDSA", typ: POP_TYP })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(await importJWK(wallet.key.priv, "EdDSA"));
}

/** The two headers for one request. */
export async function headers(wallet, method, url) {
  return { authorization: `Mandate ${wallet.chain.join("~")}`, "mandate-pop": await proof(wallet, method, url) };
}

// ---------- command line ----------

function args(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) if (argv[i].startsWith("--")) o[argv[i].slice(2)] = argv[i + 1]?.startsWith("--") || argv[i + 1] === undefined ? true : argv[++i];
  return o;
}
const right = (a, base = {}) => {
  const r = { type: "stem_mandate", locations: a.app ? [new URL(a.app).origin] : base.locations, actions: a.actions ? String(a.actions).split(",") : base.actions };
  const prefix = a.prefix ?? base.path_prefix, max = a["max-bytes"] ?? base.max_bytes;
  if (prefix !== undefined) r.path_prefix = String(prefix);
  if (max !== undefined) r.max_bytes = Number(max);
  return r;
};

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const a = args(rest);
  if (cmd === "request") {
    const terms = { authorization_details: [right(a)], purpose: a.purpose || "Agent session", ttl: Number(a.ttl || 86400), del_max_depth: Number(a.depth || 0) };
    const budget = {};
    if (a["budget-bytes"]) budget.bytes = Number(a["budget-bytes"]);
    if (a["budget-calls"]) budget.calls = Number(a["budget-calls"]);
    if (Object.keys(budget).length) terms.budget = budget;
    const r = await requestMandate(String(a.stem).replace(/\/$/, ""), terms);
    console.error(`Open this link and approve with your passkey:\n  ${r.approve_url}\nThe page should show the code ${r.user_code}. Waiting...`);
    const wallet = await r.wait();
    writeFileSync(a.out || "agent.json", JSON.stringify(wallet), { mode: 0o600 });
    console.error(`Approved. Saved to ${a.out || "agent.json"}.`);
  } else if (cmd === "derive") {
    const parent = JSON.parse(readFileSync(a.from, "utf8"));
    const key = await newKey();
    const base = rightsOf(parent)[0];
    const token = await derive(parent, { holder: key.pub, rights: [right(a, base)], ttl: Number(a.ttl || 600) });
    writeFileSync(a.out || "sub.json", JSON.stringify({ chain: [...parent.chain, token], key }), { mode: 0o600 });
    console.error(`Saved a narrower copy to ${a.out || "sub.json"}.`);
  } else if (cmd === "headers" || cmd === "call") {
    const wallet = JSON.parse(readFileSync(a.from, "utf8"));
    const method = String(a.method || "GET").toUpperCase();
    const h = await headers(wallet, method, a.url);
    if (cmd === "headers") { console.log(JSON.stringify(h, null, 2)); return; }
    const init = { method, headers: { ...h } };
    if (a.file) { init.body = readFileSync(a.file); init.headers["content-type"] = a.type || "application/octet-stream"; }
    const res = await fetch(a.url, init);
    console.log(res.status, await res.text());
  } else {
    console.error("usage: mandate-agent.mjs request|derive|headers|call [--options], see the top of this file");
    process.exit(2);
  }
}
// compare as file URLs, so this also runs on Windows, where argv[1] is a drive path
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((e) => { console.error(e.message || e); process.exit(1); });
