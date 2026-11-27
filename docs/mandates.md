# Mandates

A mandate is a power of attorney that your passkey signs. An agent asks for exact rights, you read them on stem's approval page and sign with your passkey, and stem countersigns. The agent can hand a narrower copy to a sub-agent without asking stem, and that one can do the same, as deep as the mandate allows. An app checks the whole chain with stem's public keys and can follow it back to your signature. Press stop on your account page and every branch fails on its next request.

Three properties set this apart from a stored API key or an OAuth grant:

- **The approval is evidence, not a database row.** The WebAuthn challenge your passkey signs is the SHA-256 hash of the mandate itself, with user verification (PIN or biometric) required. The assertion travels inside the token. Not even stem's own signing key can widen a mandate afterwards: the app would see that your passkey signed a different hash.
- **A sub-agent gets less, by arithmetic.** Each child token is signed by the key its parent names, binds to its parent by hash, and may only carry fewer apps, fewer actions, a longer path prefix, a smaller size limit, a shorter life and less depth. Verifiers refuse anything else. No round trip to stem.
- **Every mandate is a live object.** One Durable Object per root mandate holds the stop button, the expiry, a budget that all branches share (ten sub-agents can't each spend the full allowance), a replay check for proofs of possession and a hash-chained trail of every request.

## Standards

Mandates follow two IETF individual drafts from October 2026, so stem can converge with whatever the working groups settle on instead of inventing a dialect:

- [Attenuating Agent Tokens](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-02) (draft 02): the claim names `cnf`, `par_hash`, `del_depth`, `del_max_depth` and `authorization_details`, and the rule that a holder derives narrower tokens offline.
- [WIMSE Agent Delegation Chain](https://datatracker.ietf.org/doc/html/draft-asor-wimse-agent-delegation-chain-03) (draft 03): a chain of tokens, each bound to the key of its holder.

Rights are [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396) `authorization_details` entries. Canonical JSON for the signed hash is [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785). The proof of possession borrows `htm`, `htu`, `ath`, `iat` and `jti` from [DPoP (RFC 9449)](https://www.rfc-editor.org/rfc/rfc9449).

What stem adds on top, and the drafts don't cover: the root is signed by the person's passkey (`hp`), a shared `budget`, and the live check. Both drafts are individual submissions, not standards. Expect the format to move with them; the token `typ` (`mandate+jwt`) will change if it has to break.

## The flow

1. **The agent asks.** It creates an Ed25519 key and sends `POST /api/auth/mandates/request` with `{ "request": <JWT> }`. The JWT has `typ: mandate-request+jwt`, the agent's public key in the `jwk` header, is signed with that key and carries the terms:

   ```json
   {
     "authorization_details": [
       { "type": "stem_mandate", "locations": ["https://drop.example.com"], "actions": ["upload", "list", "delete"], "path_prefix": "screens/", "max_bytes": 50000000 }
     ],
     "purpose": "Publish tonight's screenshots",
     "ttl": 86400,
     "del_max_depth": 2,
     "budget": { "bytes": 200000000 }
   }
   ```

   stem answers with `request_id`, `user_code`, `approve_url` and `expires_in` (10 minutes). Only apps and actions listed in `MANDATE_APPS` are accepted.

2. **You approve.** The agent shows you the link and the code. The page at `/mandates/approve` shows the terms in plain words and the same code. "Approve with your passkey" fetches the exact mandate from `/api/auth/mandates/prepare` (the page checks that its hash is the challenge), your passkey signs it, and `/api/auth/mandates/approve` checks the signature against your stored passkey, runs the same check every app runs, countersigns with stem's signing key and opens the mandate's Durable Object. An account without a passkey is asked to add one first.

3. **The agent collects** the root with `POST /api/auth/mandates/collect` `{ "request_id" }`: `pending`, `denied`, `expired`, or `approved` with `mandate`. The root is bound to the agent's key, so the request id alone is worth nothing to anyone else.

4. **The agent narrows** for sub-agents, offline: a JWT with `typ: mandate+jwt`, signed by the parent's key, with `par_hash` (SHA-256 of the parent token), the child's key in `cnf.jwk`, `del_depth` (the parent's plus one), narrower `authorization_details` and an `exp` no later than the parent's.

5. **Every request** carries the chain and a fresh proof of possession signed by the last key in the chain:

   ```
   Authorization: Mandate <root>~<child>~<grandchild>
   Mandate-PoP: <JWT, typ mandate-pop+jwt: htm, htu (URL without query), ath (SHA-256 of the last token), iat, jti>
   ```

   A proof is good for 60 seconds and once.

## Narrowing rules

A child entry fits inside a parent entry when its `locations` and `actions` are subsets, its `path_prefix` starts with the parent's (a parent prefix can't be dropped), and its `max_bytes` is at most the parent's (a parent limit can't be dropped). Every child entry has to fit inside some parent entry. Unknown fields are refused, so a verifier never ignores a restriction it doesn't understand. End prefixes with `/` if they mean folders: `screens` also matches `screenshots`.

## Checking a request in an app

An app maps the request to one of its actions, the name or path it touches and its size, then asks stem.

**Same Cloudflare account** (recommended): bind the `MandateGateway` entrypoint and call it over RPC.

```jsonc
"services": [{ "binding": "MANDATES", "service": "stem", "entrypoint": "MandateGateway" }]
```

```ts
const chain = parseAuthorization(req.headers.get("authorization")); // "Mandate a~b~c" → ["a", "b", "c"]
const r = await env.MANDATES.authorize({
  chain, pop: req.headers.get("mandate-pop"),
  method: req.method, url: req.url,
  action: "upload", path: "screens/2026-11/a.png", bytes: Number(req.headers.get("content-length")),
});
if (!r.allowed) return new Response(r.message, { status: 403 });
// r.mandate, r.sub, r.purpose, r.holder, r.depth, r.rights, r.remaining
```

`authorize` verifies the chain and the proof (`src/mandates/verify.ts`), checks the call against the rights at the end of the chain, then asks the mandate's object, which checks stop, expiry, budget and replay, debits the budget and writes the trail entry, all in one step. `jwks()` returns stem's public keys.

**Elsewhere:** `POST {issuer}/api/mandates/authorize` with the same fields as JSON. The answer is the same.

**Showing a mandate later:** an app that kept `r.mandate` can ask whether it still stands, for example to print "signed on the 3rd, stopped on the 9th" next to something the mandate once let through.

```ts
const s = await env.MANDATES.status(mandateId);
// s.status: "active" | "revoked" | "expired" | "unknown", s.created_at, s.expires_at, s.revoked_at
```

`status` takes no chain and no proof, writes nothing to the trail and says nothing about the person. It is for display only: a request is let through by `authorize`, never by `status`. It is available over the service binding, not over HTTP. Any app with the binding can ask about any id, not only one it got from `authorize`: the ids are random, and the answer holds the state and three dates, nothing else.

**Offline:** `src/mandates/verify.ts` depends on `jose` and WebCrypto only, and an app can copy it to check chains without stem. It can't know about a stop, the budget or a replayed proof, so use it as a first filter, not instead of the live check.

Refusal reasons: `invalid_chain`, `invalid_human_proof`, `wider_than_parent`, `too_deep`, `invalid_pop`, `outside_mandate`, `revoked`, `expired`, `unknown`, `over_budget`, `replayed`.

## For agents: tools/mandate-agent.mjs

A small helper with no dependency beyond `jose`. As a command:

```sh
node tools/mandate-agent.mjs request --stem https://stem.example.com --app https://drop.example.com \
  --actions upload,list,delete --prefix screens/ --max-bytes 50000000 --ttl 86400 --depth 2 \
  --budget-bytes 200000000 --purpose "Publish tonight's screenshots" --out agent.json
node tools/mandate-agent.mjs derive --from agent.json --out sub.json --actions upload --prefix screens/2026-11/ --ttl 600
node tools/mandate-agent.mjs call --from sub.json --method PUT --url "https://drop.example.com/api/upload?filename=screens/2026-11/a.png" --file a.png
```

As a module: `requestMandate`, `derive`, `proof`, `headers`, `newKey`. A wallet file holds a chain and its holder's private key: keep it like a password.

## Your agents

The account page lists every mandate with what it may do, until when and how many requests it made. "Stop" ends it and everything derived from it on the next request. "Trail" shows the last requests that reached the live check, including those of sub-agents: allowed, or refused because the mandate was stopped, expired, over budget or the proof was replayed. Requests outside the rights of their chain are refused before that and don't show up. Each trail entry carries `hash = SHA-256(previous hash + canonical entry)`, so a downloaded trail can be checked for gaps or edits.

## Configuration

- `MANDATE` Durable Object binding (class `Mandate`, SQLite-backed, in `wrangler.jsonc`).
- `MANDATE_APPS`: the apps that take mandates, with a plain-words label per action for the approval page:

  ```json
  { "https://drop.example.com": { "name": "drop", "actions": { "upload": "Upload files", "list": "See the files it uploaded", "delete": "Delete the files it uploaded" } } }
  ```

Without either, mandates are off: the endpoints answer 404 and the account page has no "Your agents" section.

## Limits and what to know

- You sign what stem's page shows you. The operating system's passkey prompt doesn't display the terms. The page runs under stem's strict content security policy and checks the hash before it asks your passkey.
- The chain proves that a passkey registered at stem for your account signed, not who held it. A stem that enrolled a passkey of its own could sign as you. A public log of enrolments would close that and isn't built yet.
- The proof carries your passkey's public key, which is the same in every mandate. Two apps could tell that two mandates come from the same person.
- A stolen agent key works until the mandate expires or you stop it. Keep children short-lived; every request needs a fresh proof from the holder's key.
- Mandates live at most 30 days and allow at most 4 levels of delegation. A pending request expires after 10 minutes.
