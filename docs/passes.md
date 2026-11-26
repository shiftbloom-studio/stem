# Passes

A pass lets an app give a signed-in person more than an anonymous visitor (more free conversions, a bigger upload allowance) without the app learning who they are, and without stem learning where the pass was spent.

It works like a cinema ticket. stem checks your account at the box office and hands out tickets; the app checks the ticket at the door. The ticket doesn't carry your name, and the box office can't tell which ticket it sold to whom.

Technically, stem is a [Privacy Pass](https://www.rfc-editor.org/rfc/rfc9576) issuer for token type 2, publicly verifiable blind RSA ([RFC 9578](https://www.rfc-editor.org/rfc/rfc9578), [RFC 9474](https://www.rfc-editor.org/rfc/rfc9474)). Any library that speaks that, such as [`@cloudflare/privacypass-ts`](https://github.com/cloudflare/privacypass-ts), works with it.

## What a pass says

"stem vouches for this request: someone signed in at stem took this pass within their daily allowance." Nothing else. Each account gets 50 passes per UTC day (`PASSES_PER_DAY`), across all apps.

## The flow

1. **The app page** gets stem's current key (from its own server, see below) and makes token requests: for each pass it picks a random nonce, builds the token input and blinds it.
2. **The browser** sends the blinded requests to stem with the stem session cookie. stem checks the session and the allowance, signs the blinded values and returns them. It can't read what it signed.
3. **The browser** unblinds the signatures. Each result is a pass, kept in the app's local storage.
4. **The app server** gets a pass with a request, checks stem's signature, and records the pass's nonce so it can't be spent twice.

## Endpoints on stem

### `GET /.well-known/private-token-issuer-directory`

Public, cacheable for 5 minutes, the same for everyone.

```json
{
  "issuer-request-uri": "https://stem.example.com/api/passes/issue",
  "token-keys": [
    { "token-type": 2, "token-key": "MIIBUjA9…", "not-before": 1795651200, "stem-not-after": 1795824000, "stem-key-id": "q0Yc…" }
  ],
  "stem-statement": "signed-in",
  "stem-per-day": 50
}
```

`token-key` is the base64url RSASSA-PSS public key as RFC 9578 defines it. `stem-key-id` is its SHA-256 (the `token_key_id` inside every pass). There is one key per UTC day. Newest first: today's key signs, and apps accept today's and yesterday's, so a pass lives for one to two days.

### `POST /api/passes/issue`

From a browser on a page in `PASS_ORIGINS`, with credentials.

```http
POST /api/passes/issue
Origin: https://convert.example.com
Content-Type: application/json
Cookie: <stem session>

{ "token_key_id": "<stem-key-id>", "requests": ["<base64url TokenRequest>", …] }
```

Up to 50 requests per call. The answer holds as many blind signatures as the allowance still covers:

```json
{ "token_type": 2, "token_key_id": "q0Yc…", "responses": ["<base64url blind signature>", …], "remaining": 47, "per_day": 50, "resets_at": "2026-11-27T00:00:00.000Z" }
```

| Status | `error` | Meaning |
| --- | --- | --- |
| 401 | `sign_in` | No stem session. Send the person to sign in (below). |
| 403 | `origin_not_allowed` | The page's origin isn't in `PASS_ORIGINS`. |
| 400 | `unknown_key` | The key isn't today's or yesterday's. Fetch the current one. |
| 400 | `bad_request` | Malformed requests. Nothing was taken from the allowance. |
| 429 | `quota_used` | No passes left today. |

A plain RFC 9578 request also works: `Content-Type: application/private-token-request` with one 259-byte `TokenRequest` as the body, answered with `application/private-token-response`.

### `GET /api/passes/status`

From the same pages, with credentials: `{ "signed_in": true, "remaining": 47, "per_day": 50 }`.

### Signing in from an app page

Link to `https://stem.example.com/sign-in?next=/passes/back%3Fto%3D<url-encoded page URL>`. After signing in, stem sends the person back to that page, but only to origins in `PASS_ORIGINS`.

## Accepting passes in an app

The challenge every pass for your app is bound to (RFC 9577, section 2.1):

```
token_type          = 0x0002
issuer_name         = "stem.example.com"   (stem's hostname)
redemption_context  = empty                (so passes can be fetched ahead of time)
origin_info         = "app.example.com"    (your hostname)
```

The browser sends a pass as `Authorization: PrivateToken token="<base64url Token>"`. A token is 354 bytes:

| Bytes | Field |
| --- | --- |
| 0–1 | `token_type`, 0x0002 |
| 2–33 | `nonce` |
| 34–65 | `challenge_digest`, SHA-256 of your challenge |
| 66–97 | `token_key_id`, SHA-256 of the token key |
| 98–353 | `authenticator`, the RSA signature |

To accept it:

1. Check the length, the type and that `challenge_digest` is the SHA-256 of your own challenge. A pass made for another app fails here.
2. Look up `token_key_id` among the keys in stem's directory. Refresh the directory when you see an unknown id, but not more than once a minute.
3. Verify `authenticator` as an RSASSA-PSS signature (SHA-384, MGF1-SHA-384, 48-byte salt) over bytes 0–97, with that key.
4. Record the `nonce` together with the key id. If it was already there, the pass is spent. A Durable Object per key, with a SQLite table and `INSERT … ON CONFLICT DO NOTHING RETURNING`, does this atomically. The list can go once the key leaves the directory, two days later.

WebCrypto can't import the RSASSA-PSS key form directly; read the modulus and exponent out of it and import them as a JWK (`{ kty: "RSA", n, e }`, `RSA-PSS`, `SHA-384`). [convert](https://github.com/shiftbloom-studio/convert) has a complete browser client and verifier without dependencies.

App Workers on the same Cloudflare account should fetch the directory through a service binding to stem, not over the public hostname.

## Configuration

| Setting | Meaning |
| --- | --- |
| `PASS_ORIGINS` | Origins of app pages that may fetch passes, comma separated. Without it only stem's own origin can. |
| `PASSES_PER_DAY` | Passes per account and UTC day, default 50. |

Keys are generated on first use each day, stored in D1 encrypted with a key derived from `BETTER_AUTH_SECRET`, and deleted by the daily cleanup once no app accepts them.

## What it does and doesn't protect

- **Unlinkable in the maths.** stem signs blinded values, so even stem can't match a pass to the account that took it.
- **Not on the network.** stem and an app run by the same operator both see IP addresses and timing. A pass fetched and spent in the same second from the same address is linkable in practice. Fetching passes in batches ahead of time helps; so does keeping no logs that join the two.
- **Small crowds.** With a handful of users a day, "one of today's signed-in users" isn't anonymous.
- **No bans.** A pass can't be traced back, so it can't be revoked. Small daily batches and daily keys keep the damage of a misused account small.
- **Same key for everyone.** The directory is public and cached, and the app (not stem) gives its pages the key, so stem can't hand one person a key of their own to recognize them later.
