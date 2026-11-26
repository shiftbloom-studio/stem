# Using stem from an app

stem is a standard OpenID Connect provider. An app signs people in with the authorization code flow, verifies access tokens against stem's JWKS, and manages its teams through a small directory API.

Everything below uses `https://stem.example.com` as the issuer. Replace it with your deployment.

## 1. Register the app

The operator creates one confidential client per app (secret shown once):

```sh
curl -X POST https://stem.example.com/api/v1/operator/clients \
  -H "authorization: Bearer $OPERATOR_TOKEN" -H "content-type: application/json" \
  -d '{
    "app": "my-app",
    "name": "My App",
    "uri": "https://www.my-app.example",
    "redirect_uris": ["https://www.my-app.example/auth/callback"],
    "post_logout_redirect_uris": ["https://www.my-app.example/"],
    "resources": ["https://www.my-app.example/api"],
    "skip_consent": true
  }'
```

- `app` ties the client to its organizations. A client only ever sees organizations with the same `app`.
- `resources` must also be listed in stem's `RESOURCES` variable. Access tokens for a resource are signed JWTs; without one they are opaque.
- `skip_consent` is for first-party apps only.

Organizations are created by the operator too:

```sh
curl -X POST https://stem.example.com/api/v1/operator/orgs \
  -H "authorization: Bearer $OPERATOR_TOKEN" -H "content-type: application/json" \
  -d '{ "app": "my-app", "name": "Example Team", "slug": "example", "owner_email": "owner@example.com" }'
```

## 2. Sign people in

Discovery: `https://stem.example.com/.well-known/openid-configuration`

- Flow: authorization code with PKCE (`S256`, required), client authentication `client_secret_basic`.
- Scopes: `openid profile email offline_access orgs`.
- Send `resource=https://www.my-app.example/api` on **both** the authorize and the token request, so the access token is a JWT for your API.
- Use `state` for your own data (for example the tenant slug to return to) and `nonce` for the ID token.
- Refresh with `grant_type=refresh_token` (and the same `resource`). Refresh tokens rotate: store the new one every time.
- A refresh fails once the person removes your app on their stem account page or deletes their account. Treat that like a sign-out.
- Sign out: redirect to the `end_session_endpoint` with `id_token_hint` and a registered `post_logout_redirect_uri`.

stem's session cookie stays on stem's own host. Apps keep their own session (for example an encrypted cookie holding the refresh token) and never see stem's cookies.

## 3. Verify access tokens

Access tokens are EdDSA (Ed25519) JWTs with `typ: at+jwt`, valid for 10 minutes. Verify with the JWKS from discovery, `iss` = the issuer and `aud` = your resource.

| Claim | Meaning |
| --- | --- |
| `sub` | stem user id (a UUID). Stable; use it as your user key. |
| `client_id`, `azp` | Your client. |
| `scope` | Granted scopes, space separated. |
| `email`, `email_verified` | With the `email` scope. Signing in with a code always verifies the address. |
| `name` | With the `profile` scope. |
| `orgs` | With the `orgs` scope: `{ "<organization id>": "<role>" }` for every organization of your app the user belongs to. Empty object when they belong to none. |
| `auth_method` | How the person signed in to stem for this session: `passkey`, `email_code`, or `unknown` (sessions from before stem recorded it, or a session that has ended). Also in the ID token. See [Sign-in strength and step-up](#sign-in-strength-and-step-up). |
| `passkey_synced` | Only with `auth_method: passkey`. `true` for a passkey that syncs between devices (iCloud Keychain, Google Password Manager, most password managers), `false` for one bound to a single device or security key. |
| `signed_in_at` | When that sign-in happened, in seconds since the epoch. The same moment as the ID token's `auth_time`, which access tokens can't carry. |

There is no "active organization" in the token. The app decides which organization a request is about (for example from the URL) and checks `orgs[thatId]`. Role changes show up at the next refresh, so within 10 minutes.

Roles: `owner`, `admin`, `member`, plus any roles in stem's `ORG_ROLES` (for example `dispatcher,pilot`). What a role allows inside the app is up to the app.

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";
const JWKS = createRemoteJWKSet(new URL("https://stem.example.com/api/auth/jwks"));
const { payload } = await jwtVerify(token, JWKS, { issuer: "https://stem.example.com", audience: "https://www.my-app.example/api", typ: "at+jwt" });
const role = (payload.orgs as Record<string, string> | undefined)?.[tenant.authOrgId];
```

## Sign-in strength and step-up

An email code proves someone can read the inbox. A passkey proves they hold the device and passed its PIN or biometric check, and it can't be phished. Tokens say which one happened, so an app can ask for more before an action that matters, for example changing roles or deleting a team.

The claims follow the stem session: a token refreshed later still says how that session started. Treat anything other than `passkey` the same as an email code.

To require a recent passkey before an action:

1. Check the access token: `auth_method === "passkey"` and `now - signed_in_at` within your limit (for example 10 minutes).
2. If either fails, send the person through the authorization flow again with `prompt=login` (or `max_age=<seconds>`), and come back to the action afterwards. Optionally add `acr_values=phr` to say you want a phishing-resistant sign-in.
3. stem asks them to confirm. If they're signed in and have a passkey, the page offers it first and keeps the email code as a fallback, so a lost device never locks anyone out.
4. Check the new token again, and that its `sub` is the same person. If they used a code, the action stays blocked; tell them to add a passkey on their stem account page.

```ts
const STEP_UP_SECONDS = 600;
const fresh = typeof payload.signed_in_at === "number" && Date.now() / 1000 - payload.signed_in_at <= STEP_UP_SECONDS;
if (payload.auth_method !== "passkey" || !fresh) return redirectToStemSignIn({ prompt: "login", acr_values: "phr", returnTo: request.url });
```

Apps that don't read these claims see no change. The standard `acr` stays `"0"` and `amr` isn't set for now: Better Auth owns those values, and `acr_values` is a hint stem uses for the page, not a guarantee. The decision is always the app's, based on `auth_method`.

## 4. Directory API

For server-to-server work (invitations, member lists, roles) the app gets a token with its own credentials:

```sh
curl -u "$CLIENT_ID:$CLIENT_SECRET" https://stem.example.com/api/auth/oauth2/token \
  -d grant_type=client_credentials -d scope=directory -d resource=https://stem.example.com/api/v1
```

The token lasts 5 minutes. Send it as `Authorization: Bearer …` to:

| Method and path | What it does |
| --- | --- |
| `GET /api/v1/roles` | Role names this stem accepts. |
| `GET /api/v1/orgs` | Your app's organizations. |
| `GET /api/v1/orgs/:id` | One organization. |
| `PATCH /api/v1/orgs/:id` | Change `name`, `logo` (https URL) or `metadata` (object). |
| `GET /api/v1/orgs/:id/members?limit=100&offset=0` | Members with `user_id`, `role`, `user { id, email, name }`, plus `total`. |
| `POST /api/v1/orgs/:id/members` | Add `{ user_id \| email, role }` directly. Unknown emails get an account that is confirmed at first sign-in. |
| `PATCH /api/v1/orgs/:id/members/:userId` | Change `{ role }`. The last owner can't be demoted. |
| `DELETE /api/v1/orgs/:id/members/:userId` | Remove a member. The last owner can't be removed. |
| `GET /api/v1/orgs/:id/invitations?status=pending` | Invitations (`pending`, `accepted`, `rejected`, `canceled`). |
| `POST /api/v1/orgs/:id/invitations` | Invite `{ email, role, inviter_id?, redirect_to?, expires_in_days? }` (1 to 30, default 7). Returns `{ id, organization_id, email, role, status, expires_at, created_at, inviter_id, redirect_to }`. stem sends the email. `redirect_to` must be on one of your redirect URI origins; the person lands there after accepting. A new invite replaces a pending one for the same address. |
| `DELETE /api/v1/orgs/:id/invitations/:invId` | Withdraw an invitation. |
| `GET /api/v1/users/:id` | `{ id, email, name, email_verified }`, only for members of your organizations. |

Errors are JSON: `{ "error": "code", "detail"?: "text" }` with a fitting HTTP status.

## 5. App Workers on the same account: the gateway

An app that runs as a Cloudflare Worker on the same account as stem can bind to stem's `AppGateway` entrypoint. The binding names the app in `props`. Cloudflare sets those props from the binding, so stem knows which app is calling without a token or shared secret.

```jsonc
// The app's wrangler.jsonc
"services": [
  { "binding": "IDENTITY", "service": "stem", "entrypoint": "AppGateway", "props": { "app": "my-app" } }
]
```

**HTTP.** `env.IDENTITY.fetch(request)` serves everything the public hostname serves (token endpoint, JWKS, directory API). Rate limits through the gateway are kept per person: set `x-stem-client-ip` to the IP of the person you're calling for (for example your own `cf-connecting-ip`). Calls without it, such as background jobs, count against a bucket of their own for your app. Through the gateway, a directory token only works for the app the binding names (`403 app_mismatch` otherwise).

```ts
const res = await env.IDENTITY.fetch(new Request("https://stem.example.com/api/auth/oauth2/token", {
  method: "POST",
  headers: { authorization: basic, "content-type": "application/x-www-form-urlencoded", "x-stem-client-ip": req.headers.get("cf-connecting-ip") ?? "" },
  body,
}));
```

**Typed directory.** The directory API is also available as RPC methods, scoped to the app in `props`, with no client-credentials token. The app still needs at least one enabled client: disabling its clients cuts off these calls too. Results have the same shapes as the HTTP API.

| Method | HTTP equivalent |
| --- | --- |
| `roles()` | `GET /api/v1/roles` (returns the array) |
| `listOrgs()` | `GET /api/v1/orgs` (returns the array) |
| `getOrg(orgId)` | `GET /api/v1/orgs/:id`, `null` when not found |
| `updateOrg(orgId, { name?, logo?, metadata? })` | `PATCH /api/v1/orgs/:id` |
| `listMembers(orgId, { limit?, offset? })` | `GET /api/v1/orgs/:id/members` |
| `addMember(orgId, { user_id \| email, role })` | `POST /api/v1/orgs/:id/members` |
| `setMemberRole(orgId, userId, role)` | `PATCH /api/v1/orgs/:id/members/:userId` |
| `removeMember(orgId, userId)` | `DELETE /api/v1/orgs/:id/members/:userId` |
| `listInvitations(orgId, status = "pending")` | `GET /api/v1/orgs/:id/invitations` (returns the array) |
| `invite(orgId, { email, role?, inviter_id?, redirect_to?, expires_in_days? })` | `POST /api/v1/orgs/:id/invitations` |
| `cancelInvitation(orgId, invitationId)` | `DELETE /api/v1/orgs/:id/invitations/:invId` |
| `getUser(userId)` | `GET /api/v1/users/:id`, `null` when not found |

A failed call throws an error whose message starts with the HTTP API's error code, for example `not_found` or `invalid_role: …`.

A plain service binding without `entrypoint` keeps working exactly as before.

## 6. Mandates for agents

Agents that act for a person (upload to an app, call its API) can carry a mandate the person signed with a passkey instead of a static API key. How apps check them is in [mandates.md](mandates.md).

## 7. Passes: an allowance without accounts

An app can give signed-in people more (free conversions, uploads, requests) without learning who they are, through anonymous passes stem issues. How to accept them is in [passes.md](passes.md).

## Things to know

- `sub` is the same for a person across all apps on one stem, except sealed apps, which get their own (see [sealed-apps.md](sealed-apps.md)). Don't treat it as a secret.
- The directory API can add any existing stem account to one of your organizations by email or user id, without an invitation. That's meant for first-party apps registered by the operator; use invitations when the person should agree first.
- People can't change organizations on stem itself. Renaming, metadata, members and deletion all go through your app and the directory API.
- Per-IP limits treat every IPv6 address on its own.
