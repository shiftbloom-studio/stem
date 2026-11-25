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

There is no "active organization" in the token. The app decides which organization a request is about (for example from the URL) and checks `orgs[thatId]`. Role changes show up at the next refresh, so within 10 minutes.

Roles: `owner`, `admin`, `member`, plus any roles in stem's `ORG_ROLES` (for example `dispatcher,pilot`). What a role allows inside the app is up to the app.

```ts
import { createRemoteJWKSet, jwtVerify } from "jose";
const JWKS = createRemoteJWKSet(new URL("https://stem.example.com/api/auth/jwks"));
const { payload } = await jwtVerify(token, JWKS, { issuer: "https://stem.example.com", audience: "https://www.my-app.example/api", typ: "at+jwt" });
const role = (payload.orgs as Record<string, string> | undefined)?.[tenant.authOrgId];
```

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

## Things to know

- `sub` is the same for a person across all apps on one stem. Don't treat it as a secret.
- The directory API can add any existing stem account to one of your organizations by email or user id, without an invitation. That's meant for first-party apps registered by the operator; use invitations when the person should agree first.
- People can't change organizations on stem itself. Renaming, metadata, members and deletion all go through your app and the directory API.
- Per-IP limits treat every IPv6 address on its own.
