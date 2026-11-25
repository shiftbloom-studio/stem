# stem.

stem is the sign-in behind shiftbloom studio's apps. You make one account, and every app that uses stem lets you in with it. There are no passwords: you sign in with a passkey, or with a six-digit code we email you.

For apps, stem is an ordinary OpenID Connect provider with teams built in. An app sends people to stem, gets back a signed token that says who they are and which of its teams they're in, and manages those teams through a small API.

It runs at [stem.shiftbloom.studio](https://stem.shiftbloom.studio) on a single Cloudflare Worker, and is made by [shiftbloom studio](https://shiftbloom.studio). The code is licensed under AGPL-3.0-or-later.

## What it does

- **Passwordless sign-in.** Passkeys first, codes by email as the fallback. The first confirmed code creates the account. After that, stem offers to add a passkey once.
- **Accounts people can manage.** Change your name, add and remove passkeys, see every signed-in device and end any of them, delete your account.
- **Teams per app.** Organizations belong to one app. Members have a role (`owner`, `admin`, `member`, plus any roles the operator adds, like `dispatcher` or `pilot`). Invitations go out by email and are accepted on stem.
- **OpenID Connect for apps.** Authorization code flow with PKCE, rotating refresh tokens, RP-initiated logout, discovery and JWKS. Access tokens are EdDSA-signed JWTs for the app's API (RFC 8707 resource indicators) and carry an `orgs` claim with the person's teams in that app.
- **A directory API for app servers.** Invitations, members, roles and team details, authorized with the app's own client credentials. An app only ever sees its own teams.

How an app plugs in is described in [docs/integration.md](docs/integration.md).

## Security

- No passwords to phish, reuse or reset. Codes are six digits, valid for ten minutes, stored only as a hash and limited to five tries.
- Sending codes is protected by Cloudflare Turnstile, a per-endpoint limit (five codes per ten minutes) and a per-IP limit through the Workers rate limiting binding.
- Session cookies are `__Secure-`, `HttpOnly`, `SameSite=Lax` and host-only on stem's origin. Apps never see them; they get tokens.
- Clients are registered by the operator only. Users can't register clients, and dynamic client registration is off. Redirect URIs must match exactly. PKCE is required.
- Pages ship without inline scripts under a strict Content Security Policy, with `frame-ancestors 'none'`, HSTS and no third-party requests (fonts are proxied).
- `workers.dev` and preview URLs are off, so stem only answers on its issuer origin.
- JWKS private keys are encrypted at rest with `BETTER_AUTH_SECRET`.

Please report security problems as described in [SECURITY.md](SECURITY.md).

## Architecture

| Piece | What it does |
| --- | --- |
| `src/auth.ts` | The [Better Auth](https://www.better-auth.com) instance (pinned): email codes, passkeys, organizations, JWT/JWKS and the OAuth provider. |
| `src/api.ts` | Operator API (`/api/v1/operator/*`) and the per-app directory API (`/api/v1/*`). |
| `src/index.ts` | Hono app: pages, discovery, security headers, rate limits. |
| `src/ui/` | Server-rendered pages and the privacy policy and imprint in English and German. |
| `src/client/app.ts` | Browser code for the pages, bundled to `public/assets/app.js`. |
| `migrations/` | D1 schema. `npm run db:schema` prints what the Better Auth config needs; a test fails when they drift apart. |

Storage is one D1 database. Email goes out through Cloudflare Email Service.

## Self-hosting

You need a Cloudflare account with Workers Paid, a zone for the hostname, and a domain onboarded to Email Sending.

```sh
npm install
npx wrangler d1 create stem-db              # put the id into wrangler.jsonc
npx wrangler d1 migrations apply stem-db --remote
npx wrangler secret put BETTER_AUTH_SECRET  # 32+ random bytes
npx wrangler secret put OPERATOR_TOKEN      # 32+ random bytes
npx wrangler secret put TURNSTILE_SECRET    # optional, with TURNSTILE_SITE_KEY
npm run deploy
```

Then set the variables in `wrangler.jsonc` (or in your deploy pipeline):

| Variable | Meaning |
| --- | --- |
| `STEM_URL` | Public origin, also the OpenID Connect issuer. |
| `EMAIL_FROM` | Sender for codes and invitations, on a domain onboarded to Email Sending. |
| `ORG_ROLES` | Extra team roles, comma separated. |
| `RESOURCES` | APIs that get JWT access tokens, comma separated absolute URIs. |
| `TURNSTILE_SITE_KEY` | Turnstile widget for "email me a code". Needs the `TURNSTILE_SECRET` secret. |
| `LEGAL` | Operator details (JSON) for `/privacy`, `/datenschutz`, `/imprint` and `/impressum`. The pages are hidden without it. Keep it out of the repository. |

Register an app and create its first team with the operator API, as shown in [docs/integration.md](docs/integration.md).

## Development

```sh
cp .dev.vars.example .dev.vars
npx wrangler d1 migrations apply stem-db --local
npm run dev          # codes are printed to the console
npm run check        # typecheck, tests, bundle
```

Node 26 or newer.

## Design

The pages follow the shiftbloom studio brand book: white paper and ink, Bloom Red `#FF2E52` as the only accent, the Bloom mark drawn as SVG, Clash Display for statements, General Sans for the interface and JetBrains Mono for labels and codes. When you fork, restyle `src/ui/layout.ts`.

## Costs

D1 reads and writes per sign-in are in the single digits, and the Worker runs for a few milliseconds per request. Email Sending includes 3,000 messages a month on Workers Paid. For a few hundred people, expect well under a dollar a month.

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).
