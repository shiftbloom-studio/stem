# stem.

Multi-tenant auth for small apps. OIDC, passkeys and email codes, running on Cloudflare Workers.

**Live:** [stem.shiftbloom.studio](https://stem.shiftbloom.studio) · **License:** AGPL-3.0-or-later

stem is the sign-in behind shiftbloom studio's apps. You make one account, and every app that uses stem lets you in with it. There are no passwords: you sign in with a passkey, or with a six-digit code we email you.

For apps, stem is an ordinary OpenID Connect provider with teams built in. An app sends people to stem, gets back a signed token that says who they are and which of its teams they're in, and manages those teams through a small API.

It runs on a single Cloudflare Worker.

## Features

- **Passwordless sign-in.** Passkeys first, codes by email as the fallback. The first confirmed code creates the account. After that, stem offers to add a passkey once.
- **Accounts people can manage.** Change your name, add and remove passkeys, see every signed-in device and end any of them, see which apps have access and remove them, download your data as JSON, delete your account.
- **Teams per app.** Organizations belong to one app. Members have a role (`owner`, `admin`, `member`, plus any roles the operator adds, like `dispatcher` or `pilot`). Invitations go out by email and are accepted on stem.
- **OpenID Connect for apps.** Authorization code flow with PKCE, rotating refresh tokens, RP-initiated logout, discovery and JWKS. Access tokens are EdDSA-signed JWTs for the app's API (RFC 8707 resource indicators) and carry an `orgs` claim with the person's teams in that app, plus how they signed in (`auth_method`), so an app can ask for a fresh passkey before admin actions.
- **Mandates for agents.** Your passkey signs the exact rights an agent gets. The agent hands narrower copies to sub-agents without calling stem, apps check the whole chain back to your signature, and one stop button on your account page ends every branch. See [docs/mandates.md](docs/mandates.md).
- **A directory API for app servers.** Invitations, members, roles and team details, authorized with the app's own client credentials. An app only ever sees its own teams.

How an app plugs in is described in [docs/integration.md](docs/integration.md).

## Security model

- No passwords to phish, reuse or reset. Codes are six digits, valid for ten minutes, stored only as a hash and limited to five tries.
- Codes are also limited per address, whatever the IP: one per minute and ten per day, and fifteen sign-in attempts per day across all codes. After that the address is locked until the next day. Rotating IP addresses doesn't buy more guesses.
- Sending codes is protected by Cloudflare Turnstile, a per-endpoint limit and a per-IP limit through the Workers rate limiting binding.
- Passkeys must verify the person (PIN or biometric), not just the device.
- Session cookies are `__Secure-`, `HttpOnly`, `SameSite=Lax` and host-only on stem's origin. Apps never see them; they get tokens.
- Clients are registered by the operator only. Users can't register clients, and dynamic client registration is off. Redirect URIs must match exactly. PKCE is required.
- Pages ship without inline scripts under a strict Content Security Policy, with `frame-ancestors 'none'`, HSTS and no third-party requests (fonts are proxied).
- `workers.dev` and preview URLs are off, so stem only answers on its issuer origin.
- Organizations are changed only by their app through the directory API. Members can list their teams and answer invitations, nothing more.
- Tokens come only from the OpenID Connect endpoints; Better Auth's session-to-JWT endpoint is off, and so are its password, email-change and social endpoints.
- Cookie requests must carry stem's own `Origin`, always (Better Auth would skip this check when `NODE_ENV` says `test`).
- Sign-in codes never reach the logs outside `localhost`. Without the email binding, sending fails.
- The signing key (Ed25519) rotates every 90 days; old keys stay published for 30 more days. Private keys are encrypted at rest with `BETTER_AUTH_SECRET`.

### If a signing key leaks

Delete the keys and let stem make a new one on the next request. Every token signed so far stops verifying, so people sign in to apps again:

```sh
node scripts/render-config.mjs   # with your .env.deploy
npx wrangler d1 execute stem-db --remote -c wrangler.deploy.jsonc --command "DELETE FROM jwks"
```

If `BETTER_AUTH_SECRET` leaks, replace it too (`npx wrangler secret put BETTER_AUTH_SECRET`). That also ends every stem session.

## Architecture

| Piece | What it does |
| --- | --- |
| `src/auth.ts` | The [Better Auth](https://www.better-auth.com) instance (pinned): email codes, passkeys, organizations, JWT/JWKS and the OAuth provider. |
| `src/api.ts` | Operator API (`/api/v1/operator/*`) and the per-app directory API (`/api/v1/*`). |
| `src/index.ts` | Hono app: pages, discovery, security headers, rate limits. |
| `src/ui/` | Server-rendered pages and the privacy policy and imprint in English and German. |
| `src/mandates/` | Mandates: the `mandates()` plugin, the verifier apps run, the `Mandate` Durable Object and the `MandateGateway` entrypoint. |
| `src/client/app.ts` | Browser code for the pages, bundled to `public/assets/app.js`. |
| `migrations/` | D1 schema. `npm run db:schema` prints what the Better Auth config needs; a test fails when they drift apart. |

Storage is one D1 database, plus one SQLite-backed Durable Object per mandate. Email goes out through Cloudflare Email Service.

## Privacy and GDPR

stem stores what signing in needs and deletes the rest. A daily cron (`src/cleanup.ts`) removes expired sessions, code hashes a day after they expire, per-IP and per-address counters, expired app tokens, invitations 90 days after they expire, and unconfirmed accounts that belong to no team after 30 days. People can download everything stem holds about them from their account page, remove an app's access, and delete their account. The privacy policy in `src/ui/legal.ts` (English and German) describes exactly this; if you change a period, change both.

Together this covers the GDPR rights that matter for a sign-in service: access and portability (the JSON export), erasure (account deletion, which also removes the person's sessions, passkeys and team memberships) and storage limitation (the cleanup cron).

## Tech stack

- TypeScript on [Hono](https://hono.dev), with [Better Auth](https://www.better-auth.com) (pinned) for email codes, passkeys, organizations and the OAuth provider, and `jose` for tokens
- Cloudflare Workers with D1, static assets, Email Service, rate limiting, Turnstile and a daily Cron Trigger
- esbuild for the browser bundle, Node.js 26 for builds and tests, Vitest for tests

## Self-hosting

You need a Cloudflare account with Workers Paid, a zone for the hostname, and a domain onboarded to Email Sending.

`wrangler.jsonc` is a template. Your hostname, database id, sender and keys never go into it: `scripts/render-config.mjs` fills its `<PLACEHOLDERS>` from environment variables (or a local `.env.deploy`) and writes `wrangler.deploy.jsonc`, which isn't committed.

```sh
npm install
npx wrangler d1 create stem-db              # note the database id
cp .env.deploy.example .env.deploy          # fill in hostname, database id, sender
npm run db:migrate                          # applies migrations/ to the remote database
npx wrangler secret put BETTER_AUTH_SECRET  # 32+ random bytes
npx wrangler secret put OPERATOR_TOKEN      # 32+ random bytes
npx wrangler secret put TURNSTILE_SECRET    # optional, with TURNSTILE_SITE_KEY
npm run deploy
```

Deploy settings (`.env.deploy`, or build variables in Workers Builds):

| Setting | Meaning |
| --- | --- |
| `STEM_HOSTNAME` | Hostname stem answers on. `https://` plus this is the OpenID Connect issuer. |
| `STEM_D1_DATABASE_ID` | Id of the `stem-db` D1 database. |
| `EMAIL_FROM` | Sender for codes and invitations, on a domain onboarded to Email Sending, e.g. `stem <login@example.com>`. |
| `ORG_ROLES` | Optional. Extra team roles, comma separated. |
| `RESOURCES` | Optional. APIs that get JWT access tokens, comma separated absolute URIs. |
| `TURNSTILE_SITE_KEY` | Optional. Turnstile widget for "email me a code". Needs the `TURNSTILE_SECRET` secret. |
| `MANDATE_APPS` | Optional. Apps that take mandates and their actions, as JSON. Empty turns mandates off. See [docs/mandates.md](docs/mandates.md). |

Set `LEGAL` (operator details as JSON, see the comment in `wrangler.jsonc`) as a variable in the Cloudflare dashboard. It fills `/privacy`, `/datenschutz`, `/imprint` and `/impressum`; without it those pages are hidden. `keep_vars` keeps it across deploys.

If you fork, point `SOURCE_URL` in `src/ui/layout.ts` at your repository (AGPL-3.0 section 13).

Register an app and create its first team with the operator API, as shown in [docs/integration.md](docs/integration.md).

### Deploy with Workers Builds

stem.shiftbloom.studio deploys with [Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/) on every push to `main`, and no API token is stored on GitHub. Connect the repository to the Worker in the Cloudflare dashboard (Settings > Build), use `npm ci` as the build command and `npm run deploy` as the deploy command, and add the settings above as build variables. The build picks up Node 26 from `.node-version`.

## Development

```sh
cp .dev.vars.example .dev.vars
npm run db:migrate:local
npm run dev          # codes are printed to the console
npm run check        # typecheck, tests, bundle
```

Node 26 or newer.

## Design

The pages follow the shiftbloom studio brand book: warm off-white paper and ink, Bloom Red `#FF2E52` as the only accent, the Bloom mark drawn as SVG, Clash Display for statements, General Sans for the interface and JetBrains Mono for labels and codes. When you fork, restyle `src/ui/layout.ts`.

## Costs

D1 reads and writes per sign-in are in the single digits, and the Worker runs for a few milliseconds per request. Email Sending includes 3,000 messages a month on Workers Paid. For a few hundred people, expect well under a dollar a month.

## Contributing

Issues and pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please don't report vulnerabilities in public issues. Use GitHub's private vulnerability reporting on this repository or email [safety@shiftbloom.studio](mailto:safety@shiftbloom.studio). [SECURITY.md](SECURITY.md) has the details.

## License

Copyright © 2026 shiftbloom studio and contributors.

stem is free software: you can redistribute it and/or modify it under the terms of the [GNU Affero General Public License](LICENSE) as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version (`AGPL-3.0-or-later`). If you run a modified version for others over a network, offer them its source and point `SOURCE_URL` at your fork.

---

stem is part of [shiftbloom studio](https://shiftbloom.studio), an open studio from Hamburg. All of our apps are open source at [github.com/shiftbloom-studio](https://github.com/shiftbloom-studio).
