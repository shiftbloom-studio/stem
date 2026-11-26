# Sealed apps

Most apps on one stem see the same person under the same `sub`, and can ask for the email address. That's convenient for apps that belong together. For apps that only need to know "this is the same person as last time", it's more than they need. Two of them could join their user lists on `sub` or on the address, and a leak at one of them hands out addresses.

A sealed app gets less:

- **Its own id for each person.** stem gives a sealed app's clients [pairwise subject identifiers](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg): an HMAC of the person's stem id and the host of the client's redirect URI. The same person has a different `sub` in every sealed app, stable across sign-ins, and the ids can't be matched without stem's secret.
- **No email address.** Sealed clients are registered without the `email` scope, so stem refuses to grant it, and the access token claims leave the address out even if a client asks for it.
- **Opaque access tokens only.** Signed JWT access tokens for an API, and client-credentials tokens, carry stem's shared user id. Sealed clients can't ask for a `resource` and get no `client_credentials` grant. Read the person from `/api/auth/oauth2/userinfo`, which returns the pairwise `sub`, or from the ID token.
- **No people through the directory.** Members, invitations and user profiles carry the shared id and the address, so the directory API and the app gateway answer `403 sealed_app` for them. Organizations themselves stay available.

While sealed apps are on, stem also stores less about every session: the network of the IP address (`203.0.113.0/24`, or the first 48 bits of an IPv6 address) and the browser and system (`Firefox on Windows`) instead of the full address and user agent. The account page still shows where someone is signed in. The privacy policy changes its wording to match.

Sign-in itself doesn't change. People still sign in with a passkey or an email code, and stem still keeps their address to send codes. Sealed apps protect people from the apps and from leaks at the apps, not from stem.

## Turning it on

1. Set the secret: `npx wrangler secret put PAIRWISE_SECRET` with 32 or more random characters. **Never change or remove it once a sealed app has users.** Every pairwise `sub` would change and the apps would lose their users.
2. Set the `SEALED_APPS` variable (build variable with Workers Builds) to the app ids, comma separated, for example `drop,leaf,convert`.
3. Register the app's client with the operator API as usual. For an app listed in `SEALED_APPS`, stem registers it as pairwise without the email scope:

```sh
curl -X POST https://stem.example.com/api/v1/operator/clients \
  -H "authorization: Bearer $OPERATOR_TOKEN" -H "content-type: application/json" \
  -d '{ "app": "drop", "name": "drop", "redirect_uris": ["https://drop.example.com/auth/callback"], "skip_consent": true }'
```

The response shows `"subject_type": "pairwise"` and a `scope` without `email`. All redirect URIs of a pairwise client must share one host; that host is part of the id. Keep it when you add clients for the same app, or the ids change.

Both settings are needed. Without either, sealed apps are off and stem behaves exactly as before.

## Things to know

- **Existing clients keep their ids.** Whether a client is pairwise is fixed when it is registered. A client registered before its app was sealed keeps the shared `sub`; register a new client to switch, knowing the app sees its existing users as new ones.
- **Turning it off again.** Without `SEALED_APPS`, pairwise clients still get pairwise ids as long as `PAIRWISE_SECRET` is set, and still have no email scope. The directory guard and the coarse sessions stop.
- **Rotating the secret** isn't supported. A new secret means new ids for everyone in every sealed app.
- **It is still personal data.** A pairwise id is pseudonymous, not anonymous: stem can map it back.
