# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting (Security tab → "Report a vulnerability") or email **safety@shiftbloom.studio** with "stem security" in the subject. Include steps to reproduce and the impact you see.

We aim to acknowledge reports within 3 working days and to ship a fix or mitigation within 14 days for confirmed issues. We'll credit you in the release notes unless you'd rather stay anonymous.

## Supported versions

Only the latest `main` is supported. Self-hosters should redeploy after security fixes.

## Scope

In scope: signing in as someone else, session or token theft, bypassing PKCE, redirect URI checks or token audiences, reading or changing another app's organizations through the directory API, registering clients without the operator token, XSS on the stem origin, and leaks of codes, secrets or private keys.

Out of scope: volumetric DDoS (handle it in your Cloudflare zone), and missing rate limits on endpoints that don't touch accounts.
