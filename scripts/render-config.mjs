// SPDX-License-Identifier: AGPL-3.0-or-later
// Fills the <PLACEHOLDERS> in wrangler.jsonc from environment variables (or a local .env.deploy file)
// and writes wrangler.deploy.jsonc, which `npm run deploy` uses. Keeps installation-specific values
// (hostname, database id, sender, keys) out of the repository.
//   node scripts/render-config.mjs            real values → wrangler.deploy.jsonc (deploys, remote migrations)
//   node scripts/render-config.mjs --example  example values → wrangler.local.jsonc (wrangler dev, CI dry run)
import { readFileSync, writeFileSync, existsSync } from "node:fs";

/** Required settings, with the example value for local development and the CI dry run. */
const REQUIRED = {
  STEM_HOSTNAME: ["Hostname stem answers on and the OpenID Connect issuer, e.g. auth.example.com", "stem.example.com"],
  STEM_D1_DATABASE_ID: ["ID of the stem-db D1 database (npx wrangler d1 list)", "00000000-0000-0000-0000-000000000000"],
  EMAIL_FROM: ['Sender for codes and invitations, e.g. "stem <login@example.com>"', "stem <login@example.com>"],
};
/** Optional settings (<NAME?> in wrangler.jsonc). Empty means off. */
const OPTIONAL = {
  ORG_ROLES: "Extra team roles, comma separated",
  RESOURCES: "APIs that get JWT access tokens, comma separated absolute URIs",
  TURNSTILE_SITE_KEY: "Turnstile site key for \"email me a code\" (also set the TURNSTILE_SECRET secret)",
  PASS_ORIGINS: "App pages that may fetch passes, comma separated origins",
};

const example = process.argv.includes("--example");
const env = {};
if (example) {
  for (const [k, [, v]] of Object.entries(REQUIRED)) env[k] = v;
} else {
  Object.assign(env, process.env);
  if (existsSync(".env.deploy")) {
    for (const line of readFileSync(".env.deploy", "utf8").split("\n")) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
      if (m && !(m[1] in process.env)) env[m[1]] = m[2].replace(/^["']|["']$/g, "");
    }
  }
}

const missing = Object.keys(REQUIRED).filter((k) => !env[k]);
if (missing.length) {
  console.error("Missing deploy settings:\n" + missing.map((k) => `  ${k}: ${REQUIRED[k][0]}`).join("\n"));
  console.error("Optional:\n" + Object.entries(OPTIONAL).map(([k, d]) => `  ${k}: ${d}`).join("\n"));
  console.error("Set them as environment variables (Workers Builds: Settings > Build > Variables) or in .env.deploy.");
  process.exit(1);
}
if (!/^[a-z0-9.-]+$/i.test(env.STEM_HOSTNAME)) {
  console.error("STEM_HOSTNAME must be a bare hostname, without https:// or a path.");
  process.exit(1);
}

const json = (v) => JSON.stringify(v ?? "").slice(1, -1);
let config = readFileSync("wrangler.jsonc", "utf8");
for (const k of Object.keys(REQUIRED)) config = config.replaceAll(`<${k}>`, json(env[k]));
config = config.replace(/<([A-Z0-9_]+)\?>/g, (_m, k) => json(env[k]));
const left = config.replace(/^\s*\/\/.*$/gm, "").match(/<[A-Z0-9_]+\??>/);
if (left) {
  console.error(`Unfilled placeholder ${left[0]} in wrangler.jsonc`);
  process.exit(1);
}
const out = example ? "wrangler.local.jsonc" : "wrangler.deploy.jsonc";
writeFileSync(out, config);
console.log(`wrote ${out}${example ? " (example values)" : ""}`);
