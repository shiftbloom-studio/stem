// SPDX-License-Identifier: AGPL-3.0-or-later
// HTTP side of passes (see ./issuer.ts):
//   GET  /.well-known/private-token-issuer-directory   public keys (RFC 9578, section 4), for apps
//   POST /api/passes/issue                             blinded requests in, blind signatures out, for browsers
//   GET  /api/passes/status                            signed in? passes left today?
// Browsers call the last two from app pages, so they answer CORS requests from PASS_ORIGINS with credentials.
import { Hono, type Context } from "hono";
import type { Env } from "../env";
import { createAuth, type Exec } from "../auth";
import { activeKeys, issue, remaining, perDay, PassError, TOKEN_TYPE, MAX_BATCH } from "./issuer";
import { b64u, unb64u } from "./rsa";

type C = Context<{ Bindings: Env }>;

export const DIRECTORY_PATH = "/.well-known/private-token-issuer-directory";
const MAX_BODY = 32768;

/** Origins whose pages may fetch passes: stem itself and PASS_ORIGINS. */
export function passOrigins(env: Env): Set<string> {
  const out = new Set([new URL(env.STEM_URL).origin]);
  for (const o of (env.PASS_ORIGINS || "").split(",")) {
    try {
      const u = new URL(o.trim());
      if (u.protocol === "https:" || u.hostname === "localhost") out.add(u.origin);
    } catch {}
  }
  return out;
}

function cors(c: C): Record<string, string> | null {
  const origin = c.req.header("origin");
  if (!origin || !passOrigins(c.env).has(origin)) return null;
  return { "access-control-allow-origin": origin, "access-control-allow-credentials": "true", vary: "Origin" };
}

const reply = (c: C, h: Record<string, string> | null, body: unknown, status = 200) =>
  c.json(body as object, status as 200, { ...(h || {}), "cache-control": "no-store" });

async function signedIn(c: C) {
  try {
    const s = await createAuth(c.env, c.executionCtx as unknown as Exec).api.getSession({ headers: c.req.raw.headers });
    return s?.user?.id ? s.user.id : null;
  } catch {
    return null;
  }
}

/** The issuer directory. Public, cacheable, the same for everyone, so no visitor can be given a key of their own. */
export async function directory(env: Env) {
  const keys = await activeKeys(env);
  const body = {
    "issuer-request-uri": `${env.STEM_URL}/api/passes/issue`,
    "token-keys": keys.map((k) => ({ "token-type": TOKEN_TYPE, "token-key": b64u(k.tokenKey), "not-before": k.notBefore, "stem-not-after": k.notAfter, "stem-key-id": k.idB64 })),
    "stem-statement": "signed-in",
    "stem-per-day": perDay(env),
  };
  return new Response(JSON.stringify(body), {
    headers: { "content-type": "application/private-token-issuer-directory", "cache-control": "public, max-age=300", "access-control-allow-origin": "*" },
  });
}

export function passRoutes() {
  const r = new Hono<{ Bindings: Env }>();

  r.options("/*", (c) => {
    const h = cors(c);
    if (!h) return c.body(null, 403);
    return c.body(null, 204, { ...h, "access-control-allow-methods": "GET, POST", "access-control-allow-headers": "content-type", "access-control-max-age": "600" });
  });

  r.get("/status", async (c) => {
    const h = cors(c);
    if (c.req.header("origin") && !h) return c.json({ error: "origin_not_allowed" }, 403);
    const user = await signedIn(c);
    return reply(c, h, { signed_in: !!user, remaining: user ? await remaining(c.env, user) : 0, per_day: perDay(c.env) });
  });

  r.post("/issue", async (c) => {
    // Browsers always send Origin on POST. Only listed origins get passes, so other sites can't spend
    // someone's allowance or read the answer.
    const h = cors(c);
    if (!h) return c.json({ error: "origin_not_allowed" }, 403);
    if (c.env.API_RL) {
      const { success } = await c.env.API_RL.limit({ key: c.req.header("cf-connecting-ip") || "unknown" });
      if (!success) return reply(c, h, { error: "rate_limited", message: "Too many requests. Wait a minute." }, 429);
    }
    const user = await signedIn(c);
    if (!user) return reply(c, h, { error: "sign_in", message: "Sign in at stem to get passes." }, 401);
    if (Number(c.req.header("content-length") || 0) > MAX_BODY) return reply(c, h, { error: "bad_request" }, 400);
    const raw = new Uint8Array(await c.req.arrayBuffer());
    if (raw.length > MAX_BODY) return reply(c, h, { error: "bad_request" }, 400);

    const binary = (c.req.header("content-type") || "").split(";")[0].trim() === "application/private-token-request";
    let keyId: string | null = null;
    let requests: Uint8Array[];
    if (binary) {
      // RFC 9578, section 5: one request per call, the key picked by its truncated id.
      requests = [raw];
    } else {
      let b: { token_key_id?: unknown; requests?: unknown };
      try {
        b = JSON.parse(new TextDecoder().decode(raw));
      } catch {
        return reply(c, h, { error: "bad_request" }, 400);
      }
      if (typeof b.token_key_id !== "string" || !Array.isArray(b.requests) || !b.requests.length || b.requests.length > MAX_BATCH || !b.requests.every((x) => typeof x === "string" && x.length < 400))
        return reply(c, h, { error: "bad_request", message: `Send token_key_id and 1 to ${MAX_BATCH} requests.` }, 400);
      keyId = b.token_key_id;
      try {
        requests = (b.requests as string[]).map(unb64u);
      } catch {
        return reply(c, h, { error: "bad_request" }, 400);
      }
    }

    try {
      const out = await issue(c.env, user, keyId, requests);
      if (binary) return new Response(out.responses[0], { headers: { ...h, "content-type": "application/private-token-response", "cache-control": "no-store" } });
      return reply(c, h, { token_type: TOKEN_TYPE, token_key_id: out.key.idB64, responses: out.responses.map(b64u), remaining: out.remaining, per_day: out.perDay, resets_at: out.resetsAt });
    } catch (e) {
      if (e instanceof PassError) return reply(c, h, { error: e.code, message: e.message }, e.status);
      throw e;
    }
  });

  return r;
}
