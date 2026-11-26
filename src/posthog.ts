/**
 * PostHog: product analytics, error tracking and AI observability, all optional.
 * Nothing is sent unless the POSTHOG_KEY secret is set (the project's public "phc_" token).
 *
 * - Browser: pages load /_sb/init.js, which loads posthog-js through /_sb/* on this origin, so the
 *   Content-Security-Policy stays at 'self' and the visitor's browser never talks to PostHog directly.
 *   Cookieless: nothing is stored in the browser, no person profiles, no session replay.
 * - Worker: events and exceptions go straight to PostHog's capture API, without IP or person profile.
 */

export type PostHogEnv = { POSTHOG_KEY?: string; POSTHOG_HOST?: string };
type WaitUntil = { waitUntil(p: Promise<unknown>): void };
type Props = Record<string, unknown>;

/** Path prefix of the same-origin proxy. Deliberately not "posthog" or "analytics": blockers know those. */
export const PH_PREFIX = "/_sb";
const DEFAULT_HOST = "https://us.i.posthog.com";

export const phKey = (env: PostHogEnv): string | null => {
  const k = (env.POSTHOG_KEY || "").trim();
  return /^phc_[A-Za-z0-9_-]{10,}$/.test(k) ? k : null;
};
export function phHost(env: PostHogEnv): string {
  let h = (env.POSTHOG_HOST || DEFAULT_HOST).trim();
  while (h.endsWith("/")) h = h.slice(0, -1);
  return /^https:\/\/[a-z0-9.-]+$/i.test(h) ? h : DEFAULT_HOST;
}
/** PostHog Cloud serves the SDK from a separate host (us.i.posthog.com -> us-assets.i.posthog.com). */
export const phAssetsHost = (host: string) => host.replace(/^https:\/\/(us|eu)\.i\.posthog\.com$/, "https://$1-assets.i.posthog.com");

/** posthog-js batches stay far below this; anything bigger is not a PostHog client. */
const MAX_BODY = 1_000_000;
const METHODS = new Set(["GET", "HEAD", "POST", "OPTIONS"]);
const FORWARD = ["content-type", "content-encoding", "accept", "accept-encoding", "accept-language", "user-agent", "origin"];

/** Same-origin proxy for posthog-js: /_sb/static/* and /_sb/array/* to the assets host, the rest to the API host.
 * Returns null for any other path. Cookies and the app's own Authorization header never leave this Worker. */
export async function phProxy(req: Request, env: PostHogEnv, init?: { app: string; keep: RegExp; secret?: RegExp; extra?: Props }): Promise<Response | null> {
  const url = new URL(req.url);
  if (url.pathname !== PH_PREFIX && !url.pathname.startsWith(PH_PREFIX + "/")) return null;
  const key = phKey(env);
  if (!key) return new Response("not found", { status: 404 });
  const path = url.pathname.slice(PH_PREFIX.length) || "/";
  if (path === "/init.js" && init) {
    return new Response(initScript(key, phHost(env), init), { headers: { "content-type": "application/javascript; charset=utf-8", "cache-control": "public, max-age=300" } });
  }
  if (!METHODS.has(req.method)) return new Response("method not allowed", { status: 405 });
  let body: BodyInit | undefined;
  if (req.method === "POST") {
    if (Number(req.headers.get("content-length") || 0) > MAX_BODY) return new Response("payload too large", { status: 413 });
    const buf = await readCapped(req, MAX_BODY);
    if (!buf) return new Response("payload too large", { status: 413 });
    body = buf.buffer as ArrayBuffer; // freshly allocated, so the buffer is exactly the body
  }
  const host = /^\/(static|array)\//.test(path) ? phAssetsHost(phHost(env)) : phHost(env);
  const headers = new Headers();
  for (const name of FORWARD) {
    const v = req.headers.get(name);
    if (v) headers.set(name, v);
  }
  // capture v1 sends the project token as a bearer token; anything else (such as an app's API token) is dropped
  const auth = req.headers.get("authorization");
  if (auth && /^Bearer phc_/.test(auth)) headers.set("authorization", auth);
  // cookieless mode hashes the visitor's IP and user agent on PostHog's side, so it needs the real address
  const ip = req.headers.get("cf-connecting-ip");
  if (ip) headers.set("x-forwarded-for", ip);
  // the path only ever selects an endpoint on the PostHog host; anything that would leave it is refused
  const target = new URL(path.replace(/^\/+/, "/") + url.search, host);
  if (target.origin !== new URL(host).origin) return new Response("not found", { status: 404 });
  let res: Response;
  try {
    res = await fetch(target.toString(), {
      method: req.method,
      headers,
      body,
      redirect: "manual",
    });
  } catch {
    return new Response("upstream unavailable", { status: 502 });
  }
  const out = new Response(res.body, res);
  out.headers.delete("set-cookie");
  return out;
}

/** The request body, or null once it passes `max` bytes (a missing or wrong content-length can't get around the cap). */
async function readCapped(req: Request, max: number): Promise<Uint8Array | null> {
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const parts: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) { void reader.cancel(); return null; }
    parts.push(value);
  }
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.byteLength; }
  return out;
}

/** <script> tag for the pages that should report to PostHog. Empty when PostHog is off. */
export const phScriptTag = (env: PostHogEnv) => (phKey(env) ? `<script src="${PH_PREFIX}/init.js" defer></script>` : "");

/** posthog-js loader plus config. URLs are reduced before sending: query and hash always go, and any path that
 * `keep` does not match (an item, a claim link) is reported as "/[private]". */
function initScript(key: string, host: string, o: { app: string; keep: RegExp; secret?: RegExp; extra?: Props }) {
  const config = {
    api_host: PH_PREFIX,
    ui_host: host.replace(/^https:\/\/(us|eu)\.i\.posthog\.com$/, "https://$1.posthog.com"),
    cookieless_mode: "always",
    person_profiles: "identified_only",
    disable_session_recording: true,
    // a #hash may carry a secret (grow's first-run link holds the new key there): posthog-js must never read it
    disable_capture_url_hashes: true,
    capture_pageview: true,
    capture_pageleave: true,
    capture_exceptions: true,
    capture_heatmaps: true,
    capture_dead_clicks: false,
    capture_performance: { web_vitals: true, network_timing: false },
    // clicks on buttons and links only, never what is typed or shown (text is masked)
    autocapture: { dom_event_allowlist: ["click"], element_allowlist: ["a", "button"], capture_copied_text: false },
    mask_all_text: true,
    // before_send keeps only id, class and data-ph attributes, so clicks can be told apart without link targets or labels
    mask_all_element_attributes: false,
    mask_personal_data_properties: true,
    enable_recording_console_log: false,
    disable_web_experiments: false,
    ...o.extra,
  };
  // the stub below is PostHog's standard loader snippet; it loads /_sb/static/array.js
  return `!function(t,e){var o,n,p,r;e.__SV||(window.posthog=e,e._i=[],e.init=function(i,s,a){function g(t,e){var o=e.split(".");2==o.length&&(t=t[o[0]],e=o[1]),t[e]=function(){t.push([e].concat(Array.prototype.slice.call(arguments,0)))}}(p=t.createElement("script")).type="text/javascript",p.crossOrigin="anonymous",p.async=!0,p.src=s.api_host.replace(".i.posthog.com","-assets.i.posthog.com")+"/static/array.js",(r=t.getElementsByTagName("script")[0]).parentNode.insertBefore(p,r);var u=e;for(void 0!==a?u=e[a]=[]:a="posthog",u.people=u.people||[],u.toString=function(t){var e="posthog";return"posthog"!==a&&(e+="."+a),t||(e+=" (stub)"),e},u.people.toString=function(){return u.toString(1)+".people (stub)"},o="capture identify alias people.set people.set_once set_config register register_once unregister opt_out_capturing has_opted_out_capturing opt_in_capturing reset isFeatureEnabled onFeatureFlags getFeatureFlag getFeatureFlagPayload reloadFeatureFlags group updateEarlyAccessFeatureEnrollment getEarlyAccessFeatures getActiveMatchingSurveys getSurveys onSessionId".split(" "),n=0;n<o.length;n++)g(u,o[n]);e._i.push([i,s,a])},e.__SV=1)}(document,window.posthog||[]);
(function(){
var KEEP=new RegExp(${JSON.stringify(o.keep.source)});
var SECRET=new RegExp(${JSON.stringify(o.secret?.source ?? "(?!)")},"g");
function path(p){p=(p||"/").replace(/\\/+$/,"")||"/";return KEEP.test(p)?p:"/[private]"}
function clean(v){if(typeof v!=="string"||!/^https?:/.test(v))return v;try{var u=new URL(v,location.origin);if(u.origin!==location.origin)return u.origin;return u.origin+path(u.pathname)}catch(e){return null}}
var URLS=["$external_click_url","$current_url","$referrer","$initial_referrer","$initial_current_url","$session_entry_url","$prev_pageview_url","$session_entry_referrer"];
var PATHS=["$pathname","$initial_pathname","$session_entry_pathname","$prev_pageview_pathname"];
function mask(t){return typeof t!=="string"?t:t.replace(/"[^"]*"|'[^']*'|\\x60[^\\x60]*\\x60/g,'"[masked]"').replace(/\\b[a-z][a-z0-9+.-]*:\\/\\/\\S+/gi,"[url]").replace(/[A-Za-z0-9_-]{16,}/g,"[masked]").slice(0,500)}
var ATTR=/^attr__(id|class|data-ph.*)$/;
function scrub(ev){if(!ev||!ev.properties)return ev;var p=ev.properties,i,k;for(i=0;i<URLS.length;i++)if(URLS[i] in p)p[URLS[i]]=clean(p[URLS[i]]);for(i=0;i<PATHS.length;i++)if(typeof p[PATHS[i]]==="string")p[PATHS[i]]=path(p[PATHS[i]]);
if(typeof p.$elements_chain==="string")p.$elements_chain=p.$elements_chain.replace(/attr__(?!id=|class=|data-ph)[\\w-]+="(?:[^"\\\\]|\\\\.)*"/g,"").replace(/href="(?:[^"\\\\]|\\\\.)*"/g,'href="[private]"');
if(Array.isArray(p.$elements))for(i=0;i<p.$elements.length;i++){var el=p.$elements[i];if(el){for(k in el)if(k.indexOf("attr__")===0&&!ATTR.test(k))delete el[k];if("href" in el)el.href="[private]"}}
for(k in p)if(/^\\$web_vitals_.*_event$/.test(k)&&p[k]&&typeof p[k]==="object"&&"$current_url" in p[k])p[k].$current_url=clean(p[k].$current_url);
if(Array.isArray(p.$exception_list))for(i=0;i<p.$exception_list.length;i++){var x=p.$exception_list[i];if(x)x.value=mask(x.value)}
if("$exception_message" in p)p.$exception_message=mask(p.$exception_message);
if(p.$set)delete p.$set;if(p.$set_once)delete p.$set_once;p.app=${JSON.stringify(o.app)};ev.properties=deep(p,0);return ev}
// last pass over every string and key (heatmap data is keyed by URL, web vitals and exceptions carry URLs too)
function str(v){if(/^https?:/.test(v)){v=clean(v);if(v===null)return null}return v.replace(SECRET,"[masked]")}
function deep(v,d){if(typeof v==="string")return str(v);if(!v||typeof v!=="object"||d>8)return v;if(Array.isArray(v)){for(var i=0;i<v.length;i++)v[i]=deep(v[i],d+1);return v}
var out={},k,n;for(k in v){if(!Object.prototype.hasOwnProperty.call(v,k))continue;n=str(k)||k;var x=deep(v[k],d+1);out[n]=Array.isArray(out[n])&&Array.isArray(x)?out[n].concat(x):x}return out}
var c=${JSON.stringify(config)};c.before_send=scrub;posthog.init(${JSON.stringify(key)},c);
window.sbTrack=function(e,p){try{posthog.capture(e,p||{})}catch(x){}};
})();
`;
}

// ---------- Worker side ----------

function send(env: PostHogEnv, events: Array<{ event: string; properties: Props }>): Promise<void> {
  const key = phKey(env);
  if (!key) return Promise.resolve();
  const batch = events.map(({ event, properties: { distinct_id, ...properties } }) => ({
    event,
    // a caller may pass a pseudonymous distinct_id (a hash, never a name or key) to tie events of one account together
    distinct_id: typeof distinct_id === "string" && distinct_id ? distinct_id : crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    // no person profile, no IP and no location for server events
    properties: { $process_person_profile: false, $geoip_disable: true, $ip: null, $lib: "shiftbloom-worker", ...properties },
  }));
  return fetch(phHost(env) + "/batch/", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ api_key: key, batch }), signal: AbortSignal.timeout(5000) })
    .then((r) => { void r.body?.cancel(); })
    .catch(() => {});
}

const later = (ctx: WaitUntil | null | undefined, p: Promise<void>) => (ctx ? (ctx.waitUntil(p), Promise.resolve()) : p);

/** One server-side event. With ctx it is sent after the response; without, the returned promise sends it. */
export function phCapture(env: PostHogEnv, ctx: WaitUntil | null | undefined, event: string, properties: Props = {}) {
  return later(ctx, send(env, [{ event, properties }]));
}

/** Long random strings (tokens, codes, ids) are masked so an error message can't carry them to PostHog. */
export const scrubText = (s: string) =>
  s
    .slice(0, 2000)
    // quoted parts: V8 quotes the input in JSON.parse errors, which may be a paste or a URL to shorten
    .replace(/"[^"]*"|'[^']*'|`[^`]*`/g, '"[masked]"')
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, "[url]")
    .replace(/[A-Za-z0-9_-]{16,}/g, "[masked]")
    // item ids and codes are short: mask every word that mixes letters and digits
    .replace(/[A-Za-z0-9_-]{6,}/g, (w) => (/\d/.test(w) && /[A-Za-z]/.test(w) ? "[masked]" : w))
    .slice(0, 500);

function frames(stack: string | undefined) {
  const out: Props[] = [];
  for (const line of (stack || "").split("\n").slice(1, 30)) {
    const m = /^\s*at (?:(.+?) \()?(.+?):(\d+):(\d+)\)?$/.exec(line);
    if (m) out.push({ platform: "custom", lang: "javascript", function: m[1] || "?", filename: m[2], lineno: Number(m[3]), colno: Number(m[4]), in_app: !/node_modules|^node:/.test(m[2]) });
  }
  return out.reverse();
}

/** Error tracking for the Worker: an $exception event with the message (long strings masked) and stack. */
export function phException(env: PostHogEnv, ctx: WaitUntil | null | undefined, err: unknown, properties: Props = {}) {
  const e = err instanceof Error ? err : new Error(String(err));
  return phCapture(env, ctx, "$exception", {
    $exception_list: [{ type: e.name || "Error", value: scrubText(e.message || String(err)), mechanism: { handled: false, synthetic: false }, stacktrace: { type: "raw", frames: frames(e.stack) } }],
    ...properties,
  });
}

/** AI observability for a Workers AI call: model, latency, tokens and errors. Prompts and outputs are never sent. */
export async function phAi<T>(env: PostHogEnv, ctx: WaitUntil | null | undefined, o: { model: string; kind?: "generation" | "embedding"; traceId?: string; properties?: Props }, run: () => Promise<T>): Promise<T> {
  if (!phKey(env)) return run();
  const started = Date.now();
  const base = {
    $ai_trace_id: o.traceId || crypto.randomUUID(),
    $ai_model: o.model,
    $ai_provider: "cloudflare-workers-ai",
    ...o.properties,
  };
  const event = o.kind === "embedding" ? "$ai_embedding" : "$ai_generation";
  try {
    const out = await run();
    const usage = (out as { usage?: { prompt_tokens?: number; completion_tokens?: number } } | null)?.usage;
    await later(ctx, send(env, [{ event, properties: { ...base, $ai_latency: (Date.now() - started) / 1000, $ai_http_status: 200, $ai_input_tokens: usage?.prompt_tokens, $ai_output_tokens: usage?.completion_tokens } }]));
    return out;
  } catch (e) {
    await later(ctx, send(env, [{ event, properties: { ...base, $ai_latency: (Date.now() - started) / 1000, $ai_is_error: true, $ai_error: scrubText(String(e)) } }]));
    throw e;
  }
}

/** Rough size class for events, never the exact size. */
export function sizeBucket(bytes: number) {
  const mb = bytes / 1048576;
  return mb < 0.1 ? "<100KB" : mb < 1 ? "<1MB" : mb < 10 ? "<10MB" : mb < 100 ? "<100MB" : ">=100MB";
}
