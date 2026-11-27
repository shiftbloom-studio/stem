// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser side of mandates: the approval page and "Your agents" on the account page.
import { startAuthentication } from "@simplewebauthn/browser";

type Fetch = <T>(path: string, init: { method: "GET" | "POST"; body?: unknown; query?: Record<string, string> }) => Promise<{ data: T | null; error: { message?: string; code?: string; status?: number } | null }>;
type Helpers = {
  $fetch: Fetch;
  $: <T extends HTMLElement = HTMLElement>(id: string) => T | null;
  fail: (msg: string | null) => void;
  busy: <T>(btn: HTMLButtonElement | null, fn: () => Promise<T>) => Promise<T | undefined>;
  li: (main: string, meta: string, action?: { label: string; run: () => void }) => HTMLLIElement;
  fmt: (d: string | Date) => string;
};

/** The challenge is SHA-256 of the canonical mandate. Check it here too, so the page signs only what it got. */
const canon = (v: unknown): string =>
  Array.isArray(v) ? `[${v.map(canon).join(",")}]`
  : v && typeof v === "object" ? `{${Object.keys(v as object).filter((k) => (v as Record<string, unknown>)[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${canon((v as Record<string, unknown>)[k])}`).join(",")}}`
  : JSON.stringify(v);
async function challengeOf(core: unknown) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canon(core))));
  let s = "";
  for (const x of d) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/={1,2}$/, "");
}

export function approveMandate(h: Helpers) {
  const id = document.body.dataset.request || "";
  const approve = h.$<HTMLButtonElement>("approve"), deny = h.$<HTMLButtonElement>("deny");
  approve?.addEventListener("click", () => h.busy(approve, async () => {
    h.fail(null);
    const prep = await h.$fetch<{ mandate: unknown; publicKey: { challenge: string; rpId: string; allowCredentials: { id: string; type: "public-key"; transports?: string[] }[]; userVerification: "required"; timeout: number } }>("/mandates/prepare", { method: "POST", body: { request_id: id } });
    if (prep.error || !prep.data) { h.fail(prep.error?.message || "We couldn't prepare the mandate."); return; }
    if ((await challengeOf(prep.data.mandate)) !== prep.data.publicKey.challenge) { h.fail("The terms don't match what would be signed. Nothing was signed."); return; }
    let response;
    try {
      response = await startAuthentication({ optionsJSON: prep.data.publicKey as never });
    } catch (e) {
      if (!/cancel|abort|NotAllowed/i.test(String((e as Error).message || e))) h.fail("Your passkey didn't respond. Try again.");
      return;
    }
    const r = await h.$fetch("/mandates/approve", { method: "POST", body: { request_id: id, response } });
    if (r.error) { h.fail(r.error.message || "That didn't work. Try again."); return; }
    location.assign("/mandates/done");
  }));
  deny?.addEventListener("click", () => h.busy(deny, async () => {
    const r = await h.$fetch("/mandates/deny", { method: "POST", body: { request_id: id } });
    if (r.error) { h.fail(r.error.message || "That didn't work. Try again."); return; }
    location.assign("/mandates/done");
  }));
}

type Agent = { id: string; purpose: string; status: string; created_at: string; expires_at: string; remaining: { bytes?: number; calls?: number } | null; calls: number | null; rights: { apps: string[]; actions: string[]; path_prefix?: string }[] };
type Step = { seq: number; at: number; depth: number; action: string; path: string | null; bytes: number; outcome: string };

export async function loadAgents(h: Helpers) {
  const ul = h.$("agents");
  if (!ul) return;
  ul.replaceChildren();
  const res = await h.$fetch<Agent[]>("/mandates/list", { method: "GET" });
  const list = res.data || [];
  if (!list.length) { ul.append(h.li("No agents", "Agents show up here once you approve one.")); return; }
  for (const a of list) {
    const what = a.rights.map((r) => `${r.apps.join(", ")}: ${r.actions.join(", ")}${r.path_prefix ? ` in ${r.path_prefix}` : ""}`).join("; ");
    const state = a.status === "active" ? `until ${h.fmt(a.expires_at)}${a.calls ? ` · ${a.calls} request${a.calls > 1 ? "s" : ""}` : ""}` : a.status === "revoked" ? "stopped" : a.status;
    const row = h.li(a.purpose, `${what} · ${state}`, a.status === "active" ? {
      label: "Stop",
      run: async () => {
        if (!confirm(`Stop "${a.purpose}"? It and every helper it started lose access on their next request.`)) return;
        const r = await h.$fetch("/mandates/revoke", { method: "POST", body: { id: a.id } });
        if (r.error) h.fail(r.error.message || "That didn't work."); else void loadAgents(h);
      },
    } : undefined);
    const more = document.createElement("button");
    more.className = "btn ghost sm"; more.type = "button"; more.textContent = "Trail";
    more.addEventListener("click", () => showTrail(h, a.id));
    row.append(more);
    ul.append(row);
  }
}

async function showTrail(h: Helpers, id: string) {
  const ol = h.$("trail");
  if (!ol) return;
  const r = await h.$fetch<Step[]>("/mandates/trail", { method: "GET", query: { id } });
  ol.replaceChildren();
  const steps = r.data || [];
  if (!steps.length) ol.append(h.li("Nothing yet", "Requests made with this mandate show up here."));
  for (const s of steps) ol.append(h.li(`${s.action}${s.path ? ` ${s.path}` : ""} · ${s.outcome}`, `${h.fmt(new Date(s.at))}${s.depth ? ` · helper level ${s.depth}` : ""}${s.bytes ? ` · ${s.bytes} bytes` : ""}`));
  ol.hidden = false;
}
