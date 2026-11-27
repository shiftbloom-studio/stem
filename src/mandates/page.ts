// SPDX-License-Identifier: AGPL-3.0-or-later
// The approval page: the terms in plain words, then the passkey prompt. The passkey signs the hash of
// exactly what the page's script fetched from /api/auth/mandates/prepare, and stem only countersigns
// that, so what is shown here and what is signed come from the same stored request.
import { esc } from "../ui/html";
import { page } from "../ui/layout";
import type { Ui } from "../ui/pages";
import type { MandateApps, RequestTerms } from "./plugin";

const mb = (n: number) => (n >= 1048576 ? `${Math.round((n / 1048576) * 10) / 10} MB` : n >= 1024 ? `${Math.round(n / 1024)} KB` : `${n} bytes`);
export function duration(s: number) {
  if (s % 86400 === 0) return s === 86400 ? "1 day" : `${s / 86400} days`;
  if (s % 3600 === 0) return s === 3600 ? "1 hour" : `${s / 3600} hours`;
  return s >= 60 ? `${Math.round(s / 60)} minutes` : `${s} seconds`;
}

export function approvePage(ui: Ui, req: { id: string; userCode: string; terms: RequestTerms; expiresAt: Date } | null, apps: MandateApps, hasPasskey: boolean) {
  if (!req)
    return page(
      { title: "Agent request · stem.", legal: ui.legal },
      `<section style="padding-top:clamp(32px,6vw,64px);max-width:36em"><span class="label">agent request</span><h1 style="margin-top:14px">This request doesn't work anymore<em>.</em></h1>
<p class="lead">It may have expired or been answered already. Ask the agent for a new link.</p></section>`,
    );
  const t = req.terms;
  const rights = t.rights
    .map((r) => {
      const name = r.locations.map((l) => apps[l]?.name || new URL(l).host).join(", ");
      const acts = r.actions.map((a) => r.locations.map((l) => apps[l]?.actions[a]).find(Boolean) || a);
      const limits = [r.path_prefix !== undefined ? `only names starting with <code>${esc(r.path_prefix)}</code>` : "", r.max_bytes !== undefined ? `up to ${mb(r.max_bytes)} per request` : ""].filter(Boolean);
      return `<li><strong>${esc(name)}</strong>: ${acts.map(esc).join(", ")}${limits.length ? `<br><span class="small">${limits.join(" · ")}</span>` : ""}</li>`;
    })
    .join("");
  const budget = [t.budget.bytes !== undefined ? `${mb(t.budget.bytes)} in total` : "", t.budget.calls !== undefined ? `${t.budget.calls} requests in total` : ""].filter(Boolean);
  const terms = [
    `For ${duration(t.ttl)} from when you approve.`,
    t.del_max_depth ? `It may hand narrower copies to helpers, up to ${t.del_max_depth} level${t.del_max_depth > 1 ? "s" : ""} down. They can never get more than this.` : "It can't hand these rights to anyone else.",
    budget.length ? `Shared by everything it starts: ${budget.join(" and ")}.` : "",
  ].filter(Boolean);
  return page(
    { title: "Approve an agent · stem.", page: "mandate", legal: ui.legal, clearance: ui.turnstileSiteKey, data: { request: req.id } },
    `<section class="split">
  <div>
    <span class="label">agent request</span>
    <h1 style="margin-top:14px">An agent asks to act for you<em>.</em></h1>
    <p class="lead">${esc(t.purpose)}</p>
    <p class="small" style="margin-top:18px">Only approve if you started this agent yourself. It should show the code <strong>${esc(req.userCode)}</strong>.</p>
  </div>
  <div class="panel stack">
    <p style="margin:0"><strong>It will be able to:</strong></p>
    <ul class="seedlist">${rights}</ul>
    <ul class="seedlist">${terms.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
    ${hasPasskey
      ? `<button class="btn wide" type="button" id="approve">Approve with your passkey</button>
    <p class="small" style="margin:0">Your passkey signs these exact terms. Not even stem can widen them afterwards.</p>`
      : `<p style="margin:0">A mandate is signed with a passkey, and your account doesn't have one yet.</p>
    <a class="btn wide" href="/account">Add a passkey first</a>`}
    <button class="btn ghost wide" type="button" id="deny">Don't allow</button>
    <p class="small">You can stop it any time under "Your agents" on your <a href="/account">account page</a>.</p>
    <p class="err" id="error" role="alert" hidden></p>
  </div>
</section>`,
  );
}

export function answeredPage(ui: Ui) {
  return page(
    { title: "Agent request · stem.", legal: ui.legal },
    `<section style="padding-top:clamp(32px,6vw,64px);max-width:36em"><span class="label">agent request</span><h1 style="margin-top:14px">Done<em>.</em></h1>
<p class="lead">The agent picks up its answer on its own. You can close this page.</p>
<p style="margin-top:24px"><a class="btn" href="/account">Your agents</a></p></section>`,
  );
}
