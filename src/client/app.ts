// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser code for stem's pages. Bundled to /assets/app.js; no inline scripts anywhere (strict CSP).
import { createAuthClient } from "better-auth/client";
import { emailOTPClient, organizationClient } from "better-auth/client/plugins";
import { passkeyClient } from "@better-auth/passkey/client";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { approveMandate, loadAgents } from "./mandates";

const client = createAuthClient({
  basePath: "/api/auth",
  // We follow redirects ourselves, so a new account can pick a name before going back to the app.
  disableDefaultFetchPlugins: true,
  plugins: [emailOTPClient(), passkeyClient(), organizationClient(), oauthProviderClient()],
});

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T | null;
const show = (el: HTMLElement | null, on = true) => el && (el.hidden = !on);
const SKIP_PASSKEY = "stem_skip_passkey";

function fail(msg: string | null) {
  const e = $("error");
  if (!e) return;
  e.textContent = msg || "";
  show(e, !!msg);
}

type ApiError = { code?: string; message?: string; status?: number } | null | undefined;
function explain(err: ApiError, fallback = "Something went wrong. Try again."): string {
  if (!err) return fallback;
  if (err.status === 429) return "Too many attempts. Wait a minute, then try again.";
  const code = err.code || "";
  if (/INVALID_OTP|OTP_EXPIRED|TOO_MANY_ATTEMPTS/.test(code)) return code === "OTP_EXPIRED" ? "That code has expired. Ask for a new one." : code === "TOO_MANY_ATTEMPTS" ? "Too many wrong codes. Ask for a new one." : "That code isn't right. Check it and try again.";
  if (/CAPTCHA/i.test(code) || /captcha/i.test(err.message || "")) return "We couldn't confirm you're a person. Try the check again.";
  if (/SESSION|FRESH/i.test(code)) return "For your safety, sign in again first, then try once more.";
  return err.message || fallback;
}

async function busy<T>(btn: HTMLButtonElement | null, fn: () => Promise<T>): Promise<T | undefined> {
  if (btn) btn.disabled = true;
  try { return await fn(); } finally { if (btn) btn.disabled = false; }
}

const passkeysSupported = () => typeof window.PublicKeyCredential === "function";

// WebAuthn Signal API (Chrome 132+, others to follow): tells the password manager what the server knows,
// so it can hide passkeys we no longer accept and show the current email and name. Best effort only.
type PasskeySignals = {
  isConditionalMediationAvailable?: () => Promise<boolean>;
  signalUnknownCredential?: (o: { rpId: string; credentialId: string }) => Promise<void>;
  signalCurrentUserDetails?: (o: { rpId: string; userId: string; name: string; displayName: string }) => Promise<void>;
};
const pkApi = () => (passkeysSupported() ? (window.PublicKeyCredential as unknown as PasskeySignals) : undefined);
async function signal<K extends "signalUnknownCredential" | "signalCurrentUserDetails">(kind: K, args: Parameters<NonNullable<PasskeySignals[K]>>[0]) {
  const api = pkApi();
  const fn = api?.[kind] as ((a: typeof args) => Promise<void>) | undefined;
  if (typeof fn !== "function") return;
  // Never hold up a sign-in for this.
  await Promise.race([fn.call(api, args).catch(() => {}), new Promise((r) => setTimeout(r, 1000))]);
}
/** The credential is gone on our side: the password manager can stop offering it. */
const forgetCredential = (credentialId: string) => signal("signalUnknownCredential", { rpId: location.hostname, credentialId });

type PasskeySignIn = {
  data: unknown;
  error: { code?: string; message?: string; status?: number } | null;
  webauthn?: { response: { id: string; response: { userHandle?: string } } };
};
const next = () => {
  const n = new URLSearchParams(location.search).get("next") || "/account";
  // Same rules as safeNext on the server. Control characters matter: the URL parser drops tabs and
  // newlines, so "/\t/evil.example" would turn into "//evil.example".
  if (n.length > 512 || !n.startsWith("/") || n.startsWith("//") || n.includes("\\") || /[\u0000-\u001f]/.test(n)) return "/account";
  try {
    const u = new URL(n, location.origin);
    // Rebuilt on our own origin, so the result can only ever point back at this site.
    return u.origin === location.origin ? `${location.origin}${u.pathname}${u.search}${u.hash}` : "/account";
  } catch {
    return "/account";
  }
};

/** After signing in: an OAuth flow answers with { redirect, url }; otherwise go to `next`. */
function destination(data: unknown): string {
  const d = data as { redirect?: boolean; url?: string } | null;
  if (d?.redirect && d.url) {
    try {
      const u = new URL(d.url, location.origin);
      if (u.protocol === "https:" || u.protocol === "http:") return u.toString();
    } catch {}
  }
  return next();
}

// ---------- sign in ----------
function signIn() {
  const startStep = $("step-start"), codeForm = $<HTMLFormElement>("code-form"), nameForm = $<HTMLFormElement>("name-form"), offer = $("passkey-offer");
  let email = "";
  let target = "/account";

  async function afterSignIn(data: unknown) {
    target = destination(data);
    const s = await client.getSession();
    const user = s.data?.user;
    show(startStep, false); show(codeForm, false);
    if (user && !user.name?.trim()) { show(nameForm); $<HTMLInputElement>("name")?.focus(); return; }
    await maybeOfferPasskey();
  }

  async function maybeOfferPasskey() {
    show(nameForm, false);
    let skip = false;
    try { skip = localStorage.getItem(SKIP_PASSKEY) === "1"; } catch {}
    if (passkeysSupported() && !skip) {
      const list = await client.passkey.listUserPasskeys();
      if (!list.error && Array.isArray(list.data) && list.data.length === 0) { show(offer); return; }
    }
    location.assign(target);
  }

  /** Handles the result of a passkey sign-in, from the button or from autofill. True when signed in. */
  async function afterPasskey(res: PasskeySignIn): Promise<boolean> {
    const wa = res.webauthn;
    if (res.error) {
      if (res.error.code === "PASSKEY_NOT_FOUND") {
        // Deleted on the account page, or with the account: hide it in the password manager.
        if (wa?.response.id) await forgetCredential(wa.response.id);
        fail("That passkey isn't linked to a stem account anymore. Get a code by email instead.");
        return false;
      }
      const cancelled = res.error.status === 400 && /cancel|abort|NotAllowed/i.test(res.error.message || "");
      if (!cancelled) fail(explain(res.error as ApiError, "That didn't work. Try again, or get a code by email."));
      return false;
    }
    target = destination(res.data);
    // Keep the email address and name in the password manager current, also for passkeys made
    // before the email was their user name. Our user handles are per passkey, so this only touches this one.
    const handle = wa?.response.response.userHandle;
    if (handle && pkApi()?.signalCurrentUserDetails) {
      const s = await client.getSession();
      const u = s.data?.user;
      if (u?.email) await signal("signalCurrentUserDetails", { rpId: location.hostname, userId: handle, name: u.email, displayName: u.name?.trim() || u.email });
    }
    location.assign(target);
    return true;
  }

  // Conditional UI: saved passkeys show up in the email field's autofill list. Runs until the person
  // picks one, presses the passkey button (which cancels it) or leaves the page.
  let autofillRunning = false;
  async function passkeyAutofill() {
    if (autofillRunning) return;
    const api = pkApi();
    if (!api?.isConditionalMediationAvailable) return;
    try { if (!(await api.isConditionalMediationAvailable())) return; } catch { return; }
    autofillRunning = true;
    try {
      const res = (await client.signIn.passkey({ autoFill: true, returnWebAuthnResponse: true })) as unknown as PasskeySignIn;
      if (await afterPasskey(res)) return;
    } finally { autofillRunning = false; }
  }

  const pkBtn = $<HTMLButtonElement>("passkey-btn");
  if (passkeysSupported()) { show(pkBtn); show($("passkey-or")); }
  // An app asked for a fresh passkey: put it under the person's finger. Browsers need a tap to start it.
  if (passkeysSupported() && pkBtn?.dataset.stepUp !== undefined) pkBtn.focus();
  pkBtn?.addEventListener("click", () => busy(pkBtn, async () => {
    fail(null);
    const res = (await client.signIn.passkey({ returnWebAuthnResponse: true })) as unknown as PasskeySignIn;
    // Starting this ceremony cancelled the autofill one; offer autofill again if this didn't sign in.
    if (!(await afterPasskey(res))) void passkeyAutofill();
  }));
  void passkeyAutofill();

  $<HTMLFormElement>("email-form")?.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const form = ev.currentTarget as HTMLFormElement;
    const btn = form.querySelector<HTMLButtonElement>("button[type=submit]");
    busy(btn, async () => {
      fail(null);
      email = ($<HTMLInputElement>("email")?.value || "").trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) { fail("That doesn't look like an email address."); return; }
      const captcha = (form.querySelector<HTMLInputElement>("[name=cf-turnstile-response]")?.value || "").trim();
      if (form.querySelector(".cf-turnstile") && !captcha) { fail("Wait a moment for the check to finish, then try again."); return; }
      const res = await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" }, captcha ? { headers: { "x-captcha-response": captcha } } : undefined);
      const w = window as unknown as { turnstile?: { reset: () => void } };
      w.turnstile?.reset();
      if (res.error) { fail(explain(res.error as ApiError)); return; }
      const sent = $("sent-to"); if (sent) sent.textContent = email;
      show(startStep, false); show(codeForm); $<HTMLInputElement>("otp")?.focus();
    });
  });

  codeForm?.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const btn = codeForm.querySelector<HTMLButtonElement>("button[type=submit]");
    busy(btn, async () => {
      fail(null);
      const otp = ($<HTMLInputElement>("otp")?.value || "").replace(/\D/g, "");
      if (otp.length !== 6) { fail("The code has six digits."); return; }
      const res = await client.signIn.emailOtp({ email, otp });
      if (res.error) { fail(explain(res.error as ApiError)); return; }
      await afterSignIn(res.data);
    });
  });
  $<HTMLInputElement>("otp")?.addEventListener("input", (e) => {
    const i = e.currentTarget as HTMLInputElement;
    i.value = i.value.replace(/\D/g, "").slice(0, 6);
    if (i.value.length === 6) codeForm?.requestSubmit();
  });

  $("restart")?.addEventListener("click", () => { fail(null); show(codeForm, false); show(startStep); $<HTMLInputElement>("email")?.focus(); });

  nameForm?.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const btn = nameForm.querySelector<HTMLButtonElement>("button[type=submit]");
    busy(btn, async () => {
      fail(null);
      const name = ($<HTMLInputElement>("name")?.value || "").trim();
      if (name.length < 1) { fail("Tell us a name, even a short one."); return; }
      const res = await client.updateUser({ name: name.slice(0, 80) });
      if (res.error) { fail(explain(res.error as ApiError)); return; }
      await maybeOfferPasskey();
    });
  });

  const addBtn = $<HTMLButtonElement>("add-passkey");
  addBtn?.addEventListener("click", () => busy(addBtn, async () => {
    fail(null);
    const res = await client.passkey.addPasskey({ name: deviceName() });
    if (res?.error && !/cancel|abort|NotAllowed/i.test(res.error.message || "")) { fail(explain(res.error as ApiError, "That didn't work. You can add a passkey later on your account page.")); return; }
    location.assign(target);
  }));
  $("skip-passkey")?.addEventListener("click", () => { try { localStorage.setItem(SKIP_PASSKEY, "1"); } catch {} location.assign(target); });
}

function deviceName(): string {
  const ua = navigator.userAgent;
  const os = /iPhone|iPad/.test(ua) ? "iPhone or iPad" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "This device";
  return `${os}, added ${new Date().toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}`;
}

// ---------- account ----------
const fmt = (d: string | Date) => new Date(d).toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
function li(main: string, meta: string, action?: { label: string; run: () => void }) {
  const el = document.createElement("li");
  const left = document.createElement("div");
  const t = document.createElement("div"); t.textContent = main;
  const m = document.createElement("div"); m.className = "meta"; m.textContent = meta;
  left.append(t, m); el.append(left);
  if (action) {
    const b = document.createElement("button");
    b.className = "btn ghost sm"; b.type = "button"; b.textContent = action.label;
    b.addEventListener("click", action.run);
    el.append(b);
  }
  return el;
}
const browserOf = (ua: string | null | undefined) => {
  if (!ua) return "Unknown browser";
  // Already coarse (sealed apps on): "Firefox on Windows".
  if (!ua.includes("/")) return ua;
  const b = /Edg\//.test(ua) ? "Edge" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android" : /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${b} on ${os}` : b;
};

async function account() {
  const s = await client.getSession();
  if (!s.data) { location.assign("/sign-in?next=%2Faccount"); return; }
  const { user, session } = s.data;
  const hello = $("hello");
  if (hello) { hello.textContent = user.name ? `Hello, ${user.name.split(" ")[0]}` : "Hello"; const em = document.createElement("em"); em.textContent = "."; hello.append(em); }
  const who = $("whoami"); if (who) who.textContent = `Signed in as ${user.email}.`;
  const nameInput = $<HTMLInputElement>("name"); if (nameInput) nameInput.value = user.name || "";

  $<HTMLFormElement>("profile-form")?.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const btn = (ev.currentTarget as HTMLFormElement).querySelector<HTMLButtonElement>("button");
    busy(btn, async () => {
      fail(null);
      const name = (nameInput?.value || "").trim().slice(0, 80);
      if (!name) { fail("Tell us a name, even a short one."); return; }
      const res = await client.updateUser({ name });
      if (res.error) { fail(explain(res.error as ApiError)); return; }
      show($("profile-saved")); setTimeout(() => show($("profile-saved"), false), 2000);
    });
  });

  async function loadPasskeys() {
    const ul = $("passkeys"); if (!ul) return;
    ul.replaceChildren();
    const res = await client.passkey.listUserPasskeys();
    const list = (res.data || []) as { id: string; credentialID?: string; name?: string | null; createdAt: string | Date; backedUp?: boolean }[];
    if (!list.length) { ul.append(li("No passkeys yet", "You sign in with a code by email.")); return; }
    for (const pk of list)
      ul.append(li(pk.name || "Passkey", `Added ${fmt(pk.createdAt)}${pk.backedUp ? " · synced" : ""}`, {
        label: "Remove",
        run: async () => {
          if (!confirm(`Remove "${pk.name || "this passkey"}"? You can still sign in with a code by email.`)) return;
          const r = await client.passkey.deletePasskey({ id: pk.id });
          if (r.error) { fail(explain(r.error as ApiError)); return; }
          if (pk.credentialID) await forgetCredential(pk.credentialID);
          loadPasskeys();
        },
      }));
  }
  const addBtn = $<HTMLButtonElement>("add-passkey");
  if (!passkeysSupported()) { if (addBtn) { addBtn.disabled = true; addBtn.title = "This browser doesn't support passkeys."; } }
  addBtn?.addEventListener("click", () => busy(addBtn, async () => {
    fail(null);
    const res = await client.passkey.addPasskey({ name: deviceName() });
    if (res?.error && !/cancel|abort|NotAllowed/i.test(res.error.message || "")) fail(explain(res.error as ApiError));
    loadPasskeys();
  }));

  async function loadSessions() {
    const ul = $("sessions"); if (!ul) return;
    ul.replaceChildren();
    const res = await client.$fetch<{ token: string; id: string; userAgent?: string | null; ipAddress?: string | null; createdAt: string }[]>("/stem/sessions", { method: "GET" });
    if (res.error) { fail(explain(res.error as ApiError, "We couldn't load where you're signed in.")); return; }
    if (!Array.isArray(res.data) || !res.data.length) { ul.append(li("This browser", `Since ${fmt(session.createdAt)}`)); return; }
    for (const x of (res.data || []) as { token: string; id: string; userAgent?: string | null; ipAddress?: string | null; createdAt: string | Date }[]) {
      const current = x.id === session.id;
      ul.append(li(`${browserOf(x.userAgent)}${current ? " (this one)" : ""}`, `Since ${fmt(x.createdAt)}${x.ipAddress ? ` · ${x.ipAddress}` : ""}`, current ? undefined : {
        label: "End",
        run: async () => { const r = await client.revokeSession({ token: x.token }); if (r.error) fail(explain(r.error as ApiError)); else loadSessions(); },
      }));
    }
  }

  async function loadOrgs() {
    const ul = $("orgs"); if (!ul) return;
    ul.replaceChildren();
    const res = await client.$fetch<{ id: string; name: string; role: string; primary: boolean; stem_wide: boolean }[]>("/stem/teams", { method: "GET" });
    if (res.error) { fail(explain(res.error as ApiError, "We couldn't load your teams.")); return; }
    const list = res.data || [];
    if (!list.length) { ul.append(li("No teams", "Apps add you to teams when someone invites you.")); return; }
    for (const o of list) {
      const meta = [o.primary ? "Primary" : "", o.role, o.stem_wide ? "all apps" : ""].filter(Boolean).join(" · ");
      ul.append(li(o.name, meta, o.primary ? undefined : {
        label: "Make primary",
        run: async () => {
          const r = await client.$fetch("/stem/teams/primary", { method: "POST", body: { organization_id: o.id } });
          if (r.error) fail(explain(r.error as ApiError)); else loadOrgs();
        },
      }));
    }
  }

  async function loadApps() {
    const ul = $("apps"); if (!ul) return;
    ul.replaceChildren();
    const res = await client.$fetch<{ client_id: string; name: string; last_used: string | null }[]>("/stem/apps", { method: "GET" });
    const list = res.data || [];
    if (!list.length) { ul.append(li("No apps", "Apps show up here once you sign in to them.")); return; }
    for (const a of list)
      ul.append(li(a.name, a.last_used ? `Last used ${fmt(a.last_used)}` : "Allowed", {
        label: "Remove",
        run: async () => {
          if (!confirm(`Remove ${a.name}'s access? It can't use your account anymore until you sign in to it again.`)) return;
          const r = await client.$fetch("/stem/apps/remove", { method: "POST", body: { client_id: a.client_id } });
          if (r.error) fail(explain(r.error as ApiError)); else loadApps();
        },
      }));
  }

  $("revoke-others")?.addEventListener("click", async () => {
    const r = await client.revokeOtherSessions();
    if (r.error) fail(explain(r.error as ApiError)); else loadSessions();
  });
  $("sign-out")?.addEventListener("click", async () => { await client.signOut(); location.assign("/"); });
  $("delete-account")?.addEventListener("click", async () => {
    if (!confirm("Delete your stem account for good? You'll be signed out of every app that uses stem.")) return;
    const pks = await client.passkey.listUserPasskeys();
    const r = await client.deleteUser({});
    if (r.error) { fail(explain(r.error as ApiError)); return; }
    for (const pk of (pks.data || []) as { credentialID?: string }[]) if (pk.credentialID) await forgetCredential(pk.credentialID);
    location.assign("/");
  });

  await Promise.all([loadPasskeys(), loadSessions(), loadOrgs(), loadApps(), loadAgents(mandateHelpers)]);
}

// ---------- consent ----------
function consent() {
  const answer = (accept: boolean, btn: HTMLButtonElement | null) => busy(btn, async () => {
    fail(null);
    const res = await client.oauth2.consent({ accept });
    if (res.error) { fail(explain(res.error as ApiError)); return; }
    const d = res.data as { redirect?: boolean; url?: string; redirect_uri?: string } | null;
    const url = d?.url || d?.redirect_uri;
    if (url) location.assign(url);
  });
  const allow = $<HTMLButtonElement>("allow"), deny = $<HTMLButtonElement>("deny");
  allow?.addEventListener("click", () => answer(true, allow));
  deny?.addEventListener("click", () => answer(false, deny));
}

// ---------- invitation ----------
async function invite() {
  const id = document.body.dataset.invite || "";
  const invited = (document.body.dataset.email || "").toLowerCase();
  const s = await client.getSession();
  if (!s.data) return;
  const hint = $("invite-hint");
  if (s.data.user.email.toLowerCase() !== invited) {
    if (hint) hint.textContent = `You're signed in as ${s.data.user.email}, but this invitation is for ${invited}. Sign out and sign in with that address to accept it.`;
    const link = $<HTMLAnchorElement>("invite-sign-in");
    if (link) {
      link.textContent = "Sign out and switch";
      link.addEventListener("click", async (e) => { e.preventDefault(); await client.signOut(); location.assign(link.href); });
    }
    return;
  }
  if (hint) hint.textContent = `You're signed in as ${s.data.user.email}.`;
  show($("invite-sign-in"), false);
  const accept = $<HTMLButtonElement>("accept"), decline = $<HTMLButtonElement>("decline");
  show(accept); show(decline);
  accept?.addEventListener("click", () => busy(accept, async () => {
    fail(null);
    const r = await client.organization.acceptInvitation({ invitationId: id });
    if (r.error) { fail(explain(r.error as ApiError)); return; }
    location.assign(`/invite/${encodeURIComponent(id)}/continue`);
  }));
  decline?.addEventListener("click", () => busy(decline, async () => {
    const r = await client.organization.rejectInvitation({ invitationId: id });
    if (r.error) { fail(explain(r.error as ApiError)); return; }
    location.assign("/account");
  }));
}

// ---------- landing ----------
async function landing() {
  const s = await client.getSession();
  const inside = !!s.data;
  document.querySelectorAll<HTMLElement>("[data-when]").forEach((el) => { el.hidden = (el.dataset.when === "in") !== inside; });
}

const mandateHelpers = { $fetch: client.$fetch as never, $, fail, busy, li, fmt };
const pages: Record<string, () => unknown> = { "sign-in": signIn, account, consent, invite, landing, mandate: () => approveMandate(mandateHelpers) };
pages[document.body.dataset.page || ""]?.();
