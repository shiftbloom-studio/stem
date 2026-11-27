// SPDX-License-Identifier: AGPL-3.0-or-later
import { bloomSvg } from "../bloom";
import { esc } from "./html";
import { page, SOURCE_URL } from "./layout";

export type Ui = { legal: boolean; turnstileSiteKey: string | null; origin: string; mandates?: boolean };

const DESC = "The sign-in behind shiftbloom studio apps. Passkeys or a code by email, no passwords. Open source, on Cloudflare Workers.";

export function landingPage(ui: Ui) {
  return page(
    { title: "stem. · sign-in for shiftbloom studio", index: true, description: DESC, canonical: `${ui.origin}/`, legal: ui.legal, page: "landing" },
    `<section class="split">
  <div>
    <span class="label">shiftbloom studio · sign-in</span>
    <h1 style="margin-top:14px">One way in to everything we build<em>.</em></h1>
    <p class="lead">stem is the account behind shiftbloom studio apps. There's no password to remember: your device signs you in with a passkey, or we email you a short code.</p>
    <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:28px">
      <a class="btn" href="/account" data-when="in" hidden>Your account</a>
      <a class="btn" href="/sign-in" data-when="out">Sign in</a>
      <a class="btn ghost" href="${SOURCE_URL}">How it works</a>
    </div>
  </div>
  <div class="art" aria-hidden="true">${bloomSvg({ size: 220, id: "hero" })}</div>
</section>
<section class="split" style="padding-top:48px">
  <div class="panel"><h2>What apps get</h2><ul class="seedlist" style="margin-top:14px">
    <li>Your name and email address, once you say yes.</li>
    <li>Which teams you're in for that app or across stem, your role in each, and your primary team.</li>
    <li>Nothing else. No password, no browsing history, no tracking.</li>
  </ul></div>
  <div class="panel"><h2>How you sign in</h2><ul class="seedlist" style="margin-top:14px">
    <li>A passkey on your phone or laptop, with Face ID, a fingerprint or your PIN.</li>
    <li>Or a six-digit code by email. It works once, for ten minutes.</li>
    <li>You see every device that's signed in and can end any of them.</li>
  </ul></div>
</section>`,
  );
}

/** Set when an app asks a signed-in person who has a passkey to prove it's them again (step-up). */
export type StepUp = { email: string };

/** `clientName` is set when an app sent the person here to sign in. */
export function signInPage(ui: Ui, clientName: string | null, stepUp: StepUp | null = null) {
  const target = clientName ? `Sign in to continue to <strong>${esc(clientName)}</strong>.` : "Sign in to your stem account.";
  const intro = stepUp
    ? `<span class="label">confirm it's you</span>
    <h1 style="margin-top:14px">One more check<em>.</em></h1>
    <p class="lead">${clientName ? `<strong>${esc(clientName)}</strong> wants` : "We want"} to make sure it's still you before you go on. Use your passkey, or get a code by email if it isn't at hand.</p>`
    : `<span class="label">sign in</span>
    <h1 style="margin-top:14px">Welcome back<em>.</em></h1>
    <p class="lead">${target} New here? Same steps: the first code you confirm creates your account.</p>`;
  return page(
    { title: stepUp ? "Confirm it's you · stem." : "Sign in · stem.", page: "sign-in", legal: ui.legal, turnstile: !!ui.turnstileSiteKey },
    `<section class="split">
  <div>
    ${intro}
  </div>
  <div class="panel">
    <div class="stack" id="step-start">
      <button class="btn wide" type="button" id="passkey-btn"${stepUp ? " data-step-up" : ""} hidden>${stepUp ? "Confirm with your passkey" : "Sign in with a passkey"}</button>
      <div class="or" id="passkey-or" hidden>or</div>
      <form class="stack" id="email-form" novalidate>
        <label class="f">Email address<input type="email" name="email" id="email" required autocomplete="username webauthn" inputmode="email" maxlength="254" placeholder="you@example.com"${stepUp ? ` value="${esc(stepUp.email)}"` : ""}></label>
        ${ui.turnstileSiteKey ? `<div class="cf-turnstile" data-sitekey="${esc(ui.turnstileSiteKey)}" data-action="send-code" data-theme="light" data-size="flexible"></div>` : ""}
        <button class="btn wide" type="submit">Email me a code</button>
      </form>
    </div>
    <form class="stack" id="code-form" hidden novalidate>
      <p style="margin:0">We sent a six-digit code to <strong id="sent-to"></strong>. It works for ten minutes.</p>
      <label class="f">Code<input class="code" name="otp" id="otp" required inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6"></label>
      <button class="btn wide" type="submit">Sign in</button>
      <p class="small">Nothing there? Check your spam folder, or <button class="linkbtn" type="button" id="restart">use a different address</button>.</p>
    </form>
    <form class="stack" id="name-form" hidden novalidate>
      <p style="margin:0"><strong>One more thing.</strong> What should apps call you?</p>
      <label class="f">Your name<input name="name" id="name" required autocomplete="name" maxlength="80"></label>
      <button class="btn wide" type="submit">Continue</button>
    </form>
    <div class="stack" id="passkey-offer" hidden>
      <p style="margin:0"><strong>Skip the code next time.</strong> Add a passkey and this device signs you in with Face ID, a fingerprint or your PIN.</p>
      <button class="btn wide" type="button" id="add-passkey">Add a passkey</button>
      <button class="btn ghost wide" type="button" id="skip-passkey">Not now</button>
    </div>
    <p class="err" id="error" role="alert" hidden></p>
    <p class="small" style="margin-top:18px">By signing in you agree that we store what's described in the ${ui.legal ? `<a href="/privacy">privacy policy</a>` : "privacy policy"}. No tracking, no ads.</p>
  </div>
</section>`,
  );
}

export function accountPage(ui: Ui) {
  return page(
    { title: "Your account · stem.", page: "account", legal: ui.legal },
    `<section style="padding-top:clamp(32px,6vw,64px)">
  <span class="label">your account</span>
  <h1 style="margin-top:14px" id="hello">Hello<em>.</em></h1>
  <p class="lead" id="whoami"></p>
</section>
<div class="split" style="padding-top:32px">
  <div>
    <section class="panel">
      <h2>Your name</h2>
      <form class="stack" id="profile-form" style="margin-top:12px" novalidate>
        <label class="f">Shown to apps you sign in to<input name="name" id="name" autocomplete="name" maxlength="80" required></label>
        <div><button class="btn sm" type="submit">Save</button> <span class="small" id="profile-saved" hidden>Saved.</span></div>
      </form>
    </section>
    <section class="panel sect">
      <h2>Passkeys</h2>
      <p class="small">Each passkey lives on one device or in one password manager.</p>
      <ul class="rows" id="passkeys" style="margin-top:8px"></ul>
      <button class="btn sm" type="button" id="add-passkey" style="margin-top:12px">Add a passkey</button>
    </section>
    <section class="panel sect">
      <h2>Where you're signed in</h2>
      <ul class="rows" id="sessions" style="margin-top:8px"></ul>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px">
        <button class="btn ghost sm" type="button" id="revoke-others">Sign out everywhere else</button>
        <button class="btn sm" type="button" id="sign-out">Sign out</button>
      </div>
    </section>
  </div>
  <div>
    <section class="panel">
      <h2>Teams</h2>
      <p class="small">Your primary team is the one apps open first.</p>
      <ul class="rows" id="orgs" style="margin-top:8px"></ul>
    </section>
    <section class="panel sect">
      <h2>Apps with access</h2>
      <p class="small">Apps that can keep you signed in or that you said yes to. Removing one ends its access to your account within ten minutes.</p>
      <ul class="rows" id="apps" style="margin-top:8px"></ul>
    </section>${ui.mandates ? `
    <section class="panel sect">
      <h2>Your agents</h2>
      <p class="small">Agents you signed a mandate for with your passkey. Stopping one also stops every helper it handed rights to, on their next request.</p>
      <ul class="rows" id="agents" style="margin-top:8px"></ul>
      <ol class="rows small" id="trail" hidden style="margin-top:8px"></ol>
    </section>` : ""}
    <section class="panel sect">
      <h2>Your data</h2>
      <p class="small">Everything stem stores about you, as one JSON file: your account, passkeys, sessions, teams, invitations and apps.</p>
      <a class="btn ghost sm" href="/api/auth/stem/export" download style="margin-top:12px">Download my data</a>
    </section>
    <section class="panel sect">
      <h2>Delete your account</h2>
      <p class="small">This removes your account, passkeys, sessions and team memberships at once. Apps keep only what they stored themselves.</p>
      <button class="btn ghost sm" type="button" id="delete-account" style="margin-top:12px">Delete my account</button>
    </section>
  </div>
</div>
<p class="err" id="error" role="alert" hidden></p>`,
  );
}

export function consentPage(ui: Ui, client: { name: string; uri: string | null }, scopes: string[]) {
  const SCOPE_TEXT: Record<string, string> = {
    openid: "Know that it's you",
    profile: "See your name",
    email: "See your email address",
    offline_access: "Keep you signed in until you sign out",
    orgs: "See which of its teams and stem-wide teams you're in, your role, and your primary team",
  };
  const items = scopes.filter((s) => SCOPE_TEXT[s]).map((s) => `<li>${esc(SCOPE_TEXT[s])}</li>`).join("");
  return page(
    { title: `Allow ${client.name} · stem.`, page: "consent", legal: ui.legal },
    `<section class="split">
  <div>
    <span class="label">permission</span>
    <h1 style="margin-top:14px">${esc(client.name)} wants to use your stem account<em>.</em></h1>
    ${client.uri ? `<p class="lead">From <a href="${esc(client.uri)}" rel="noopener">${esc(new URL(client.uri).host)}</a>.</p>` : ""}
  </div>
  <div class="panel stack">
    <p style="margin:0"><strong>It will be able to:</strong></p>
    <ul class="seedlist">${items}</ul>
    <button class="btn wide" type="button" id="allow">Allow</button>
    <button class="btn ghost wide" type="button" id="deny">Cancel</button>
    <p class="small">You can take this back any time on your <a href="/account">stem account page</a>.</p>
    <p class="err" id="error" role="alert" hidden></p>
  </div>
</section>`,
  );
}

export function invitePage(ui: Ui, inv: { id: string; orgName: string; email: string; inviter: string | null } | null) {
  if (!inv)
    return page(
      { title: "Invitation · stem.", legal: ui.legal },
      `<section style="padding-top:clamp(32px,6vw,64px);max-width:36em"><span class="label">invitation</span><h1 style="margin-top:14px">This invitation doesn't work anymore<em>.</em></h1>
<p class="lead">It may have expired, been withdrawn or already been used. Ask the person who invited you to send a new one.</p></section>`,
    );
  return page(
    { title: `Join ${inv.orgName} · stem.`, page: "invite", legal: ui.legal, data: { invite: inv.id, email: inv.email } },
    `<section class="split">
  <div>
    <span class="label">invitation</span>
    <h1 style="margin-top:14px">Join ${esc(inv.orgName)}<em>.</em></h1>
    <p class="lead">${inv.inviter ? `${esc(inv.inviter)} invited` : "You've been invited with"} <strong>${esc(inv.email)}</strong>${inv.inviter ? "" : ""}.</p>
  </div>
  <div class="panel stack">
    <p style="margin:0" id="invite-hint">Sign in with that address to accept. If you don't have an account yet, signing in creates one.</p>
    <a class="btn wide" id="invite-sign-in" href="/sign-in?next=${encodeURIComponent(`/invite/${inv.id}`)}">Sign in to accept</a>
    <button class="btn wide" type="button" id="accept" hidden>Accept and join</button>
    <button class="btn ghost wide" type="button" id="decline" hidden>No, thanks</button>
    <p class="err" id="error" role="alert" hidden></p>
  </div>
</section>`,
  );
}

export function messagePage(ui: Ui, title: string, text: string, status = "not found") {
  return page(
    { title: `${title} · stem.`, legal: ui.legal },
    `<section style="padding-top:clamp(32px,6vw,64px);max-width:36em"><span class="label">${esc(status)}</span><h1 style="margin-top:14px">${esc(title)}<em>.</em></h1><p class="lead">${esc(text)}</p>
<p style="margin-top:24px"><a class="btn" href="/">Back to the start</a></p></section>`,
  );
}
