// SPDX-License-Identifier: AGPL-3.0-or-later
import { describe, it, expect } from "vitest";
import { accountPage, signInPage } from "../src/ui/pages";

const ui = (key: string | null) => ({ legal: false, turnstileSiteKey: key, origin: "https://stem.example" });
const widgets = (html: string) => html.match(/class="cf-turnstile"/g)?.length ?? 0;

describe("Turnstile pre-clearance", () => {
  it("adds a background check and the Turnstile script to the account page", () => {
    const html = accountPage(ui("0xSITEKEY"));
    expect(html).toContain('data-action="clearance"');
    expect(html).toContain('data-appearance="interaction-only"');
    expect(html).toContain("challenges.cloudflare.com/turnstile/v0/api.js");
    expect(widgets(html)).toBe(1);
  });

  it("keeps a single widget on the sign-in page, which already has one", () => {
    expect(widgets(signInPage(ui("0xSITEKEY"), null))).toBe(1);
  });

  it("leaves pages alone when Turnstile is off", () => {
    const html = accountPage(ui(null));
    expect(html).not.toContain("cf-turnstile");
    expect(html).not.toContain("challenges.cloudflare.com");
  });
});
