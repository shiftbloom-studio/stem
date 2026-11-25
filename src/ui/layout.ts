// SPDX-License-Identifier: AGPL-3.0-or-later
// stem's pages follow the shiftbloom studio brand book v2: paper and ink, one loud flower.
// Paper is a soft warm off-white rather than pure white, which is easier on bright screens.
// Bloom Red for actions and seeds, gradients only inside the mark. Clash Display for statements,
// General Sans for UI and body, JetBrains Mono for labels and codes.
import { bloomSvg } from "../bloom";
import { esc } from "./html";

/** AGPL §13: people using stem over a network are offered the source. Forks: point this at your repo. */
export const SOURCE_URL = "https://github.com/shiftbloom-studio/stem";

const css = `
:root{--bloom:#FF2E52;--root:#C81040;--petal:#FF8FAB;--blush:#FFE9EF;--ink:#1A1216;--ink60:rgba(26,18,22,.66);--ink40:rgba(26,18,22,.42);--line:#E4DADB;--paper:#F6F1EE;--warm:#EEE6E2;--field:#FBF8F6;
--display:"Clash Display",ui-sans-serif,system-ui,sans-serif;--sans:"General Sans",ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;--mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
--ease:cubic-bezier(.22,1.1,.36,1);--settle:cubic-bezier(.4,0,.2,1)}
*{box-sizing:border-box}[hidden]{display:none!important}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.65 var(--sans);-webkit-font-smoothing:antialiased}
::selection{background:var(--blush)}
a{color:var(--root);text-decoration:none;background:linear-gradient(var(--root),var(--root)) 0 100%/0 1px no-repeat;transition:background-size .24s var(--ease)}
a:hover{background-size:100% 1px}
.wrap{max-width:1040px;margin:0 auto;padding:0 clamp(20px,5vw,48px);min-height:100vh;display:flex;flex-direction:column}
main{flex:1}
.label{font:500 11px/1.4 var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--ink60)}
.top{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:22px 0;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px;color:var(--ink);background:none}
.brand .word{font:600 20px/1 var(--display);letter-spacing:-.02em}@media(min-width:640px){.brand .word{font-size:22.4px}}
.brand .word i,h1 em{font-style:normal;color:var(--bloom)}
h1,h2{font-family:var(--display);font-weight:600;letter-spacing:-.025em;line-height:1.04;margin:0}
h1{font-size:clamp(34px,5vw,56px)}h2{font-size:22px;line-height:1.15}
.lead{font-size:17px;color:var(--ink60);margin:16px 0 0;max-width:32em}
.btn{appearance:none;border:0;border-radius:999px;background:var(--bloom);color:#fff;font:600 15px/1 var(--sans);padding:14px 22px;cursor:pointer;transition:background .24s var(--settle),transform .24s var(--ease);display:inline-flex;align-items:center;justify-content:center;gap:8px;text-decoration:none}
.btn:hover{background:var(--root);background-size:auto}.btn:active{transform:scale(.97)}.btn[disabled]{opacity:.55;cursor:default}
.btn.ghost{background:transparent;color:var(--ink);box-shadow:inset 0 0 0 1px var(--ink)}.btn.ghost:hover{background:var(--ink);color:#fff}
.btn.sm{padding:9px 14px;font-size:13px}.btn.wide{width:100%}
.linkbtn{appearance:none;border:0;background:none;padding:0;font:inherit;color:var(--root);cursor:pointer}.linkbtn:hover{text-decoration:underline}
.btn:focus-visible,a:focus-visible,button:focus-visible{outline:2px solid var(--root);outline-offset:2px}
input{font:16px/1.5 var(--sans);color:var(--ink);background:var(--field);border:1px solid var(--line);border-radius:12px;padding:12px 14px;width:100%;transition:border-color .24s var(--settle),box-shadow .24s var(--settle)}
input:focus{outline:0;border-color:var(--bloom);box-shadow:0 0 0 3px var(--blush)}
input.code{font:500 26px/1.2 var(--mono);letter-spacing:.32em;text-align:center}
label.f{display:grid;gap:6px;font:500 14px/1.3 var(--sans)}
.panel{background:var(--warm);border-radius:20px;padding:clamp(20px,3vw,32px)}
.stack{display:grid;gap:16px}
.small{font-size:13px;color:var(--ink60);margin:0}
.err{color:var(--root);font-size:14px;margin:0}
.or{display:flex;align-items:center;gap:12px;color:var(--ink40);font:500 11px/1 var(--mono);letter-spacing:.16em;text-transform:uppercase}.or:before,.or:after{content:"";flex:1;height:1px;background:var(--line)}
.seedlist{list-style:none;padding:0;margin:0;display:grid;gap:10px}.seedlist li{position:relative;padding-left:20px}.seedlist li:before{content:"";position:absolute;left:2px;top:.62em;width:7px;height:7px;border-radius:50%;background:var(--bloom)}
.split{display:grid;grid-template-columns:1.05fr 1fr;gap:clamp(24px,5vw,64px);padding:clamp(32px,6vw,72px) 0 0;align-items:start}
@media (max-width:780px){.split{grid-template-columns:1fr}}
.rows{display:grid;gap:0;margin:0;padding:0;list-style:none}.rows li{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 0;border-top:1px solid var(--line)}.rows li:first-child{border-top:0}
.rows .meta{font:400 12px/1.4 var(--mono);color:var(--ink60)}
.pill{display:inline-block;background:var(--blush);color:var(--root);border-radius:999px;padding:3px 10px;font:500 11px/1.4 var(--mono);letter-spacing:.08em}
.sect{margin-top:28px}.sect h2{margin-bottom:10px}
.foot{display:flex;justify-content:space-between;gap:12px 24px;flex-wrap:wrap;padding:22px 0 30px;margin-top:72px;border-top:1px solid var(--line)}.foot p{margin:0;font-size:14px;color:var(--ink60)}
.sb{font:600 15px/1 var(--display);letter-spacing:-.02em;color:var(--ink);background:none;white-space:nowrap}.sb span{font-weight:400;color:var(--ink60);margin-left:.28em}.sb i{font-style:normal;color:var(--bloom)}
.art{display:grid;place-items:center;min-height:260px}.art svg{width:min(220px,70%);height:auto;animation:unfold .6s var(--ease) both,breathe 6s var(--settle) .6s infinite}
.unfold{animation:unfold .6s var(--ease) both}
@keyframes unfold{from{opacity:0;transform:scale(.6)}to{opacity:1;transform:none}}
@keyframes breathe{0%,100%{transform:scale(1)}50%{transform:scale(1.02)}}
@media (prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}}
.legal{max-width:44em;padding:clamp(28px,5vw,56px) 0 0}.legal h1{font-size:clamp(32px,4.6vw,48px)}.legal h2{margin:36px 0 10px}
.legal p,.legal address{margin:0 0 14px;font-style:normal}.legal .meta{display:flex;gap:16px;flex-wrap:wrap;margin:14px 0 28px;font-size:14px;color:var(--ink60)}
`;

export type PageOpts = {
  title: string;
  page?: string;
  lang?: "en" | "de";
  index?: boolean;
  description?: string;
  canonical?: string;
  turnstile?: boolean;
  data?: Record<string, string>;
  legal?: boolean;
};

const STUDIO = `<a class="sb" href="https://shiftbloom.studio" aria-label="shiftbloom studio">shiftbloom<span>studio</span><i>.</i></a>`;

export function topbar(right = "") {
  return `<header class="top"><a class="brand" href="/" aria-label="stem, shiftbloom studio">${bloomSvg({ size: 30, id: "tb" })}<span class="word">stem<i>.</i></span></a>${right}</header>`;
}

export function footer(lang: "en" | "de", legal: boolean) {
  const links = legal ? (lang === "de" ? ` · <a href="/datenschutz">Datenschutz</a> · <a href="/impressum">Impressum</a>` : ` · <a href="/privacy">Privacy</a> · <a href="/imprint">Imprint</a>`) : "";
  return `<footer class="foot"><p>${lang === "de" ? "stem ist Open Source unter AGPL-3.0." : "stem is open source under AGPL-3.0."} <a href="${SOURCE_URL}">${lang === "de" ? "Zum Code" : "Read the code"}</a>${links}</p><p>${STUDIO}</p></footer>`;
}

export function page(o: PageOpts, body: string, right = "") {
  const lang = o.lang || "en";
  const data = Object.entries(o.data || {}).map(([k, v]) => ` data-${k}="${esc(v)}"`).join("");
  return `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(o.title)}</title>${o.index ? "" : `<meta name="robots" content="noindex, nofollow">`}${o.description ? `<meta name="description" content="${esc(o.description)}">` : ""}${o.canonical ? `<link rel="canonical" href="${esc(o.canonical)}">` : ""}
<meta name="theme-color" content="#F6F1EE"><meta name="referrer" content="strict-origin-when-cross-origin">
<link rel="icon" href="/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/assets/fonts.css"><style>${css}</style>
${o.page ? `<script src="/assets/app.js" defer></script>` : ""}${o.turnstile ? `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` : ""}
</head><body${o.page ? ` data-page="${esc(o.page)}"` : ""}${data}><div class="wrap">${topbar(right)}<main>${body}</main>${footer(lang, !!o.legal)}</div></body></html>`;
}
