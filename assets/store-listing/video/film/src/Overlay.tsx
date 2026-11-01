import "./overlay.css";

import { ARMOR_IN, ARMOR_OUT, click, DECRYPT_AT, encClick, END_AT, KEYS_AT, TAMPERED_AT } from "./script";
import { expo, io, P } from "./time";

/**
 * The type layer: plain DOM over the canvas, so text stays crisp. Linear's
 * rule: one short line at a time, sliding out from behind a mask edge on a
 * fast-out, long-settle curve. No scale, no blur, no bounce.
 */
interface Caption { id: string; lines: string[]; green?: number; at: () => number; until: () => number; cls?: string }
// ?clip: the film is cut into the main promo, which has already said the
// headline, so the opening line is left out.
const CLIP = new URLSearchParams(location.search).has("clip");
const ALL: Caption[] = [
  { id: "h-open", lines: ["Encrypt without", "leaving the tab"], green: 1, at: () => 1.8, until: () => encClick(0) + 0.6, cls: "big" },
  { id: "c-pick", lines: ["Pick who it's for."], at: () => encClick(0) - 0.2, until: () => encClick(2) - 0.3 },
  { id: "c-write", lines: ["Write it."], at: () => encClick(2) - 0.1, until: () => encClick(3) - 0.5 },
  { id: "c-sign", lines: ["Sign it."], at: () => encClick(3) - 0.4, until: () => encClick(4) - 0.5 },
  { id: "c-enc", lines: ["Encrypt."], at: () => encClick(4) - 0.4, until: () => ARMOR_OUT[0] + 0.35 },
  { id: "c-alice", lines: ["Only Alice", "can read it."], green: 1, at: () => ARMOR_OUT[1] - 0.25, until: () => ARMOR_IN[0] - 0.1 },
  { id: "c-dec", lines: ["Decrypt and verify,", "in one step."], green: 1, at: () => click("decrypt", 1) - 0.3, until: () => TAMPERED_AT - 0.45 },
  { id: "c-tam", lines: ["Tampered with?", "You'll know."], green: 1, at: () => click("tampered", 1) - 0.25, until: () => KEYS_AT - 0.45 },
  { id: "c-keys", lines: ["Your keys and contacts,", "encrypted at rest."], green: 1, at: () => KEYS_AT + 0.6, until: () => END_AT - 0.2 },
];
const CAPTIONS = CLIP ? ALL.filter((c) => c.id !== "h-open") : ALL;
void DECRYPT_AT;

export function Overlay() {
  return (
    <div id="overlay">
      {CAPTIONS.map((c) => (
        <h1 key={c.id} id={c.id} className={`display cap ${c.cls ?? ""}`}>
          {c.lines.map((l, i) => (
            <span key={i} className={`line${c.green === i ? " green" : ""}`}>
              <span>{l}</span>
            </span>
          ))}
        </h1>
      ))}
      <div id="lockup">
        <img src="/sl/icon/128.png" alt="" />
        <h2 className="display">
          <span className="line"><span>PGP Tools</span></span>
        </h2>
        <p className="lsub">Free and open source. <span className="green">Encrypt without leaving the tab.</span></p>
        <div className="badges">
          <img src="/gh/chrome-web-store-badge.png" alt="" />
          <img src="/gh/microsoft-edge-addons-badge.png" alt="" />
        </div>
      </div>
    </div>
  );
}

const $ = (id: string) => document.getElementById(id);

/** A caption leaves in time for the next one to arrive in the same place. */
const untilOf = (i: number) => {
  const own = CAPTIONS[i].until();
  const next = CAPTIONS[i + 1];
  return next ? Math.min(own, next.at() - 0.55) : own;
};

export function overlay(t: number) {
  for (const [i, c] of CAPTIONS.entries()) {
    const el = $(c.id);
    if (!el) continue;
    const a = c.at(), b = untilOf(i);
    const on = t > a - 0.05 && t < b + 0.6;
    el.style.visibility = on ? "visible" : "hidden";
    if (!on) continue;
    // In: each line slides up out of its mask. Out: up and away into the
    // same edge, never a fade-to-blur.
    el.querySelectorAll<HTMLElement>(".line > span").forEach((s, i) => {
      const x = expo(P(t, a + i * 0.1, a + i * 0.1 + 0.9));
      const o = io(P(t, b + i * 0.05, b + i * 0.05 + 0.45));
      s.style.transform = `translateY(${(1 - x) * 110 - o * 110}%)`;
    });
  }
  // The lockup: icon, name, one line, the stores.
  const lk = $("lockup");
  if (lk) {
    const a = END_AT + 1.0;
    lk.style.visibility = t > a - 0.05 ? "visible" : "hidden";
    const icon = lk.querySelector<HTMLElement>("img")!;
    const k = expo(P(t, a, a + 0.9));
    icon.style.opacity = String(k);
    icon.style.transform = `translateY(${(1 - k) * 24}px)`;
    lk.querySelectorAll<HTMLElement>(".line > span").forEach((s) => {
      s.style.transform = `translateY(${(1 - expo(P(t, a + 0.15, a + 1.05))) * 110}%)`;
    });
    [lk.querySelector<HTMLElement>(".lsub")!, lk.querySelector<HTMLElement>(".badges")!].forEach((el, i) => {
      const x = expo(P(t, a + 0.45 + i * 0.15, a + 1.35 + i * 0.15));
      el.style.opacity = String(x);
      el.style.transform = `translateY(${(1 - x) * 18}px)`;
    });
  }
}
