# End-to-end tests

Playwright drives the **built** extension in a real Chromium: it loads the
unpacked MV3 build from `.output/chrome-mv3` into a persistent context and
exercises the side-panel page against real `chrome.storage`, the WASM
crypto engine, and the lock/unlock lifecycle — the parts unit tests can't
reach.

## Running

```bash
pnpm build          # produce .output/chrome-mv3 (needed once, or after changes)
pnpm test:e2e       # run the specs

# or in one step:
pnpm test:e2e:build
```

First-time setup downloads the browser: `npx playwright install chromium`.

They run **headless** via Chromium's new headless mode (which, unlike the
classic one, loads extensions) — so no display or `xvfb` is needed. Set
`HEADED=1` to watch a real window while debugging.

## Layout

- `fixtures.ts` — loads the extension, exposes its `extensionId` and a
  `panel` page; helpers to read `chrome.storage` and measure blob sizes.
- `helpers.ts` — onboarding / unlock / navigation / import / verify flows
  and the padded-bucket check.
- `keys.ts` — auto-generated fixtures: real OpenPGP keys + signed messages
  across a spread of user-ID shapes and capabilities.
- `edge-keys.ts` — auto-generated "wild and whacky" fixtures: expired,
  revoked, multi-UID, RSA-4096, passphrase-protected, offline-primary
  (stubbed secret), refreshed-expiry pair, binary export, bidi-override
  user ID.
- `smoke.spec.ts` — the extension boots into onboarding.
- `storage.spec.ts` — onboarding encrypts + pads the keyring, encrypts
  settings, keeps sync as bootstrap-only, and leaks no plaintext.
- `lifecycle.spec.ts` — lock (reload drops the in-page WASM session) then
  unlock preserves the keys, keeps the blob padded, and rejects a wrong
  password.
- `keys.spec.ts` — data-driven over every fixture key: import as a contact
  and verify a signature it made. Covers no-email and sign-only keys.
- `recipients.spec.ts` — sign-only contacts are importable but excluded
  from the encryption-recipient picker.
- `edge-import.spec.ts` — weird public keys: expired/revoked import
  rejections with actionable messages, multi-UID and RSA-4096 imports,
  and every verify outcome (valid / unknown signer / tampered / not a
  PGP message). Includes a local-only regression against
  `messy/sample-failed` (gitignored real key material; skipped in CI).
- `edge-private.spec.ts` — private keys as GnuPG exports them:
  passphrase-protected import (incl. gpg's zero-padded ECC secret MPIs,
  see `decrypt_gpg_padded_secret` in gpg-wasm), wrong-passphrase error,
  offline-primary (GNU-dummy stub) legible failure.
- `edge-probes.spec.ts` — interop hazards: re-importing a refreshed key
  updates the stored expiry, binary (non-armored) `.gpg` files import,
  bidi override characters never reach the DOM.
- `passkey.spec.ts` — onboard / lock / unlock with a **passkey**, driven by
  a virtual WebAuthn authenticator with PRF (`webauthn.ts`). WebAuthn needs
  the page focused, so the spec calls `bringToFront()`.
- `heap.spec.ts` — the key one for a WASM-isolated design. Walks a private
  key (`private-key.ts`) through its whole lifecycle — import, unlock,
  sign, encrypt+decrypt, in-app lock, re-unlock — and after **each** stage
  asserts a distinctive slice of its SECRET material is **not retained in
  the V8 heap** (`heap.ts` takes a CDP heap snapshot after a forced GC).
  Only the encrypted-at-rest blob survives; the plaintext stays in WASM. A
  control string that IS present proves the scan works.
- `memory.spec.ts` — complementary: reads the live WASM linear memory via
  CDP (`wasm-memory.ts`) and asserts a distinctive master password does
  not linger there after unlock — an in-browser check of the
  zeroize-on-free allocator. **Caveat:** the unlock path takes its
  password as `&[u8]`, so nothing explicitly zeroizes the marshalled copy
  (`T-UNLOCK-PARAM-NOT-OWNED`). Treat a pass here as evidence about the
  allocator's incidental behaviour, not proof of a deliberate scrub.
- `hostile-dep.spec.ts` — the ACTIVE counterpart to `heap.spec.ts`:
  simulates a compromised in-panel dependency and pins exactly what
  in-realm JS can and cannot reach. Live WASM export table: **yes** — an
  `import()` of the glue chunk plus `getKeyArmored(1)` returns plaintext
  secret material with no user gesture. Prototype hooks on
  encode/decode/getRandomValues/clipboard: **yes**. Linear memory and
  React state: **no** (the two genuine design wins). Gaps are asserted
  *as* gaps and commented `GAP (documented, not desired)` so the suite
  stays green; flip those assertions when hardening lands. See §8.10.
- `history-memory.spec.ts` — the opt-in operation history: manifest holds
  only `{n,bytes}`, canary absent from all three storage areas, and the
  JS-heap count is 0 after an in-app master lock (including with the
  viewer never opened, proving nothing module-level caches decrypted
  entries). Also demonstrates the **integrity** gap in §11.1: replaying a
  segment into another slot, and substituting one across stores.
- `draft-memory.spec.ts` — the workspace draft. Ciphertext mechanism
  passes (absent from WASM memory and storage, rehydrates on unlock); the
  second test is a deliberate `test.fail()` pinning §8.11, the plaintext
  that survives master lock in the DOM. It will fail on an unexpected
  pass the moment that is fixed.
- `crx-memory.spec.ts` — the CRX RSA signing key, asserted
  **present-then-absent** rather than absence-only: a needle from the
  interior of prime `p` is found while a `CRX_KEY_STORE` handle is held
  open, then gone after `closeCrxKey`, with a liveness re-assert so the
  zero can't come from a dead scan.
- `heap-retainers.ts` — retainer-aware companion to `heap.ts`. Walks the
  snapshot's edges back to GC roots, which is how §8.11's
  `FormTracker → value-tracker closure → plaintext` chain was found.
  Reach for this when a canary count is non-zero and you need to know
  *why* rather than just *that*.

> **Heap-needle caveat.** V8 truncates each string node's recorded value
> to the **first 1024 characters** of the string. A needle taken from
> beyond that offset returns 0 whether or not the string is retained —
> the assertion passes for the wrong reason. Constrain the needle offset
> and include a positive control, as `crx-memory.spec.ts` does.
>
> **Trace-cache caveat.** Run retainer analysis with `--trace=off`.
> Playwright's tracing attaches a `__playwright_snapshot_cache_` symbol to
> DOM nodes holding cached serialised values, which shows up as a live
> retainer of an input's text and *masks* the application-owned chain
> underneath it. This was observed while fixing §8.11: with tracing on,
> the only visible retainer was Playwright's own cache; with it off, the
> real React fiber `alternate` chain appeared. Note the config default is
> `trace: "retain-on-failure"`, which is **active during passing runs**, so
> this bites even when nothing is failing — `draft-memory.spec.ts` therefore
> sets `test.use({ trace: "off" })` rather than relying on a CLI flag. Only
> specs whose canary is an input's `value` are affected.
>
> **Validate before you believe a zero.** A retainer walk returning nothing
> can mean "no leak" or "the walk is broken". Prove the measurement by
> temporarily reintroducing the leak (e.g. an effect closing over the
> plaintext), confirming the count goes to 1, then removing it. The
> differential is the trustworthy signal — not the absence of a hit, and not
> the chain text, since the walker reports the shortest path and that may run
> through V8 internals such as the externalised-string table.

Specs are `*.spec.ts` (Playwright); unit tests are `*.test.ts` (vitest),
so the two runners never collide.

## Regenerating fixtures

`e2e/keys.ts` and `e2e/edge-keys.ts` are generated from throwaway gpg
keyrings:

```bash
./e2e/gen-keys.sh         # happy-path fixtures; needs gpg 2.4+ and python3
./e2e/gen-edge-keys.sh    # edge-case fixtures (expired via gpg's own
                          # --faked-system-time; no faketime needed)
```

Add a key by extending the `q ...` calls and the `meta` map in that
script, then re-run it.

`private-key.ts` (the heap test's fixture) is a separate one-off:

```bash
gpg --quick-generate-key "Heap Test <heap@test.local>" default default 1y
gpg --armor --export-secret-keys heap@test.local   # -> privateKey
# secretNeedle = any ~44-char base64 line from the key body
```
