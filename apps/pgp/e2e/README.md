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
  zeroize-on-free allocator.

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
