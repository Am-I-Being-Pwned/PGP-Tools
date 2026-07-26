# PGP Tools — Security Architecture

For auditors, security-curious users, and anyone who wants to verify
the claim "private keys never leave the WASM sandbox in plaintext."
If a claim here disagrees with the code, the code wins.

---

## 1. What we defend

- **Passive** inspection of the V8 heap: private key material is never
  present in the JS heap, so a memory-scraping bug, a heap snapshot, or
  a crash dump of the JS heap yields only encrypted blobs. Verified by
  `e2e/heap.spec.ts`.
  This does **not** extend to code *executing* in the side-panel realm.
  A compromised UI dependency does not need the heap — it can call the
  WASM exports directly. See §8.10.
- Forensic recovery of plaintext key material after the user is done
  with a key (drop / lock / idle).
- Clipboard exfiltration after key export (auto-clear after 30s/60s).
- Surprise passkey ceremonies after a system-initiated lock — the
  user must click Unlock first.
- Cross-blob substitution: ciphertext AAD is bound to the cert's
  fingerprint, so swapping two encrypted-key blobs on disk fails
  authentication.
- Outbound network exfiltration (§7).

What we do **not** defend is in §8.

---

## 2. Trust boundary

```
                       ┌──────────────────────────────────────┐
                       │         WASM linear memory           │
                       │  (Rust / Sequoia-PGP, gpg-wasm/)     │
                       │                                      │
   passwords / PRF ───►│  Zeroizing<Vec<u8>>                  │
   passphrase      ───►│  Sequoia Password (Protected<Vec<u8>>)│
                       │   — only in decrypt_cert_secrets,    │
                       │     encrypt_cert_for_export          │
   armored input   ───►│  StoredKey { bytes: Vec<u8> } (Drop  │
                       │   zeroizes)                          │
                       │  KEY_STORE: HashMap<u32, StoredKey>  │
                       │                                      │
                       │  ↑ entries inserted ONLY by         │
                       │     unlockWithPassword / unlockWithPrf│
                       └────────────┬─────────────────────────┘
                                    │
              wasm-bindgen boundary │ (memcpy in / out)
                                    ▼
   ┌──────────────────────────────────────────────────────────┐
   │            JavaScript (side-panel context)               │
   │                                                          │
   │  lib/pgp/wasm-public.ts   ── no secret material          │
   │  lib/pgp/wasm-secrets.ts  ── carries secrets in/out;     │
   │                              every fn documents its      │
   │                              zeroize contract            │
   │                                                          │
   │  React components ── only see public material + opaque   │
   │                       u32 KEY_STORE handles              │
   └──────────────────────────────────────────────────────────┘
```

Private-key material crosses from WASM into JS in only two places:

- `getKeyArmored(handle)` — plaintext armored, gated by a
  type-to-confirm ("EXPORT") UI.
- `encryptKeyForExportWithHandle(handle, passphrase)` — armored cert
  re-encrypted under a user-supplied export passphrase.

Both are user-initiated destructive-export paths *in the UI*. Neither is
enforced as such at the WASM boundary — the type-to-confirm gate is React
state, not a capability check. Code running in the side-panel realm can
call either export directly. See §8.10.

---

## 3. File map

| #   | File                                       | What's in it                                                                                                                 |
| --- | ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------- |
| 1   | `apps/pgp/SECURITY.md` (this file)         | The contract                                                                                                                 |
| 2   | `apps/pgp/gpg-wasm/src/lib.rs`             | The WASM crate. The actual sandbox.                                                                                          |
| 2a  | `apps/pgp/gpg-wasm/src/crx.rs`             | RSA-2048 CRX (Chrome extension) signer/verifier. Separate `CRX_KEY_STORE`; see §10.                                          |
| 5a  | `apps/pgp/lib/crx/`                        | JS-side CRX key storage, sign/verify coordinator, and backup (de)serialization.                                             |
| 3   | `apps/pgp/lib/pgp/wasm.ts`                 | JS-side barrel.                                                                                                              |
| 4   | `apps/pgp/lib/pgp/wasm-public.ts`          | Wasm wrappers that don't carry secrets.                                                                                      |
| 5   | `apps/pgp/lib/pgp/wasm-secrets.ts`         | Wasm wrappers that do, each with a `@secret-handling` block.                                                                 |
| 6   | `apps/pgp/lib/protection/protect-flow.ts`  | Generate/import/protect. Owns the `Uint8Array.fill(0)` calls.                                                                |
| 7   | `apps/pgp/hooks/useKeySession.ts`          | KEY_STORE lifetime in JS (handle map, idle-/visibility-/OS-idle locks).                                                      |
| 8   | `apps/pgp/entrypoints/sidepanel/App.tsx`   | Auto-lock wiring + workspace-draft persistence.                                                                              |
| 8a  | `apps/pgp/entrypoints/welcome/Welcome.tsx` | First-install welcome page; only does `chrome.sidePanel.open` from a user-gesture click. No secret material.                 |
| 8b  | `apps/pgp/entrypoints/background.ts`       | Service worker. Two responsibilities: register context-menu items + open the welcome tab on first install. Holds no secrets. |
| 9   | `apps/pgp/lib/network-lockdown.ts`         | Frozen `globalThis.fetch`; blocks XHR/WS/EventSource/RTC/sendBeacon.                                                         |
| 10  | `apps/pgp/scripts/audit-network.mjs`       | Build-time check that no unexpected network code is shipped.                                                                 |
| 11  | `apps/pgp/lib/storage/history.ts`          | Opt-in operation history. Segmented AES-256-GCM blobs under the contacts session key; holds message content. See §11.        |
| 12  | `apps/pgp/lib/workspace-draft.ts`          | In-progress composer text, encrypted under a separate in-WASM draft session key (§6).                                        |
| 13  | `apps/pgp/lib/security/threat-model.ts`    | This document's attack model as typed data. `threat-model.test.ts` fails if a claimed defence names no live test.            |
| 14  | `apps/pgp/scripts/audit-invariants.mjs`    | Build-time enforcement of §9. Replaces running those greps by hand.                                                          |

---

## 4. KEY_STORE invariant

`KEY_STORE` (Rust: `HashMap<u32, StoredKey>`) is the in-WASM cache of
unlocked private keys. There is exactly one insert site:
`parse_and_store_private_key`, called only from `unlock_with_password`
and `unlock_with_prf`. Every entry traces back to a user-initiated
unlock.

```sh
grep -n 'insert_key' apps/pgp/gpg-wasm/src/lib.rs
# → the fn definition, 1 shipping call site (parse_and_store_private_key),
#   and 1 call site inside a `#[cfg(test)]` fn (`store_key`, a unit-test
#   shim that predates the unlock-only rule and is compiled out of release
#   builds). Don't eyeball this — `scripts/audit-invariants.mjs` encodes the
#   cfg(test) exemption and fails the build if a non-test call site appears.

grep -n 'parse_and_store_private_key' apps/pgp/gpg-wasm/src/lib.rs
# → the fn definition + 2 call sites (unlock_with_password, unlock_with_prf)
```

Generation and import (`generateProtectedWith*`,
`protectImportedWith*`) build the cert in WASM, encrypt it, and drop
it at function exit. They never insert into KEY_STORE.

Cached generation (`cache: true`) chains an `unlockWith*` against the
new blob using the credentials the user just provided, so the
KEY_STORE entry still comes from an unlock path.

CRX signing keys (§10) live in a **separate** `CRX_KEY_STORE` and never
touch `KEY_STORE`, so this invariant is unaffected — `insert_key` still
has exactly one shipping call site.

---

## 5. Zeroization — per-secret lifetime

| Secret                                      | Created in                                                           | Zero / drop point                                                         | File                                                             |
| ------------------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Typed password (JS string)                  | React `<input>` state                                                | `setX("")`; V8 GC eventually reclaims                                     | dialog components                                                |
| Password bytes (`Uint8Array`) for wasm      | `TextEncoder.encode(password)`                                       | `.fill(0)` in `finally`                                                   | `protect-flow.ts`, `useKeySession.ts`, dialog components         |
| Argon2id-derived AES key (Rust)             | `argon2_derive`                                                      | `derived.zeroize()` after AES-GCM                                         | `lib.rs` `encrypt_cert_with_password`, `unlock_with_password`    |
| HKDF-derived AES key (Rust)                 | `Hkdf::expand` into `vec![0u8; 32]`                                  | `derived.zeroize()` after AES-GCM                                         | `lib.rs` `encrypt_cert_with_prf`, `unlock_with_prf`              |
| Sequoia `Password`                          | `Password::from(bytes)`                                              | Drop (Sequoia uses `Protected<Vec<u8>>`)                                  | `lib.rs` `decrypt_cert_secrets`, `encrypt_cert_for_export`       |
| Wasm-side password / PRF `Vec<u8>` (owned)  | wasm-bindgen marshals from JS `Uint8Array`                           | `Zeroizing::new(...)` on entry — every secret param is taken by value      | `lib.rs` all `_with_password` / `_with_prf` fns, incl. the three unlock/contacts entry points |
| WebAuthn PRF output                         | `authenticateAndGetPrf`                                              | `prfOutput.fill(0)` in `finally`                                          | `protect-flow.ts`, `useKeySession.ts`, master/onboarding screens |
| Plaintext serialized cert (Rust)            | `cert.as_tsk().to_vec()`                                             | `Zeroizing<Vec<u8>>`, pre-sized to avoid realloc trail                    | `lib.rs` `serialize_secret_cert`, `StoredKey::from_cert`         |
| `StoredKey.bytes` (KEY_STORE entry)         | `StoredKey::from_cert`                                               | `Drop for StoredKey`: `bytes.zeroize()`                                   | `lib.rs`                                                         |
| Cached handle in JS                         | `useKeySession.handleRef`                                            | `dropKey(handle)` on lock / idle / unmount                                | `useKeySession.ts`, `App.tsx`, `ImportKeyPage.tsx`               |
| Contacts session AES key                    | `init_contacts_session_with_prf` / `encrypt_canary_and_init_session` | `set_contacts_key(None)` zeroizes; `dropContactsSession()` on master lock | `lib.rs`, `App.tsx` `doMasterLock`                               |
| AES cipher expanded key schedule            | `Aes256Gcm::new_from_slice`                                          | `zeroize_cipher` after every encrypt/decrypt                              | `lib.rs` `aes_gcm_encrypt`, `aes_gcm_decrypt`                    |
| Workspace draft AES key                     | `init_draft_session_if_unset`                                        | `set_draft_key(None)` on `dropDraftSession` (or panel close)              | `lib.rs`                                                         |
| Encrypted workspace draft                   | App-level `draftCiphertext`                                          | Cleared once `WorkspaceView` rehydrates on unlock                         | `App.tsx`, `useWorkspaceState.ts`                                |
| Decrypted message text (user data, not key) | `decryptWithHandle`                                                  | UI-controlled; cleared on view dismiss / panel close                      | `WorkspaceView.tsx`                                              |
| Clipboard contents after key export         | `clipboard.writeText`                                                | `setTimeout` overwrites with `""` (60s encrypted, 30s plaintext)          | `KeyCard.tsx` `scheduleClipboardClear`                           |
| Workspace input plaintext (ref + DOM node)  | `useWorkspaceState` `inputRef` / textarea `#pgp-input`               | `wipe()` in `doMasterLock` clears the ref, the DOM value and the clear-undo buffer. Uncontrolled on purpose — never in render state. §8.11 | `useWorkspaceState.ts`, `App.tsx` `doMasterLock`                  |
| Decrypted output plaintext (React state)    | `useWorkspaceState` `output`                                         | **NOT cleared on master lock** — retained via React's `fiber.alternate`. Cleared only by reload. See §8.11 / `T-OUTPUT-HEAP-RESIDUE` | `useWorkspaceState.ts`, `WorkspaceView.tsx`                      |
| History segment plaintext JSON (JS)         | `JSON.stringify` → `TextEncoder.encode` in `writeSegment`            | **NOT zeroized** — the `Uint8Array` is never `.fill(0)`'d and the intermediate JSON string is unzeroizable. See §11.2 | `lib/storage/history.ts`                                         |
| History segment plaintext `&[u8]` (wasm)    | wasm-bindgen mallocs a borrowed copy into linear memory              | **NOT zeroized as an owned value** — `encrypt_contacts` takes `&[u8]`, so no `Zeroizing` wrapper; up to 64 KB of content per call | `lib.rs` `encrypt_contacts` / `decrypt_contacts`                 |
| Decrypted segment bytes returned to JS      | `decryptContacts` in `readSegment`                                   | **NOT zeroized** — decoded and dropped without `.fill(0)`                 | `lib/storage/history.ts`                                         |
| Decrypted history entries (JS objects)      | `loadHistory` → `HistoryPage` state                                  | Component unmount on master lock; nothing module-level. Verified by `e2e/history-memory.spec.ts` | `HistoryPage.tsx`, `lib/storage/history.ts`                      |
| CRX RSA PKCS#8 DER (`CRX_KEY_STORE`)        | `unlock_crx_with_*` → `insert_crx_key`                               | `Zeroizing<Vec<u8>>`; `dropCrxKey` / drop. Verified present-then-absent by `e2e/crx-memory.spec.ts` | `gpg-wasm/src/crx.rs`                                            |

---

## 6. Auto-lock

KEY_STORE entries are dropped on any of:

1. Manual per-key lock (`KeyCard` Lock button).
2. Inactivity timer (only when `autoLockEnabled` is true) — fires
   after `autoLockMinutes` of no activity (5/15/30/60, configurable).
   The timer resets on every `getKeyHandle()` call, so "idle" means
   "idle since last cryptographic use," not "idle since unlock."
3. `chrome.idle.onStateChanged` fires `"locked"` (OS lockscreen,
   always immediate, not user-configurable).
4. The side panel becomes hidden (alt-tab / collapsed / window
   minimised) — only when `lockOnTabAway` is on.
5. `lockAllIfNoCache` after every encrypt/decrypt/sign when
   `neverCacheKeys` is on.
6. The side-panel React tree unmounts (effect cleanup).

System-initiated locks (2–4) set `masterAutoLocked`, which suppresses
the `MasterUnlockScreen` auto-passkey ceremony — the user must click
Unlock to trigger WebAuthn after a system lock.

In-progress workspace text is encrypted under a separate in-WASM
session key and held at App level as ciphertext; it rehydrates on
re-unlock. See `lib/workspace-draft.ts`.

---

## 7. Network surface

The extension makes exactly one kind of HTTP call:

1. **Wasm load**, once per side-panel session:
   `fetch(chrome.runtime.getURL("gpg_wasm_bg.wasm"))` — same-origin
   `chrome-extension://`, fetches the WASM blob from the extension's
   own bundle.

The browser-level boundary is the manifest CSP: `connect-src 'self'`
in `wxt.config.ts` blocks any non-extension fetch destination at the
network layer regardless of what JS attempts.

Defence in depth in `lib/network-lockdown.ts` (first import in every
entrypoint): freezes `globalThis.fetch` non-configurable to strip
auth/cookie/api-key headers and reject POST/PUT/PATCH/DELETE; replaces
`XMLHttpRequest`, `WebSocket`, `EventSource`, `RTCPeerConnection`,
`navigator.sendBeacon` with throwing stubs.
`scripts/audit-network.mjs` re-asserts at build time.

---

## 8. What we don't defend (and why)

### 8.1 OS / hardware

- **Swap / page file.** The OS may write WASM-linear-memory or JS-heap
  pages to disk before our zeroize runs; the on-disk copy persists
  until overwritten. macOS encrypts swap by default on T2 / Apple
  Silicon. Linux needs swap-on-LUKS or encrypted ZRAM. Windows
  BitLocker covers the page file when the system drive is encrypted.
- **Hibernation.** RAM is written to disk on hibernate. Full-disk
  encryption covers it.
- **Cold-boot attacks.** DIMMs retain bits for seconds after power-off.
- **Crash dumps.** A browser crash may dump our memory. Chrome uploads
  crash reports to Google if the user opted in (`Send usage statistics
and crash reports`).
- **Hardware side channels.** Spectre-class transient execution,
  Rowhammer, EM emanations. Mitigated by Site Isolation; not airtight.
- **Compromised firmware / SMM / TPM.**

### 8.2 V8 internals

- **GC non-determinism.** `setX("")` drops the React reference; the
  underlying string lives until V8 GCs it. A heap snapshot taken in
  between still sees it.
- **String interning.** V8 may intern strings into long-lived
  structures that survive normal GC.
- **Generational GC copies.** Promotion from young to old gen copies
  bytes; the predecessor allocation is freed without zeroing.
- **JIT artefacts.** V8 may inline string literals into JIT code, hold
  copies in optimised closure contexts, etc.

### 8.3 Rust / LLVM

- **Register spills, stack temporaries, copy elision.** `Zeroize` only
  overwrites the address it's handed. The compiler can hold secrets in
  registers, spill to stack slots that never get overwritten, or copy
  through SIMD scratch — none of which `Zeroize` sees.
- **`allow-variable-time-crypto`.** RustCrypto can't guarantee
  constant-time on `wasm32-unknown-unknown`. A same-origin attacker
  who can time crypto operations could in principle extract bits.
  Documented in `gpg-wasm/Cargo.toml`.
- **Sequoia internals.** We rely on Sequoia's `Protected<T>` for
  zero-on-drop. Sequoia is not line-by-line audited; if it clones a
  secret into a non-`Protected` intermediate, that gap is unaudited.

### 8.4 wasm-bindgen boundary

When JS passes a `Uint8Array` to a Rust `Vec<u8>` parameter, wasm-bindgen
allocates in WASM linear memory, memcpys the bytes, and frees on return
without zeroing. We never see the address of the freed buffer.

So every wasm function taking a secret takes it as an owned `Vec<u8>`,
never `&[u8]`, and wraps it in `Zeroizing` on entry — owning the
marshalled copy is the only way to scrub it. Enforced by
`scripts/audit-invariants.mjs` (`owned-secret-params-zeroized`), which
fails the build on a borrowed secret param.

> Previously `unlock_with_password`, `unlock_with_prf` and
> `init_contacts_session_with_prf` took `&[u8]` and scrubbed only the
> derived AES key, leaving the raw password / PRF bytes in a freed
> allocation — on the app's three most frequently exercised secret entry
> points. Fixed by taking them by value (`T-UNLOCK-PARAM-NOT-OWNED`).
> Note the residual limit: an inner copy made *by* wasm-bindgen before
> our binding sees the value is still outside our reach. What changed is
> that the copy we own is now scrubbed deterministically rather than left
> to allocator reuse.

### 8.5 Browser features the user controls

- **Clipboard managers.** Windows Clipboard History, macOS Universal
  Clipboard, KDE Klipper, Alfred, Raycast etc may retain copies our
  `clipboard.writeText("")` cannot reach.
- **Browser sync.** Chrome Sync syncs extension storage if the user
  has it enabled. Encrypted blobs stay encrypted; protection is the
  master password / passkey.
- **Password managers.** Browser / 1Password / Bitwarden may save
  whatever they observe via our `autoComplete` hints.
- **Autofill, accessibility tree, screen capture.** All can observe
  React state at render — including the user's typed message before
  it's encrypted.
- **Download filenames leak metadata.** Encrypt output defaults to a
  descriptive name carrying the first recipient and a minute-precision
  timestamp — `message.to-alice.2026-07-16-1432.gpg`
  (`components/workspace/output-name.ts`). The *contents* are
  ciphertext; the *filename* is not. Once saved it is cleartext in the
  Downloads folder, indexed by Spotlight / Windows Search, and recorded
  in `chrome://downloads`, which syncs across the user's devices if
  Chrome Sync is on. Anyone with filesystem or browsing-history access
  learns who the user encrypts to and when, without breaking any
  crypto. This is a deliberate usability trade — a Downloads folder of
  identically-named `.gpg` blobs is unusable — but it means the
  encrypt-to-file path does **not** protect recipient identity or
  activity timing. Rename before sharing, and treat the local
  filesystem as in-scope for metadata.
- **DevTools open on the side panel.** Equivalent to running with
  root.

### 8.6 Other software on the device

- **Keyloggers, screen recorders, OS malware.** No application-layer
  defence.
- **Other browser extensions.** Extensions with `chrome.debugger` or
  certain `tabs` permissions may interact with our pages in surprising
  ways. Recommend a Chrome profile with minimal other extensions.

### 8.7 WebAuthn

- **Passkey sync.** If the authenticator syncs (iCloud Keychain,
  Google Password Manager, 1Password etc), the credential is on every
  synced device. Trust is bounded by the sync provider.
- **Authenticator firmware.** A compromised security-key firmware can
  do anything with the credential.
- **Recovery flows.** Account-recovery (e.g. iCloud Keychain via
  SMS / email) is an attack surface.

### 8.8 Supply chain

- **Non-reproducible builds.** The Chrome Web Store binary isn't
  reproducible from this repo; verifying source ≠ verifying ship.
- **Dependency trust.** Sequoia, RustCrypto, wasm-bindgen, React, WXT
  and transitive deps are all trusted.
- **Auto-update.** Chrome Web Store can push silent updates; a
  compromised publisher account would ship malicious code.

### 8.9 The deliberate trapdoor

A user social-engineered into typing `EXPORT` (see §2) and pasting
the result into an attacker-controlled chat leaks their key.
Unfixable in software given the feature exists.

### 8.10 Malicious code executing in the side-panel realm

A compromised UI dependency is **not** defended against. This is the
sharpest limit of the design and it is worth stating precisely, because
§1's WASM-isolation guarantee is easy to over-read.

What *is* opaque to such code: WASM linear memory (no in-page API
enumerates a `WebAssembly.Memory` it doesn't already hold — reading ours
needs a debugger capability like CDP `queryObjects`), and the React tree,
which carries only public metadata plus opaque `u32` handles.

What is **not** opaque is the module's *export table*. The wasm-bindgen
glue ships as an ES module chunk in our own bundle, and the ES module
registry is keyed by resolved URL — so `import()`-ing that chunk returns
the **already-initialised** instance, with the live `KEY_STORE`, not a
fresh empty one. The chunk's hashed filename needs no build-time
knowledge; it appears verbatim in the entry chunk, which same-origin JS
can read. Handles are sequential from 1 (`next_handle`), and the
type-to-confirm "EXPORT" gate is UI, not a boundary. Verified: an
in-page `import()` plus `getKeyArmored(1)` returns plaintext secret key
material with no user gesture.

Such code can equally hook the primitives the boundary is built on, all
of which are looked up per call:

- `TextEncoder.prototype.encode` — the unlock password in transit. The
  `.fill(0)` contract is forensic hygiene, not a defence here.
- `TextDecoder.prototype.decode` — every string returned from WASM, so
  even a perfectly gated export path leaks when the *user* legitimately
  exports.
- `Crypto.prototype.getRandomValues` — the WASM module's only entropy
  source. A hook returning constants makes every subsequently generated
  key predictable.
- `navigator.clipboard.writeText` — read at write time, so the 30s/60s
  auto-clear (a defence against clipboard *managers*) does not apply.

What *does* still apply: the size of the unlocked window (§6 — no handle
survives a lock, so the attack window is exactly the unlocked window,
which makes auto-lock load-bearing security rather than convenience) and
the network lockdown (§7 — exfiltration still has to leave the process).

The honest general statement: you cannot defend against arbitrary JS in
your own realm using in-realm mechanisms. Freezing the primitives above
and shrinking the unlocked window raise an attacker's cost; only moving
the engine into a separate realm (a Worker, with the panel holding just a
narrow `MessagePort`) would change the structure. We have not done that.

Pinned by `e2e/hostile-dep.spec.ts`, which asserts both the gaps and the
two genuine wins (linear memory and React state stay opaque).

### 8.11 Composer plaintext across a lock (fixed; output still open)

Unlike the rest of §8, this was **not** an accepted boundary — it was a
defect. It is recorded in full because the diagnosis is the useful part,
and because one half of it is still open.

The original defect: after an in-app master lock, the user's composed
plaintext remained in the V8 heap. `doMasterLock` encrypted the draft and
unmounted the workspace, so the app believed it held only ciphertext,
while a live plaintext copy survived alongside it. Confirmed not a GC
artefact — still present after six forced collections over ten seconds
plus deliberate string churn.

The first retainer chain found:

```
(GC roots) → C++ Persistent roots
  → autofill::FormTracker  [native]  <textarea id="pgp-input">
    → property[get value]  [closure]
      → context[n]         [string]  the user's plaintext
```

Two mechanisms combine. React installs its own `value` getter/setter on
controlled inputs (`inputValueTracking`), and that closure captures the
last value it saw. Chromium's autofill `FormTracker` then holds a **C++
Persistent** handle to the last-interacted form control, so unmounting
the textarea does not free the node — and the captured plaintext stays
strongly reachable from a GC root.

Blanking the DOM value (as `ImportKeyPage`'s `resetAndClose` does for
pasted key armor) removed that chain and revealed a **second** one, which
is the more important lesson:

```
(GC roots) → (Global handles) → closure
  → property[alternate]              ← React's double-buffered fiber
    → updateQueue.lastEffect.create  ← a retained effect closure
      → context → property[workspace]
        → property[input]  [string]  the user's plaintext
```

The plaintext was in React **state**, not only in the DOM. React
double-buffers hook state onto `fiber.alternate` and keeps effect closures
hanging off it reachable from a GC root long after unmount, so a
controlled `value={input}` retained the string no matter what the DOM
said. **Clearing the DOM was never going to be sufficient.**

**Fixed.** The composer input is now **uncontrolled**: the message lives
in a ref and in the DOM node, never in React render state. Only
non-sensitive derived facts (`hasInput`, `hasTrimmedInput`,
`inputVersion`) enter state. `doMasterLock` *pulls* the draft via
`WorkspaceDraftSource.getDraft()`, encrypts it under the in-WASM draft
key, then calls `wipe()` — clearing the input ref, the textarea's DOM
value, and the clear-undo buffer — before flipping `masterUnlocked`. A ref
is a single mutable slot shared by both fiber copies, so clearing it
actually releases the string; the unmount alone does not.

This also deleted `App.tsx`'s `latestDraftRef`, which had held a live
plaintext copy for the entire panel session on top of the copy React was
already retaining. Push became pull for that reason.

Guarded by `e2e/draft-memory.spec.ts`, which asserts a heap count of zero
after an in-app lock with a positive control proving the scan works. That
spec must run with tracing off — see the caveats in `e2e/README.md`.

**Still open: decrypted output.** `s.output` in `useWorkspaceState` is
ordinary render state and is retained by the identical mechanism after a
lock (measured count 1 following a real encrypt→decrypt→lock cycle).
Reload or relaunch clears it; an in-app lock does not. Making it
uncontrolled is its own refactor — output is rendered, copied, downloaded
and part of the draft. Tracked as `T-OUTPUT-HEAP-RESIDUE`.

Note this is distinct from §8.5's accepted "plaintext is observable in
the rendered UI." That accepts plaintext being visible *while composing*.
This is plaintext persisting *after* the lock, when nothing is rendered.

---

## 9. Verification checklist

All five invariants below are enforced mechanically by
`scripts/audit-invariants.mjs`, which runs as part of `pnpm build` and
fails the build on violation. It resolves enclosing functions and
`#[cfg(test)]` gating structurally rather than counting grep lines, and
masks out comments and string literals so a mention of `console.log(`
in prose can't trip it. The greps below are the human-readable form —
run them to understand an invariant, trust the script to enforce it.

```sh
# 1. KEY_STORE has exactly one *live* insert site. This grep returns three
#    lines: the fn definition, the live call inside
#    parse_and_store_private_key, and a call inside the `#[cfg(test)]`
#    `store_key` shim, which is compiled out of release builds.
grep -nE 'insert_key\(' apps/pgp/gpg-wasm/src/lib.rs

# 2. That site is only called from the unlock paths:
grep -nE 'parse_and_store_private_key' apps/pgp/gpg-wasm/src/lib.rs

# 3. No first-party JS callsite bypasses the boundary module. NOTE: this is
#    a code-hygiene check, NOT a security boundary. It cannot see a runtime
#    import() of the glue chunk, which returns the live instance — see §8.10.
grep -rnE 'wasm\.(generateProtectedWith|protectImportedWith|unlockWith|encryptKeyForExportWithHandle|getKeyArmored|argon2Derive|initContactsSessionWithPrf|encryptCanaryAndInitSession|verifyCanaryAndInitSession|encryptDraft|decryptDraft|initDraftSessionIfUnset|dropDraftSession)' \
  apps/pgp --include='*.ts' --include='*.tsx' \
  | grep -v 'apps/pgp/lib/pgp/wasm-secrets.ts'
# → empty.

# 4. Every wasm fn taking a secret takes it as an owned Vec<u8> (never
#    &[u8]) and wraps it in Zeroizing on entry. Owning the wasm-bindgen
#    marshalled copy is the only way to scrub it -- see §8.4.
grep -nE 'fn (encrypt|protect|generate|unlock|verify_canary|encrypt_canary|init_contacts).*_with_(password|prf)' \
  apps/pgp/gpg-wasm/src/lib.rs

# 5. No console.* in shipping code except the network-lockdown blocked-URL
#    logs. Anything else is a regression. (Note the trailing `(` -- without
#    it this also matches prose mentioning console.* in comments.)
#    Test and spec files are exempt: they are never bundled, so a log there
#    cannot reach a user's devtools alongside unlocked key material. A
#    canary printed by a test still lands in CI logs, though -- treat that
#    as a defect in review even though the gate no longer catches it.
grep -rnE 'console\.[a-z]+\(' apps/pgp --include='*.ts' --include='*.tsx' \
  | grep -vE '\.(test|spec)\.tsx?:'
```

---

## 10. CRX (Chrome extension) signing keys

Optional, off by default (`crxSigningEnabled` preference). Lets a user
sign a packed extension (`.zip`) into a CRX3 `.crx` for the Chrome Web
Store's Verified CRX Uploads, using a key kept in the vault rather than
in CI. All of it lives in `apps/pgp/gpg-wasm/src/crx.rs`.

- **Not OpenPGP.** CRX3 is signed with a raw RSA-2048 (PKCS#1-v1.5-SHA256)
  key, not an OpenPGP signature. Sequoia is not involved; the RustCrypto
  `rsa` primitive is, plus a hand-rolled protobuf encoder for the tiny
  CRX3 header.
- **Key isolation.** The RSA private key (PKCS#8 DER) lives in a separate
  `CRX_KEY_STORE` behind a `u32` handle — `Zeroizing<Vec<u8>>`, zeroized
  on drop / `dropCrxKey`. It is populated only by `unlockCrxWith*`. This
  keeps the `KEY_STORE`-only-via-unlock invariant (§4) intact. Only the
  public half (SPKI DER) and the derived extension id ever cross to JS.
- **At rest.** Identical scheme to PGP keys: Argon2id (64 MB) or
  WebAuthn-PRF → AES-256-GCM, AAD-bound via
  `gpg-tools:crx-{password,passkey}:{extensionId}` (distinct from the PGP
  prefixes, so blobs can't be cross-substituted).
- **Identity binding.** The AAD only covers the extension id *string*, not
  the stored public key — and AAD strings are public. So both trust
  boundaries re-derive the id from the key itself: on unlock, `store_
  decrypted_der` (`crx.rs`) recomputes SHA-256(SPKI) → id and refuses a key
  that doesn't match the id it was sealed under; on the JS side, `addCrxKey`
  / backup import reject a blob whose `publicKeyDerB64` doesn't hash to its
  `extensionId`. A forged blob carrying a foreign key (or a swapped public
  half) is thrown out before it can sign or be shown as "your" key.
- **Verify** (`verifyCrx`) carries no key material and requires a valid
  signature **and** that the proving key's SHA-256 matches the signed
  crx_id — a valid signature by an unrelated key cannot spoof an
  extension id. The parser is panic-free on malformed input.
- **Backup.** Export/Import All Keys round-trips CRX keys in a labelled
  `PGP TOOLS CRX SIGNING KEY` block (`lib/crx/backup.ts`). Bulk export
  *unlocks* each key and *re-seals* it under the single export passphrase so
  the backup restores on any device (a passkey seal is bound to one
  authenticator); this needs each key unlocked first, exactly like the
  per-key "Copy private key". Import stores the blob under whatever
  protection it carries, and — mirroring the PGP path — skips any extension
  id already held rather than overwriting a live signing key.
- **Posture.** Stronger than a key in CI (which a poisoned dependency or
  leaked token would expose); weaker than a hardware token, where the key
  never leaves the chip — here it is briefly reconstructed in the WASM
  sandbox during signing and zeroized after.
- **Memory.** Verified present-then-absent in WASM linear memory by
  `e2e/crx-memory.spec.ts`: with a `CRX_KEY_STORE` handle held open
  across a user step (the bulk-export flow), a needle from the interior
  of RSA prime `p` is found; after unmount runs `closeCrxKey` it is gone,
  with a liveness re-assert so the zero isn't a dead scan.

---

## 11. Operation history

Opt-in, off by default. Records what the user *produces* (encrypt/sign),
not what they read — decrypt/verify rows are deliberately not captured.
Each entry may carry up to 32 KB of **message content** (`CONTENT_CAP`),
so this is the only store that persists user plaintext by design.

- **At rest.** Entries are appended to a head segment, sealed at ~64 KB,
  each an AES-256-GCM blob. A plaintext manifest at `pgp_history` tracks
  only segment numbers and byte sizes — never entry data. Verified by
  `e2e/history-memory.spec.ts`, which also confirms the canary is absent
  from `local`, `sync` and `session`.
- **Always local.** Lives in `chrome.storage.local` regardless of the
  user's storage-location preference: sync's ~100 KB quota couldn't hold
  it, and history shouldn't leave the device.
- **After lock.** Nothing is cached at module level; every read decrypts
  on demand. Verified: after an in-app master lock the canary count in
  the V8 heap is **0**, and a probe that never opens the viewer finds
  zero string nodes containing it.
- **Budget.** Permanently 2 MB (`DEFAULT_BUDGET_BYTES`).
  `optional_permissions` no longer contains `unlimitedStorage`, so
  `requestUnlimitedHistoryStorage` can never succeed and
  `UNLIMITED_BUDGET_BYTES` (50 MB) is unreachable dead code.

### 11.1 Segments are bound to their slot and store

Every store sealed under the master session — keyring, contacts, settings,
CRX keys, and each history segment — is sealed for a **domain**, and the
domain is the `chrome.storage` key the blob lives under. The wasm side
derives both an HKDF-SHA256 subkey and the AEAD's AAD from it
(`gpg-tools:store-subkey:v1:<key>` and `gpg-tools:store:v1:<key>`), so a
blob only opens in the slot it was written to. Moving an intact blob to
another segment number, or to another store, fails the tag check.

Two independent bindings on purpose: the AAD alone would suffice for a
correct AEAD, but a distinct key means a future bug that drops or
mismatches the AAD still cannot cross a domain boundary. An empty domain
is rejected outright so it cannot silently collapse back to one subkey.

Using the storage key as the domain means there is no mapping table to
keep in sync, and the read and write paths physically cannot disagree
about a slot. It is the *key*, not the storage area, so a `local`↔`sync`
move is unaffected. Per-segment binding falls out for free rather than
being a special case.

**Migration.** Blobs written before this keep opening: `openEnvelope`
tries the domain-bound scheme first and falls back to the legacy shared
one. History re-seals on read (it already holds its lock, and re-seals the
exact plaintext bytes so the manifest's `bytes` accounting stays correct);
the shared stores re-seal on the next mutation; and `normalizePadding` —
which runs on unlock — upgrades a store the user only ever reads,
including one whose padding is already canonical. Reads never write, so an
upgrade cannot race a mutation. A failed re-seal leaves the readable
legacy blob alone.

Verified by `e2e/history-memory.spec.ts`, `lib/storage/envelope.test.ts`,
`lib/storage/history.test.ts` and `lib/storage/upgrade.test.ts` (the last
exercises a real v1.3.1 settings blob). The e2e pair was validated against
a negative control: collapsing every domain to one constant makes both
tests fail, each on its own assertion.

> **This does not fix the key coupling.** The per-store subkey is derived
> *from* the contacts session key, so it inherits that key's lifetime
> exactly and possession of the contacts key still yields it. Domain
> separation buys cryptographic separation between stores, not lifetime
> independence — `T-HISTORY-KEY-COUPLING` remains open, and the Rust test
> `test_store_envelope_unreadable_after_the_session_drops` asserts the
> coupling rather than pretending it is gone. Resolving it needs an
> independently generated history key persisted under master protection.

<details>
<summary>The original gap, for the record</summary>

History reuses both the contacts **session key** and the contacts
**AAD** (`gpg-tools:contacts:master`), which is shared with the keyring,
contacts, settings and the CRX key store. Nothing in the sealed data
names the store or the segment number.

Confidentiality is unaffected — the key is master-protected and zeroized
on lock (§5), and the tests above confirm it. **Integrity is not.**
Anyone who can write `chrome.storage.local`, with no knowledge of the
vault key, can:

- **Replay a segment into another slot.** Copying
  `pgp_history_seg_0` → `pgp_history_seg_1` causes `loadHistory`'s
  `adoptStraySegments` to adopt it, producing duplicate entries in the
  viewer. Because adoption only happens for segments it *actually
  decrypted*, this is a rigorous demonstration that the AEAD accepts a
  blob in a slot it was never sealed for.
- **Substitute across stores.** Writing that segment blob to
  `pgp_public_contacts` yields a silently empty contact list after
  reload — and `loadEncryptedArray` gives the UI no way to distinguish
  "tag failed" from "decrypted fine but items failed validation."

Both are demonstrated by `e2e/history-memory.spec.ts`
(`history ciphertext is not bound to its slot or its store`).

The workspace draft showed the correct pattern all along: its own session
key **and** its own versioned AAD (`gpg-tools:workspace-draft:v1`).

</details>

### 11.2 History plaintext is zeroized

Three places, all listed in §5, all previously unzeroized and now fixed:
the `Uint8Array` in `writeSegment` is `.fill(0)`'d in a `finally`;
`encrypt_contacts` and `encrypt_store` take the plaintext **by value**
under `Zeroizing::new` rather than as a borrowed `&[u8]` (the same class
of gap as §8.4, here covering up to 64 KB of message content per call);
and the bytes `decryptContacts` returns in `readSegment` are `.fill(0)`'d
in a `finally`.

Proven behaviourally rather than by inspection: the unit-test mock retains
references to the *actual* buffers that crossed the wasm boundary and
asserts they are non-empty before the call and all-zero after — on write,
on read, on an unparseable segment, and on the legacy-migration path where
one buffer is both the decrypt output and the re-seal input.

The intermediate `JSON.stringify` string remains genuinely unzeroizable
(JS strings are immutable). Avoiding it means hand-serialising entries
into a byte buffer, which is a larger change than the residual leak
justifies; it is called out in `writeSegment`'s doc comment.

> Enforcement note: `audit-invariants.mjs` did not originally match
> `encrypt_store` / `encrypt_contacts` or the `plaintext` param, so this
> claim was unenforced and the check passed either way. `SECRET_FN_RE` and
> `SECRET_PARAM_NAMES` were extended, and the extension was verified to
> fail on a deliberate regression. A gate that cannot fail is not a gate.
