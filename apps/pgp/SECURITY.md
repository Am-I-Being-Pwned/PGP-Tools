# PGP Tools — Security Architecture

For auditors, security-curious users, and anyone who wants to verify
the claim "private keys never leave the WASM sandbox in plaintext."
If a claim here disagrees with the code, the code wins.

---

## 1. What we defend

- Malicious JS in the side panel (e.g. a compromised UI dep) reading
  private keys from the V8 heap.
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

Both are user-initiated destructive-export paths.

---

## 3. File map

| # | File | What's in it |
|---|------|--------------|
| 1 | `apps/pgp/SECURITY.md` (this file) | The contract |
| 2 | `apps/pgp/gpg-wasm/src/lib.rs` | The WASM crate. The actual sandbox. |
| 3 | `apps/pgp/lib/pgp/wasm.ts` | JS-side barrel. |
| 4 | `apps/pgp/lib/pgp/wasm-public.ts` | Wasm wrappers that don't carry secrets. |
| 5 | `apps/pgp/lib/pgp/wasm-secrets.ts` | Wasm wrappers that do, each with a `@secret-handling` block. |
| 6 | `apps/pgp/lib/protection/protect-flow.ts` | Generate/import/protect. Owns the `Uint8Array.fill(0)` calls. |
| 7 | `apps/pgp/hooks/useKeySession.ts` | KEY_STORE lifetime in JS (handle map, idle-/visibility-/OS-idle locks). |
| 8 | `apps/pgp/entrypoints/sidepanel/App.tsx` | Auto-lock wiring + workspace-draft persistence. |
| 8a | `apps/pgp/entrypoints/welcome/Welcome.tsx` | First-install welcome page; only does `chrome.sidePanel.open` from a user-gesture click. No secret material. |
| 8b | `apps/pgp/entrypoints/background.ts` | Service worker. Two responsibilities: register context-menu items + open the welcome tab on first install. Holds no secrets. |
| 9 | `apps/pgp/lib/network-lockdown.ts` | Frozen `globalThis.fetch`; blocks XHR/WS/EventSource/RTC/sendBeacon. |
| 10 | `apps/pgp/scripts/audit-network.mjs` | Build-time check that no unexpected network code is shipped. |

---

## 4. KEY_STORE invariant

`KEY_STORE` (Rust: `HashMap<u32, StoredKey>`) is the in-WASM cache of
unlocked private keys. There is exactly one insert site:
`parse_and_store_private_key`, called only from `unlock_with_password`
and `unlock_with_prf`. Every entry traces back to a user-initiated
unlock.

```sh
grep -n 'insert_key' apps/pgp/gpg-wasm/src/lib.rs
# → 1 call site (parse_and_store_private_key)

grep -n 'parse_and_store_private_key' apps/pgp/gpg-wasm/src/lib.rs
# → 2 call sites (unlock_with_password, unlock_with_prf)
```

Generation and import (`generateProtectedWith*`,
`protectImportedWith*`) build the cert in WASM, encrypt it, and drop
it at function exit. They never insert into KEY_STORE.

Cached generation (`cache: true`) chains an `unlockWith*` against the
new blob using the credentials the user just provided, so the
KEY_STORE entry still comes from an unlock path.

---

## 5. Zeroization — per-secret lifetime

| Secret | Created in | Zero / drop point | File |
|--------|------------|-------------------|------|
| Typed password (JS string) | React `<input>` state | `setX("")`; V8 GC eventually reclaims | dialog components |
| Password bytes (`Uint8Array`) for wasm | `TextEncoder.encode(password)` | `.fill(0)` in `finally` | `protect-flow.ts`, `useKeySession.ts`, dialog components |
| Argon2id-derived AES key (Rust) | `argon2_derive` | `derived.zeroize()` after AES-GCM | `lib.rs` `encrypt_cert_with_password`, `unlock_with_password` |
| HKDF-derived AES key (Rust) | `Hkdf::expand` into `vec![0u8; 32]` | `derived.zeroize()` after AES-GCM | `lib.rs` `encrypt_cert_with_prf`, `unlock_with_prf` |
| Sequoia `Password` | `Password::from(bytes)` | Drop (Sequoia uses `Protected<Vec<u8>>`) | `lib.rs` `decrypt_cert_secrets`, `encrypt_cert_for_export` |
| Wasm-side passphrase `Vec<u8>` | wasm-bindgen marshals from JS `Uint8Array` | `Zeroizing::new(passphrase)` on entry | `lib.rs` every `_with_password`/`_with_prf` fn |
| WebAuthn PRF output | `authenticateAndGetPrf` | `prfOutput.fill(0)` in `finally` | `protect-flow.ts`, `useKeySession.ts`, master/onboarding screens |
| Plaintext serialized cert (Rust) | `cert.as_tsk().to_vec()` | `Zeroizing<Vec<u8>>`, pre-sized to avoid realloc trail | `lib.rs` `serialize_secret_cert`, `StoredKey::from_cert` |
| `StoredKey.bytes` (KEY_STORE entry) | `StoredKey::from_cert` | `Drop for StoredKey`: `bytes.zeroize()` | `lib.rs` |
| Cached handle in JS | `useKeySession.handleRef` | `dropKey(handle)` on lock / idle / unmount | `useKeySession.ts`, `App.tsx`, `ImportKeyDialog.tsx` |
| Contacts session AES key | `init_contacts_session_with_prf` / `encrypt_canary_and_init_session` | `set_contacts_key(None)` zeroizes; `dropContactsSession()` on master lock | `lib.rs`, `App.tsx` `doMasterLock` |
| AES cipher expanded key schedule | `Aes256Gcm::new_from_slice` | `zeroize_cipher` after every encrypt/decrypt | `lib.rs` `aes_gcm_encrypt`, `aes_gcm_decrypt` |
| Workspace draft AES key | `init_draft_session_if_unset` | `set_draft_key(None)` on `dropDraftSession` (or panel close) | `lib.rs` |
| Encrypted workspace draft | App-level `draftCiphertext` | Cleared once `WorkspaceView` rehydrates on unlock | `App.tsx`, `useWorkspaceState.ts` |
| Decrypted message text (user data, not key) | `decryptWithHandle` | UI-controlled; cleared on view dismiss / panel close | `WorkspaceView.tsx` |
| Clipboard contents after key export | `clipboard.writeText` | `setTimeout` overwrites with `""` (60s encrypted, 30s plaintext) | `KeyCard.tsx` `scheduleClipboardClear` |

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

The extension makes two kinds of HTTP calls:

1. **Wasm load**, once per side-panel session:
   `fetch(chrome.runtime.getURL("gpg_wasm_bg.wasm"))` — same-origin
   `chrome-extension://`, fetches the WASM blob from the extension's
   own bundle.
2. **Import key from link**, on user click of the context menu:
   `fetch(linkUrl, { redirect: "error" })` — goes through
   `lockedFetch`, which strips `Authorization` / `Cookie` /
   `X-Api-Key` and sets `credentials: "omit"`.

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
without zeroing. We never see the address of the freed buffer. The
Rust-side copy we do control is `Zeroizing`-wrapped on entry.

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

---

## 9. Verification checklist

```sh
# 1. KEY_STORE has exactly one insert site:
grep -nE 'insert_key\(' apps/pgp/gpg-wasm/src/lib.rs

# 2. That site is only called from the unlock paths:
grep -nE 'parse_and_store_private_key' apps/pgp/gpg-wasm/src/lib.rs

# 3. No JS-side direct wasm secret call bypasses the boundary module:
grep -rnE 'wasm\.(generateProtectedWith|protectImportedWith|unlockWith|encryptKeyForExportWithHandle|getKeyArmored|argon2Derive|initContactsSessionWithPrf|encryptCanaryAndInitSession|verifyCanaryAndInitSession|encryptDraft|decryptDraft|initDraftSessionIfUnset|dropDraftSession)' \
  apps/pgp --include='*.ts' --include='*.tsx' \
  | grep -v 'apps/pgp/lib/pgp/wasm-secrets.ts'
# → empty.

# 4. Every `_with_password` / `_with_prf` wasm fn takes owned Vec<u8>
#    so we can wrap in Zeroizing:
grep -nE 'fn (encrypt|protect|generate|unlock|verify_canary|encrypt_canary|init_contacts).*_with_(password|prf)' \
  apps/pgp/gpg-wasm/src/lib.rs

# 5. No console.* anywhere except the network-lockdown blocked-URL
#    logs. Anything else is a regression.
grep -rn 'console\.' apps/pgp --include='*.ts' --include='*.tsx'
```
