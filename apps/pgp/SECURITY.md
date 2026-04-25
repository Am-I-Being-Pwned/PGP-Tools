# PGP Tools — Security Architecture

**Audience**: external auditors, security-curious users, anyone who wants
to verify the claim "private keys never leave the WASM sandbox in
plaintext form."

This document is the single jumping-off point for that audit. Every
claim here is either backed by a file:line reference or the explicit
text of a code comment. If a claim and the code disagree, **the code is
authoritative** — please open an issue.

---

## 1. Threat model

### What we defend against

- **Malicious or compromised JavaScript** in the side-panel context
  (e.g. supply-chain compromise of a UI dependency) reading private key
  material directly out of the V8 heap.
- **Forensic recovery** of plaintext key material from memory after the
  user has finished using a key (drop / lock / idle timeout).
- **Clipboard exfiltration** by other apps / browser extensions / OS
  clipboard-history tools after a user copies an exported key.
- **Surprise authentication ceremonies** — auto-launching a passkey
  dialog without explicit user input (a screen-grab attacker should not
  get a pre-launched WebAuthn ceremony).
- **Cross-blob substitution** — an attacker who can write to disk
  swapping two encrypted-key blobs to point them at the wrong
  cert. (Defended via AAD binding to the cert's fingerprint.)
- **All outbound network exfiltration**. The extension makes zero
  outbound requests except for one user-initiated context-menu action
  ("Import key from link").

### What we do **not** defend against

- **A fully malicious browser** (compromised V8, compromised extension
  host).
- **An attacker with arbitrary read of the WASM linear memory mid-run**.
  We minimise the *window* during which secrets live there; we cannot
  prevent reads while they do.
- **Side-channel timing attacks** against the RustCrypto backend.
  Sequoia is built with `allow-variable-time-crypto` (required for
  wasm32). Browser sandboxing mitigates in practice; a sophisticated
  same-origin attacker could still observe timing.
- **JS-string immutability for typed passwords**. The DOM `<input>`
  exposes only `string`-typed values; we cannot zero a typed password.
  We `setX("")` to drop the React reference ASAP, but the underlying
  V8-heap allocation lives until GC.
- **OS clipboard managers**. We schedule `clipboard.writeText("")`
  after exports (60s for encrypted-armored, 30s for plaintext) but
  cannot read the clipboard to confirm the user hasn't already copied
  something else.

---

## 2. Trust boundary

```
                       ┌──────────────────────────────────────┐
                       │         WASM linear memory           │
                       │  (Rust / Sequoia-PGP, gpg-wasm/)     │
                       │                                      │
   typed passwords ───►│  Zeroizing<Vec<u8>>                  │
   PRF outputs    ───►│  Sequoia Protected<…> containers      │
   armored input  ───►│  StoredKey { bytes: Vec<u8> } (zeroed)│
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

**The line we defend**: private-key material never crosses from WASM
linear memory back into the JS heap, except via the explicit
`getKeyArmored(handle)` destructive-export path that requires the
user to type the literal word "EXPORT" in the UI.

---

## 3. File map for auditors

Open these in this order:

| Step | File | What to look for |
|------|------|------------------|
| 1 | `apps/pgp/SECURITY.md` (this file) | The contract |
| 2 | `apps/pgp/gpg-wasm/src/lib.rs` | The WASM crate — the actual sandbox. Read the doc-comment header for invariants. |
| 3 | `apps/pgp/lib/pgp/wasm.ts` | The JS-side barrel. Confirms only two sub-modules exist. |
| 4 | `apps/pgp/lib/pgp/wasm-public.ts` | Every wasm wrapper that does **not** carry secrets. |
| 5 | `apps/pgp/lib/pgp/wasm-secrets.ts` | Every wasm wrapper that **does** carry secrets, each with a per-function `@secret-handling` block. |
| 6 | `apps/pgp/lib/protection/protect-flow.ts` | The single JS module that drives generate/import/protect flows. Owns the `Uint8Array.fill(0)` calls. |
| 7 | `apps/pgp/hooks/useKeySession.ts` | KEY_STORE lifetime in the JS layer (handle map, idle/visibility/OS-idle locks). |
| 8 | `apps/pgp/entrypoints/sidepanel/App.tsx` | Auto-lock wiring (visibilitychange, chrome.idle, idle timer). |
| 9 | `apps/pgp/lib/network-lockdown.ts` | Frozen `globalThis.fetch` override; blocks XHR/WebSocket/EventSource/RTC/sendBeacon. |
| 10 | `apps/pgp/scripts/audit-network.mjs` | Build-time assertion that no unexpected network code is shipped. |

---

## 4. KEY_STORE invariant

`KEY_STORE` is the WASM-side `HashMap<u32, StoredKey>` that holds
unlocked private keys behind opaque integer handles. There is exactly
**one** call site that inserts into it: `parse_and_store_private_key`
in `lib.rs`, called only from `unlock_with_password` and
`unlock_with_prf`.

Verify with grep:

```sh
grep -n 'insert_key' apps/pgp/gpg-wasm/src/lib.rs
# 1 call site (parse_and_store_private_key)

grep -n 'parse_and_store_private_key' apps/pgp/gpg-wasm/src/lib.rs
# 2 call sites (unlock_with_password, unlock_with_prf)
```

This means **every entry in `KEY_STORE` traces back to a user-initiated
unlock**. Generation and import (`generateProtectedWith*`,
`protectImportedWith*`) build the cert in WASM, encrypt it under the
user's chosen protection, and drop it at function exit — they
never touch the long-lived store.

If a caller wants the freshly-generated key to be immediately usable
(`cache: true` flag), the protect-flow re-runs the standard
`unlockWith*` path against the just-produced blob, using the same
credentials the user just provided. The store insertion is still tied
to a user-initiated unlock; we just chain the unlock onto the protect
without prompting twice.

---

## 5. Zeroization audit — per-secret lifetime table

| Secret | Created in | Zero / drop point | File:Line |
|--------|------------|-------------------|-----------|
| Typed password (JS string) | React `<input>` state | `setX("")` after use; V8 GC eventually reclaims | `MasterUnlockScreen.tsx`, `KeyCard.tsx`, `ImportKeyDialog.tsx`, `OnboardingFlow.tsx`, `ProtectionMethodPicker.tsx` |
| Password bytes (`Uint8Array`) for wasm call | `new TextEncoder().encode(password)` | `.fill(0)` in `finally` | `protect-flow.ts`, `useKeySession.ts`, `MasterUnlockScreen.tsx`, `OnboardingFlow.tsx`, `KeyCard.tsx` |
| Argon2id-derived key bytes (Rust) | `argon2_derive` | `derived.zeroize()` after AES-GCM use | `lib.rs` `encrypt_cert_with_password`, `unlock_with_password` |
| HKDF-derived key bytes (Rust) | `Hkdf::expand` into `vec![0u8; 32]` | `derived.zeroize()` after AES-GCM use | `lib.rs` `encrypt_cert_with_prf`, `unlock_with_prf` |
| Sequoia `Password` (passphrase wrapper) | `Password::from(bytes)` | Drop (Sequoia internally uses `Protected<Vec<u8>>`) | `lib.rs` `decrypt_cert_secrets`, `encrypt_cert_for_export` |
| Wasm-side passphrase `Vec<u8>` | wasm-bindgen marshals from JS `Uint8Array` | `Zeroizing::new(passphrase)` wraps; zero on drop | `lib.rs` every `_with_password`/`_with_prf` fn |
| WebAuthn PRF output | `authenticateAndGetPrf` | `prfOutput.fill(0)` in `finally` | `protect-flow.ts`, `useKeySession.ts`, `OnboardingFlow.tsx`, `MasterUnlockScreen.tsx` |
| Plaintext serialized cert (Rust) | `cert.as_tsk().to_vec()` | `Zeroizing<Vec<u8>>` wrapper; zero on drop | `lib.rs` `serialize_secret_cert`, `StoredKey::from_cert` (pre-sized to avoid realloc trail) |
| `StoredKey.bytes` (KEY_STORE entry) | `StoredKey::from_cert` (pre-sized) | `Drop` impl: `bytes.zeroize()` | `lib.rs` `impl Drop for StoredKey` |
| Cached handle in JS | `useKeySession.handleRef` | `dropKey(handle)` on lock / idle / unmount | `useKeySession.ts`, `App.tsx`, `ImportKeyDialog.tsx` |
| Contacts session AES key | `init_contacts_session_with_prf` / `encrypt_canary_and_init_session` | `set_contacts_key(None)` zeroizes prior; `wasmApi.dropContactsSession()` on master lock | `lib.rs` `set_contacts_key`, `App.tsx` `doMasterLock` |
| AES cipher expanded key schedule | `Aes256Gcm::new_from_slice` | `zeroize_cipher(&mut cipher)` after every encrypt/decrypt | `lib.rs` `aes_gcm_encrypt`, `aes_gcm_decrypt` |
| Decrypted message text (user data, not key) | `decryptWithHandle` returns bytes → JS `string` | UI-controlled; cleared on view dismiss / panel close | `WorkspaceView.tsx` |
| Clipboard contents after key export | `clipboard.writeText` | `setTimeout` overwrites with `""` (60s encrypted, 30s plaintext) | `KeyCard.tsx` `scheduleClipboardClear` |

---

## 6. Auto-lock surface

KEY_STORE entries are dropped on **any** of:

1. Manual per-key lock (`KeyCard` Lock button → `useKeySession.lock(keyId)` → `dropKey`).
2. Manual master lock (currently no UI, but `doMasterLock()` API exists).
3. Idle timer fires after `autoLockMinutes` of no key access (configurable 5/15/30/60 min).
4. The idle timer **resets on every `getKeyHandle()` call** — i.e. on every encrypt/decrypt/sign use. "Idle" therefore means "idle since last cryptographic use," not "idle since unlock."
5. The side panel's `document.visibilityState` becomes `"hidden"`.
6. `chrome.idle.onStateChanged` fires `"idle"` or `"locked"`.
7. The side panel React tree unmounts (effect cleanup `dropKey`s).

Auto-lock paths set `masterAutoLocked = true`, which suppresses
`MasterUnlockScreen`'s otherwise-automatic passkey ceremony. The user
must click "Unlock with passkey" to trigger WebAuthn after any auto-lock.

---

## 7. Network surface

**Outbound network requests made by the extension**:

1. **One** at WASM init: `fetch(chrome.runtime.getURL("gpg_wasm_bg.wasm"))` —
   loads the WASM binary from the extension's own bundle. Same-origin
   `chrome-extension://` URL.
2. **At most one per user click** of the "Import PGP key from link"
   context menu: `fetch(linkUrl, { redirect: "error" })` for the
   user-clicked URL, then sent via `lockedFetch` which strips
   `Authorization` / `Cookie` / `X-Api-Key` headers and sets
   `credentials: "omit"`.

**Everything else is blocked** by `lib/network-lockdown.ts`, which is
the first import in every entrypoint. It freezes `globalThis.fetch`
non-configurable, blocks `XMLHttpRequest`, `WebSocket`, `EventSource`,
`RTCPeerConnection`, and `navigator.sendBeacon`. The build-time script
`scripts/audit-network.mjs` re-asserts no unexpected network code is
shipped.

---

## 8. Known structural residuals (deliberate)

These are **out of scope** for any patch — they require either browser
or platform-level changes:

- **JS-string immutability** for typed passwords. We can drop
  references but not overwrite memory. Workaround would require a
  custom keystroke-capture component, which is hostile to password
  managers / paste / accessibility / IME.
- **wasm-bindgen boundary memcpy**. Marshalling `Uint8Array` → `Vec<u8>`
  copies the bytes via `__wbindgen_malloc` and frees without
  zeroizing. We can't see the address. Mitigated by minimising
  cross-boundary calls for secrets and by always wrapping the
  WASM-side copy in `Zeroizing`.
- **Decrypted user message text** lives in JS as the whole point of
  the app. UI-controlled lifetime; we don't auto-copy to clipboard.
- **`getKeyArmored` returns plaintext armored key as a JS `String`**
  for the user-initiated destructive export. Mitigated by
  type-to-confirm UI gate and clipboard auto-clear.

---

## 9. Verification checklist

If you want to verify the claims here:

```sh
# 1. KEY_STORE has exactly one insert site:
grep -nE 'insert_key\(' apps/pgp/gpg-wasm/src/lib.rs

# 2. That site is only called from the unlock paths:
grep -nE 'parse_and_store_private_key' apps/pgp/gpg-wasm/src/lib.rs

# 3. No JS-side direct wasm secret call bypasses the boundary module:
grep -rn 'wasm\.\(generateProtectedWith\|protectImportedWith\|unlockWith\|encryptKeyForExportWithHandle\|getKeyArmored\|argon2Derive\|initContactsSessionWithPrf\|encryptCanaryAndInitSession\|verifyCanaryAndInitSession\)' \
  apps/pgp --include='*.ts' --include='*.tsx' \
  | grep -v 'apps/pgp/lib/pgp/wasm-secrets.ts'
# Should return nothing.

# 4. Every `_with_password` / `_with_prf` wasm fn takes owned Vec<u8>
#    (not &[u8]) so we can wrap in Zeroizing:
grep -nE 'fn (encrypt|protect|generate|unlock|verify_canary|encrypt_canary|init_contacts).*_with_(password|prf)' \
  apps/pgp/gpg-wasm/src/lib.rs

# 5. No console.log of secret-bearing variables:
grep -rn 'console\.\(log\|info\|warn\|debug\)' apps/pgp --include='*.ts' --include='*.tsx'
# Only network-lockdown should appear (it logs blocked URLs only).
```
