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
  This does **not** extend to code _executing_ in the side-panel realm.
  A compromised UI dependency does not need the heap — it can call the
  WASM exports directly. See §8.10.
- Forensic recovery of plaintext key material after the user is done
  with a key (drop / lock / idle).
- Clipboard exfiltration after key export (auto-clear after 30s/60s).
- Surprise passkey ceremonies after a system-initiated lock — the
  user must click Unlock first.
- Cross-blob substitution: ciphertext AAD is bound to the key's identity
  — the cert fingerprint, the CRX extension id, or the SSH key's SHA-256
  fingerprint — under a per-key-type prefix, so swapping two encrypted-key
  blobs on disk fails authentication, whether they are the same key type
  or not.
- Outbound network exfiltration (§7) — with two deliberate exceptions,
  both of them key-discovery lookups: the background service worker may
  reach `https://api.github.com/users/` and
  `https://keys.openpgp.org/vks/v1/`, and only those. Neither is reachable
  by any code path unless the `keyDiscoveryEnabled` preference is on (it
  is on by default, and off in the strictest security preset). The side
  panel, which is the realm that holds key handles and composed
  plaintext, is still pinned to `connect-src 'self'`. Read §7 before
  relying on this line.

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
   armored input   ───►│  Zeroizing<Vec<u8>> (Drop zeroizes)  │
                       │  KEY_STORE: protected::HandleStore   │
                       │   (HashMap<u32, Zeroizing<Vec<u8>>>) │
                       │                                      │
                       │  ↑ entries inserted ONLY by         │
                       │     unlockWithPassword / unlockWithPrf│
                       │                                      │
                       │  sibling stores, same type, separate │
                       │  instances (§4, §10, §13):           │
                       │   CRX_KEY_STORE  — RSA PKCS#8 DER    │
                       │   SSH_KEY_STORE  — OpenSSH priv key  │
                       │                                      │
                       │  at-rest envelope for all three:     │
                       │   protected::seal_with_* / open_*    │
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

Both are user-initiated destructive-export paths _in the UI_. Neither is
enforced as such at the WASM boundary — the type-to-confirm gate is React
state, not a capability check. Code running in the side-panel realm can
call either export directly. See §8.10.

---

## 3. File map

| #   | File                                       | What's in it                                                                                                                                                                                                                                                          |
| --- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `apps/pgp/SECURITY.md` (this file)         | The contract                                                                                                                                                                                                                                                          |
| 2   | `apps/pgp/gpg-wasm/src/lib.rs`             | The WASM crate. The actual sandbox.                                                                                                                                                                                                                                   |
| 2a  | `apps/pgp/gpg-wasm/src/crx.rs`             | RSA-2048 CRX (Chrome extension) signer/verifier. Separate `CRX_KEY_STORE`; see §10.                                                                                                                                                                                   |
| 2b  | `apps/pgp/gpg-wasm/src/age.rs`             | age encrypt/decrypt to imported SSH keys (`ssh-ed25519`, `ssh-rsa`). Separate `SSH_KEY_STORE`; see §13.                                                                                                                                                               |
| 2c  | `apps/pgp/gpg-wasm/src/protected.rs`       | The at-rest envelope every key type is sealed by (`seal_with_*` / `open_*`), plus the generic `HandleStore`. See §5, §13.                                                                                                                                             |
| 5b  | `apps/pgp/lib/age/`                        | JS-side age coordinator and SSH-identity import/unlock/drop. Holds recipient lines and `u32` handles; no key material.                                                                                                                                                |
| 5a  | `apps/pgp/lib/crx/`                        | JS-side CRX key storage, sign/verify coordinator, and backup (de)serialization.                                                                                                                                                                                       |
| 3   | `apps/pgp/lib/pgp/wasm.ts`                 | JS-side barrel.                                                                                                                                                                                                                                                       |
| 4   | `apps/pgp/lib/pgp/wasm-public.ts`          | Wasm wrappers that don't carry secrets.                                                                                                                                                                                                                               |
| 5   | `apps/pgp/lib/pgp/wasm-secrets.ts`         | Wasm wrappers that do, each with a `@secret-handling` block.                                                                                                                                                                                                          |
| 6   | `apps/pgp/lib/protection/protect-flow.ts`  | Generate/import/protect. Owns the `Uint8Array.fill(0)` calls.                                                                                                                                                                                                         |
| 7   | `apps/pgp/hooks/useKeySession.ts`          | KEY_STORE lifetime in JS (handle map, idle-/visibility-/OS-idle locks).                                                                                                                                                                                               |
| 8   | `apps/pgp/entrypoints/sidepanel/App.tsx`   | Auto-lock wiring + workspace-draft persistence.                                                                                                                                                                                                                       |
| 8a  | `apps/pgp/entrypoints/welcome/Welcome.tsx` | First-install welcome page; only does `chrome.sidePanel.open` from a user-gesture click. No secret material.                                                                                                                                                          |
| 8b  | `apps/pgp/entrypoints/background.ts`       | Service worker. Context menus + welcome tab, the two key-discovery lookups (§7, §7.1), and the pending-op channel. No wasm, no keys -- but it writes the user's raw selection to `chrome.storage.session` unsealed (§7).                                              |
| 8c  | `apps/pgp/entrypoints/gmail.content.ts`    | The opt-in Gmail add-on's content script, registered at runtime only while the optional mail.google.com permission is held. No keys, wasm or storage; one pinned same-origin fetch (attachments, on the panel's request); writes only ciphertext into Gmail. See §17. |
| 8d  | `apps/pgp/entrypoints/gmail-frame/`        | The add-on's inline reader frame: an extension page Gmail embeds where an encrypted block was. A dumb view fed by the panel over a runtime port, like the reader tab (§16). The only web-accessible resource. See §17.                                                |
| 8e  | `apps/pgp/hooks/useGmailFrames.ts`         | The panel's side of the frames: decrypts/verifies for them under §15's unattended rules (an open handle or nothing), posts plaintext over the port and keeps none.                                                                                                    |
| 9   | `apps/pgp/lib/network-lockdown.ts`         | Frozen `globalThis.fetch`; blocks XHR/WS/EventSource/RTC/sendBeacon.                                                                                                                                                                                                  |
| 10  | `apps/pgp/scripts/audit-network.mjs`       | Build-time per-context census: worker = 2 fetches, pinned apart to api.github.com and keys.openpgp.org; pages = no code that can name a remote destination.                                                                                                           |
| 11  | `apps/pgp/lib/storage/history.ts`          | Opt-in operation history. Segmented AES-256-GCM blobs under the contacts session key; holds message content. See §11.                                                                                                                                                 |
| 12  | `apps/pgp/lib/workspace-draft.ts`          | In-progress composer text, encrypted under a separate in-WASM draft session key (§6).                                                                                                                                                                                 |
| 13  | `apps/pgp/lib/security/threat-model.ts`    | This document's attack model as typed data. `threat-model.test.ts` fails if a claimed defence names no live test.                                                                                                                                                     |
| 14  | `apps/pgp/scripts/audit-invariants.mjs`    | Build-time enforcement of §9. Replaces running those greps by hand.                                                                                                                                                                                                   |
| 15  | `apps/pgp/gpg-wasm/src/rng.rs`             | ChaCha20 CSPRNG between us and `crypto.getRandomValues`. See §12 for what it does and does not cover.                                                                                                                                                                 |

---

## 4. KEY_STORE invariant

`KEY_STORE` (Rust: a `protected::HandleStore`, i.e.
`HashMap<u32, Zeroizing<Vec<u8>>>`) is the in-WASM cache of
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

"Unlock keys with the vault" (§14) is the same story from the other
side: the master passkey ceremony is a user-initiated unlock, and the
keys it opens go through `unlock_with_prf` exactly like a per-key
prompt would. `reprotect_key_with_prf` (the re-seal primitive)
reads a live handle and **inserts nothing**; the re-sealed blob only
ever enters KEY_STORE through a later unlock.

CRX signing keys (§10) and imported SSH identities (§13) live in
**separate** stores — `CRX_KEY_STORE` and `SSH_KEY_STORE` — and never
touch `KEY_STORE`, so this invariant is unaffected: `insert_key` still
has exactly one shipping call site. All three are distinct
`thread_local!` instances of the same `protected::HandleStore` type, and
a store is only reachable through the module that declares it, which is
what keeps "KEY_STORE holds OpenPGP certs and is populated only by the
unlock paths" a checkable claim rather than a convention. Handles come
from the crate-wide monotonic `next_handle`, so no two stores ever issue
the same `u32`.

---

## 5. Zeroization — per-secret lifetime

| Secret                                         | Created in                                                                 | Zero / drop point                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | File                                                                                          |
| ---------------------------------------------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Typed password (JS string)                     | React `<input>` state                                                      | `setX("")`; V8 GC eventually reclaims                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | dialog components                                                                             |
| Password bytes (`Uint8Array`) for wasm         | `TextEncoder.encode(password)`                                             | `.fill(0)` in `finally`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | `protect-flow.ts`, `useKeySession.ts`, dialog components                                      |
| Argon2id-derived AES key (Rust)                | `argon2_derive`                                                            | `derived.zeroize()` after AES-GCM                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `protected.rs` `seal_with_password` / `open_with_password` (all key types)                    |
| HKDF-derived AES key (Rust)                    | `Hkdf::expand` into `vec![0u8; 32]`                                        | `derived.zeroize()` after AES-GCM                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `protected.rs` `seal_with_prf` / `open_with_prf` (all key types)                              |
| Sequoia `Password`                             | `Password::from(bytes)`                                                    | Drop (Sequoia uses `Protected<Vec<u8>>`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | `lib.rs` `decrypt_cert_secrets`, `encrypt_cert_for_export`                                    |
| Wasm-side password / PRF `Vec<u8>` (owned)     | wasm-bindgen marshals from JS `Uint8Array`                                 | `Zeroizing::new(...)` on entry — every secret param is taken by value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `lib.rs` all `_with_password` / `_with_prf` fns, incl. the three unlock/contacts entry points |
| JS-side OpenSSH key-file `Uint8Array`          | `new TextEncoder().encode(text)` before the wasm call                      | `.fill(0)` in a `finally`. NOTE: the source `text` is an immutable JS string and cannot be zeroized, so this scrubs one additional copy rather than eliminating the exposure                                                                                                                                                                                                                                                                                                                                                                                                                                | `lib/import/prepare.ts` (`sshPrivateKeyFormatRejection` call), `lib/age/protect-flow.ts`      |
| WebAuthn PRF output                            | `authenticateAndGetPrf`                                                    | `prfOutput.fill(0)` in `finally`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `protect-flow.ts`, `useKeySession.ts`, master/onboarding screens                              |
| Plaintext serialized cert (Rust)               | `cert.as_tsk().to_vec()`                                                   | `Zeroizing<Vec<u8>>`, pre-sized to avoid realloc trail                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | `lib.rs` `serialize_secret_cert`, `insert_key`                                                |
| KEY_STORE entry (`Zeroizing<Vec<u8>>`)         | `insert_key` -> `HandleStore::insert`                                      | `Drop for Zeroizing`: zeroized on `remove`/replace                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `lib.rs`                                                                                      |
| Cached handle in JS                            | `useKeySession` store (closure-private map)                                | `dropKey` / `closeSshIdentity` on lock / idle, dispatched by key kind. An unlock that resolves AFTER a lock is dropped rather than stored: the store captures a lock generation when the unlock starts and re-checks it before inserting, and insertion has exactly one entry point so a new unlock path cannot bypass it. Unit-tested in `useKeySession.test.ts`, and driven end to end on the SSH passkey path — ceremony held open, master lock, ceremony released — by `e2e/ssh-memory.spec.ts`                                                                                                         | `useKeySession.ts`, `App.tsx` `doMasterLock`                                                  |
| Contacts session AES key                       | `init_contacts_session_with_prf` / `encrypt_canary_and_init_session`       | `set_contacts_key(None)` zeroizes; `dropContactsSession()` on master lock                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `lib.rs`, `App.tsx` `doMasterLock`                                                            |
| AES cipher expanded key schedule               | `Aes256Gcm::new_from_slice`                                                | `zeroize_cipher` after every encrypt/decrypt                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `lib.rs` `aes_gcm_encrypt`, `aes_gcm_decrypt`                                                 |
| Workspace draft AES key                        | `init_draft_session_if_unset`                                              | `set_draft_key(None)` on `dropDraftSession` (or panel close)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | `lib.rs`                                                                                      |
| Encrypted workspace draft                      | App-level `draftCiphertext`                                                | Cleared once `WorkspaceView` rehydrates on unlock                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `App.tsx`, `useWorkspaceState.ts`                                                             |
| Symmetric message password (`Uint8Array`)      | `TextEncoder.encode(password)` in `lib/pgp/operations.ts`                  | `.fill(0)` in `finally` on the JS side; `Zeroizing::new(...)` on entry in Rust — `decrypt_with_password` takes the param **owned**, so unlike the `unlock_*` fns there is no un-scrubbed marshalled copy (`T-UNLOCK-PARAM-NOT-OWNED`). The React `<input>` string behind it is immutable and is bounded by the panel's lifetime, as every typed password is                                                                                                                                                                                                                                                 | `lib/pgp/operations.ts`, `lib.rs` `decrypt_with_password`                                     |
| Decrypted message text (user data, not key)    | `decryptWithHandle` / `decryptWithPassword`                                | UI-controlled; cleared on view dismiss / panel close                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `WorkspaceView.tsx`                                                                           |
| Clipboard contents after key export            | `clipboard.writeText`                                                      | `setTimeout` overwrites with `""` (60s encrypted, 30s plaintext)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `KeyCard.tsx` `scheduleClipboardClear`                                                        |
| Workspace input plaintext (ref + DOM node)     | `useWorkspaceState` `inputRef` / textarea `#pgp-input`                     | `wipe()` in `doMasterLock` clears the ref, the DOM value and the clear-undo buffer. Uncontrolled on purpose — never in render state. §8.11                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | `useWorkspaceState.ts`, `App.tsx` `doMasterLock`                                              |
| Decrypted output plaintext (ref + DOM node)    | `useWorkspaceState` `outputRef` / the result `<pre>`                       | `wipe()` in `doMasterLock` clears the ref and the node's text. Written via `textContent`, never a React child, so it never enters render state. §8.11                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `useWorkspaceState.ts`, `OutputArea.tsx`                                                      |
| History segment plaintext JSON (JS)            | `JSON.stringify` → `TextEncoder.encode` in `writeSegment`                  | **NOT zeroized** — the `Uint8Array` is never `.fill(0)`'d and the intermediate JSON string is unzeroizable. See §11.2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | `lib/storage/history.ts`                                                                      |
| History segment plaintext `&[u8]` (wasm)       | wasm-bindgen mallocs a borrowed copy into linear memory                    | **NOT zeroized as an owned value** — `encrypt_contacts` takes `&[u8]`, so no `Zeroizing` wrapper; up to 64 KB of content per call                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | `lib.rs` `encrypt_contacts` / `decrypt_contacts`                                              |
| Decrypted segment bytes returned to JS         | `decryptContacts` in `readSegment`                                         | **NOT zeroized** — decoded and dropped without `.fill(0)`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `lib/storage/history.ts`                                                                      |
| Decrypted history entries (JS objects)         | `loadHistory` → `HistoryPage` state                                        | Component unmount on master lock; nothing module-level. Verified by `e2e/history-memory.spec.ts`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `HistoryPage.tsx`, `lib/storage/history.ts`                                                   |
| CRX RSA PKCS#8 DER (`CRX_KEY_STORE`)           | `unlock_crx_with_*` → `insert_crx_key`                                     | `Zeroizing<Vec<u8>>`; `dropCrxKey` / drop. Verified present-then-absent by `e2e/crx-memory.spec.ts`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `gpg-wasm/src/crx.rs`                                                                         |
| SSH source passphrase (on the user's key file) | wasm-bindgen marshals `source_passphrase` from JS                          | `Zeroizing::new(...)` on entry — taken by value; used once to decrypt the OpenSSH file, dropped at function exit including on error paths                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | `gpg-wasm/src/age.rs` `protect_ssh_identity_with_*`                                           |
| Normalized (unencrypted) OpenSSH private key   | `ssh_key::PrivateKey::to_openssh`, after the source passphrase is stripped | `Zeroizing<Vec<u8>>` over `ssh-key`'s own `Zeroizing<String>`; dropped once sealed. Never crosses to JS. Asserted absent from linear memory after the import call returns, by `e2e/ssh-memory.spec.ts`                                                                                                                                                                                                                                                                                                                                                                                                      | `gpg-wasm/src/age.rs` `normalize_openssh_identity`                                            |
| SSH identity (`SSH_KEY_STORE`)                 | `unlock_ssh_identity_with_*` → `HandleStore::insert_validated`             | `Zeroizing<Vec<u8>>`; `dropSshIdentity` / replace / thread teardown. A payload that fails validation is dropped, and so wiped, before it is reachable. Verified present-then-absent (per-key lock, master lock, vault re-unlock) by `e2e/ssh-memory.spec.ts`; see `T-SSH-KEY-MEMORY` for what that evidence does and does not cover                                                                                                                                                                                                                                                                         | `gpg-wasm/src/age.rs`                                                                         |
| Decrypted age plaintext returned to JS         | `decryptAgeWithHandle`                                                     | Rust-side buffer wiped by the crate's zeroize-on-free allocator when the marshalled copy is freed. **The JS-side copy is a `.slice()` the caller owns, and `lib/age/operations.ts` scrubs it -- `.fill(0)` on the UTF-8 branch, where the decoded string is the result and the buffer is surplus. NOT on the binary branch, where the buffer IS the result and ownership passes to the workspace (`zeroizeResultBytes` at master lock). As for the OpenSSH row above: the decoded string is an immutable JS string, is not zeroizable, and outlives the buffer -- this removes one copy, not the exposure** | `gpg-wasm/src/age.rs` `decrypt_age_with_handle`                                               |

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
6. The side panel closes. NOTE: this is not an effect-cleanup drop --
   `useKeySession`'s unmount cleanup clears the auto-lock timer and
   releases no handles. What ends the keys' lifetime here is the panel
   being torn down along with the WASM instance holding them, so nothing
   survives; but there is no code performing the drop, and this list
   previously implied there was.

System-initiated locks (2–4) set `masterAutoLocked`, which suppresses
the `MasterUnlockScreen` auto-passkey ceremony — the user must click
Unlock to trigger WebAuthn after a system lock.

In-progress workspace text is encrypted under a separate in-WASM
session key and held at App level as ciphertext; it rehydrates on
re-unlock. See `lib/workspace-draft.ts`.

---

> **Fixed, and worth recording.** `lib/network-lockdown.ts` is the first
> import in every entrypoint, including the background service worker.
> It referenced `Clipboard.prototype` and `navigator.clipboard`
> unguarded — both document-only APIs that do not exist in a worker
> realm — so reading them threw at module scope and **the service worker
> crashed on startup**. WXT's wrapper logs "The background crashed on
> startup!" and rethrows; nothing else surfaced it. The failure mode was
> silent absence: the context menu was never created (its `onInstalled`
> listener never registered), the keyboard commands never bound, the
> install-time welcome tab never opened, and `setPanelBehavior` never
> ran. This was live in shipped builds through 1.4.4 — verified by
> finding the same reference in that release's `background.js`. No e2e
> exercised the background worker, which is why it survived. The
> document-only pins are now existence-guarded; there is nothing to pin
> in a worker because the API a tap would target is not there.

## 7. Network surface

The extension makes exactly **two** kinds of HTTP call. It used to make
one, and the sentence "the extension never talks to a remote server" was
true until the GitHub recipient lookup shipped. It is not true any more,
and this section says so before it says anything else.

1. **Wasm load**, once per side-panel session:
   `fetch(chrome.runtime.getURL("gpg_wasm_bg.wasm"))` — same-origin
   `chrome-extension://`, fetches the WASM blob from the extension's
   own bundle.

2. **GitHub SSH-key lookup**, `GET https://api.github.com/users/<u>/keys`.
   - **Where.** The background service worker, and only there. The panel
     asks the worker over the message boundary and never issues the
     request itself.
   - **When.** Only on an explicit button press in the import UI. Never
     on a timer, never on install, never on unlock, never on encrypt,
     never as a background refresh. One press, one request.
   - **What it carries.** The username, in the URL path. Nothing else:
     no body (it is a GET), no message content, no key material, no
     vault or installation identifier, no telemetry.
   - **What it does not carry.** No credentials. `network-lockdown.ts`
     forces `credentials: "omit"` and strips `Cookie`, `Authorization`
     and `X-Api-Key`, and the extension holds **no host permission** for
     `api.github.com` — the endpoint answers unauthenticated with
     `access-control-allow-origin: *`, so none is needed and none is
     requested. `host_permissions` is absent from the manifest, and the
     build audit fails if it appears. `optional_host_permissions` holds
     exactly one pattern, `https://mail.google.com/*`, for the opt-in
     Gmail add-on (§17); the audit pins it, and it can never cover
     either lookup host.
   - **What it does not buy.** Omitting the cookie means the request is
     not joinable to the user's GitHub account _from the request alone_.
     It is not anonymity. GitHub still learns the username looked up,
     the IP, and the time, and can join on IP with any logged-in
     browsing from the same address. Pasting an `ssh-ed25519 …` line
     does the same job with no network at all and stays first-class.
     `T-GITHUB-LOOKUP-DISCLOSURE`.

3. **Keyserver certificate lookup**, `GET
https://keys.openpgp.org/vks/v1/by-{email,fingerprint,keyid}/<q>`.
   - **Where.** The background service worker, and only there. The panel
     asks the worker over the message boundary and never issues the
     request itself.
   - **When.** Only on an explicit button press in the import UI, and
     only while `keyDiscoveryEnabled` is on — with it off, the field that
     starts a lookup is not rendered and no code path reaches either
     endpoint. Never on a timer, never on install, never on unlock,
     never on encrypt, never as a background refresh. One press, one
     request.
   - **What it carries.** The canonical query — a lowercased address, or
     an uppercase fingerprint or long key id — in the URL path. Nothing
     else: no body (it is a GET), no message content, no key material, no
     vault or installation identifier, no telemetry.
   - **What it does not carry.** No credentials, exactly as above; the
     endpoint answers unauthenticated with `access-control-allow-origin:
*` (measured), so no host permission is needed or requested.
   - **What it does not buy, and why this one is worse than the GitHub
     lookup.** A GitHub lookup discloses an account name; this discloses
     an **email address** — the identity of the person the user is about
     to write to — in the clear in a URL path, to a third party with no
     other reason to know it. Looking up **by fingerprint** discloses
     strictly less (it names a key, not a person) and the same field
     accepts one. Pasting the armored cert does the same job with no
     network at all and stays first-class.
     `T-KEYSERVER-LOOKUP-DISCLOSURE`.
   - **What the service's own verification means.** keys.openpgp.org
     publishes an address only after an email round-trip to it. That is
     **mailbox control at upload time, not identity**, and it is a
     property an attacker who controls or intercepts that mailbox also
     has. It is not verification and the UI does not present it as such.
     `T-KEYSERVER-KEY-SUBSTITUTION`.

**The CSP is no longer uniform, and `connect-src 'self'` is no longer an
extension-wide claim.** It is now two policies:

- **Manifest** (`wxt.config.ts`, applies to every extension realm
  including the MV3 service worker — CSP does reach the worker, verified:
  with plain `connect-src 'self'` the worker's fetch fails, and widened it
  returns 200):
  `connect-src 'self' https://api.github.com/users/ https://keys.openpgp.org/vks/v1/`.
  Note that a manifest is static: the `keyDiscoveryEnabled` preference
  removes the only code path that reaches these origins, it does not and
  cannot narrow this policy.
- **Panel** (`entrypoints/sidepanel/index.html`): a
  `<meta http-equiv="Content-Security-Policy" content="connect-src 'self'">`
  tag. Meta CSP can only tighten, never loosen, so the panel realm is
  back to exactly where it was before this feature. Verified in a real
  build: with the manifest widened, the worker's fetch returned 200 while
  the same fetch from the panel failed. This is enforced by the browser
  at document load, **not** by our own same-realm JS, so unlike
  `network-lockdown.ts` it is not subject to §8.10's hook problem.

**The residual, stated rather than glossed.** CSP path-matches the path
and **not the query string**. `https://api.github.com/users/x/keys` is
allowed and so is `…/keys?leak=SECRET` — verified. A `/gists` path is
blocked, so the prefix itself works. The keyserver origin adds a second
host the same channel can be pointed at; it does not change the shape of
the residual. What this means: a compromised
_worker_ bundle could exfiltrate inside a query string on an allowed
path, and no narrower CSP can close that. What bounds it: the worker
is the ORIGIN of one plaintext rather than a router of it:
`contextMenus.onClicked` hands it `info.selectionText`, and
`openPanelWithOperation` writes that selection **unsealed** into
`chrome.storage.session`. It can read every storage key: the sealed blobs
(opaque to it -- no wasm instance means no session key) and the cleartext
ones. The most valuable of those is `pgp_master_protection`, which for the
password path is `kdfSalt` + `encryptedCanary`: a **verifiable offline
brute-force oracle** for the master password. What bounds it is that it
holds no key material and no wasm instance (structural -- the build audit
asserts `background.js` has no module imports), that the one plaintext it
does hold now has a bounded lifetime (`T-PENDING-OP-AT-REST`), that the
channel is GET-only to one path-prefixed origin, and that the panel realm
-- which does hold key handles and plaintext -- keeps `connect-src 'self'`.
Bandwidth is NOT offered as a bound: a query string is small, but the
worker can issue many. `T-GITHUB-CSP-SCOPE`.

Defence in depth in `lib/network-lockdown.ts` (first import in every
entrypoint, active in the worker as well as the pages, and unchanged by
this feature — it already permitted HTTPS GET with `credentials: "omit"`):
freezes `globalThis.fetch` non-configurable to strip auth/cookie/api-key
headers and reject plain HTTP and POST/PUT/PATCH/DELETE; replaces
`XMLHttpRequest`, `WebSocket`, `EventSource`, `RTCPeerConnection`,
`navigator.sendBeacon` with throwing stubs.

`scripts/audit-network.mjs` re-asserts all of this at build time, and now
does so **per context with exact counts** rather than against one flat
allowlist:

- **worker bundle** — exactly two `fetch` call sites beyond the
  lockdown's own reference to `globalThis.fetch`, and they are pinned
  **apart**: one call's destination must resolve statically to
  `https://api.github.com` and the other's to `https://keys.openpgp.org`,
  so two fetches to the same permitted host fail the build rather than
  sharing a budget. Exactly two `https://` origin literals, and they are
  those two; each appears in exactly one built file in the whole output,
  and that file is `background.js`; and `background.js` has no module
  imports, so worker code cannot be hiding in a chunk shared with the
  panel.
- **panel and welcome bundles** — no `fetch` beyond the two wasm loaders,
  no XHR / WebSocket / EventSource / RTCPeerConnection / sendBeacon /
  `new Worker` / `new Function` / `eval` at all, and no absolute URL
  literal outside a pinned set of XML namespaces and href targets.
- **content script** (`content-scripts/gmail.js`, the Gmail add-on, §17)
  — exactly one `fetch` call site, the attachment fetch: a same-origin GET
  as the page (init pinned exactly), made only when the panel asks for a
  chip the user pressed, whose destination is Gmail's own `download_url`
  re-checked at runtime to be this origin under `/mail/`. No reference to
  any other network primitive, and no absolute URL literal but the SVG
  namespace its icons are built in.
- **manifest** — `connect-src` exactly as written above (not a substring
  match), no `host_permissions`, `optional_host_permissions` exactly
  `["https://mail.google.com/*"]`, `web_accessible_resources` exactly the
  reader frame page framable by that one pattern, `scripting` the only
  addition to the permission set, and the meta tag present in the built
  HTML of the panel, the reader tab and the frame.

Counts are exact, not upper bounds, so deleting a guard fails as loudly
as adding a leak. Both directions were confirmed with negative controls:
planting `https://evil.tld/x` in a panel component fails the build, and a
second `fetch` in the worker fails it twice over (count mismatch plus an
unpinned call site).

**What the audit does not prove.** Two things, and neither is small. It
reads the built bundles, so a URL assembled at runtime from fragments
never appears as a literal and is invisible to it — the URL checks are a
change detector, not a proof, and the runtime layers are what actually
stop a request. And the panel is **not** free of network primitives: the
wasm loader is a real `fetch`, and the lockdown reads `globalThis.fetch`
in order to replace it. The defensible claim is the narrower one the
audit actually makes: **the side-panel bundle contains no code that can
name a remote destination.**

### 7.1 The keyserver lookup, in detail

The GitHub lookup's own mechanics are in §13.1, next to the age engine it
feeds. This one produces an OpenPGP certificate, so it lives here.

**One preference gates both lookups.** `keyDiscoveryEnabled` (default
on; off in the "If this leaks, I'm in trouble" preset) is what decides
whether the import step renders the field that starts a lookup. Off, no
code path in the app issues either request. What it is **not** is a
capability revocation: a manifest is static, so the `connect-src` entries
remain, and code injected into the panel realm under §8.10's precondition
could still send the worker a lookup message. The preference removes the
feature, not the permission. It is one switch rather than
two because it gates one capability — the panel asking a third party who
someone is — and a user who does not want that does not want half of it.

**The query never becomes an arbitrary path.** `lib/keyserver/query.ts`
holds no `https://keys.openpgp.org` literal at all — it is handed the
origin — and admits exactly three shapes: a conservative address grammar,
40 hex characters, or 16 hex characters (each accepting an `0x` prefix
and GnuPG's grouping spaces, which are stripped). None admits `/`, `?`,
`#`, `\`, `:` or whitespace. The value is then **percent-encoded** rather
than interpolated — a legal `%` or `+` in a local part is data, not
syntax — and the URL is built with `new URL()` and its origin, pathname,
search, hash, username and password each re-asserted before the request
is issued. Without all of that, "look up a key" is an arbitrary-GET
primitive against keys.openpgp.org driven by the untrusted side of the
message boundary.

**The query is canonical, and the worker re-derives it.** An address is
lowercased and a fingerprint uppercased before the request, so the same
person looked up twice is one contact rather than two. The panel sends
the canonical form and the worker re-parses it and compares — a value the
panel merely _claims_ is canonical is refused, because the URL builder
interpolates what it is given.

**Redirects are refused.** `redirect: "error"`. A redirect is a
server-chosen destination, and the whole point of the URL builder is that
the destination is ours; following one would let the endpoint hand the
lookup — and the identity in its path — to any origin it liked, with the
`connect-src` entry as the only thing left saying no.

**The worker is a transport that shape-checks; the engine decides.** It
bounds the body before it is in memory: a 15-second deadline, a
`Content-Length` pre-check that cancels without reading a byte, and a
reader loop that stops at 128 KiB measured in **bytes**, not UTF-16 code
units. (That loop is `lib/net/capped-body.ts` and is shared with the
GitHub lookup — one copy, because a second hand-rolled bounded reader is
free to drift from the one this document quotes, and the drift would be
silent.) It requires `application/pgp-keys`, then extracts only the text
between a matched BEGIN/END **public** key armor pair. A private key
block cannot match, so the endpoint has no way to hand this app
secret-shaped material to classify. Extra blocks are counted and
surfaced, never silently truncated. Tagged result codes cross the message
boundary, never prose the service wrote — which matters more here than
for GitHub, whose 404 is JSON: this endpoint's 404 body is `text/html`
quoting the query back at you.

The armor is then re-parsed by `prepareImport` in the panel, the
identical wasm path a pasted certificate takes. **A key that reaches
storage has been through wasm, whatever its source.**
`T-KEYSERVER-UNTRUSTED-PARSE`.

**What none of that establishes is that the key is the right one.** See
`T-KEYSERVER-KEY-SUBSTITUTION`, and note in particular that the service's
email verification proves **mailbox control at upload time, not
identity**. A by-fingerprint lookup is the one path here that is
self-verifying, because the query is the check.

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

That check is scoped **structurally**, to every `#[wasm_bindgen]`
export, not to a naming convention. It began as a `_with_password` /
`_with_prf` suffix match, which silently covered nothing for exports
outside that convention — `sshPrivateKeyFormatRejection`, which takes a
complete unencrypted private key file, was gated by no invariant at all
until the scope was widened. A name-shaped allowlist rots; the set of
wasm exports does not. The parameter-name list it matches on is still a
list (`password`, `passphrase`, `source_passphrase`, `prf_output`,
`stored_secret`, `key_file`, `plaintext`), so an export whose secret
param is named something else — `secret`, `pin`, `recovery_code` —
still passes vacuously. The summary line prints which names it matched
on, and which listed names it never saw, so a dead entry is visible;
that makes the gap legible, it does not close it.

> Previously `unlock_with_password`, `unlock_with_prf` and
> `init_contacts_session_with_prf` took `&[u8]` and scrubbed only the
> derived AES key, leaving the raw password / PRF bytes in a freed
> allocation — on the app's three most frequently exercised secret entry
> points. Fixed by taking them by value (`T-UNLOCK-PARAM-NOT-OWNED`).
> Note the residual limit: an inner copy made _by_ wasm-bindgen before
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
  (`components/workspace/output-name.ts`). The _contents_ are
  ciphertext; the _filename_ is not. Once saved it is cleartext in the
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

### 8.9a Password-encrypted messages are weaker than key-encrypted ones

`gpg --symmetric` messages are both **readable and writable** here. An
earlier version of this section said the capability was read-only, and
that the app therefore never chose an S2K cost or a cipher on anyone's
behalf. Encryption shipped afterwards, so here is what it actually picks:

- **Cipher: AES-256**, pinned explicitly rather than inherited from
  Sequoia's `Default` — a default that changes underneath us is a cipher
  change nobody reviewed.
- **S2K: SHA-256, iterated, count `0x3e00000`.** That is the _largest
  count the OpenPGP wire format can represent_ (~354ms to derive on a
  moderate CPU). There is no stronger value to choose, which is what
  made this comfortable to ship: the app takes the format's maximum
  rather than picking a number. Asserted by a test that reads the SKESK
  packet back, not left to a dependency's default.
- **Minimum password length: 8**, the same floor the vault's own
  `validatePassword` applies. A message password guards a file that can
  be attacked offline forever, so it has no business being weaker than
  the one guarding the keyring.

The password is **additive**: it adds an SKESK alongside whatever PKESKs
the message already had, and either opens it. It is a badge next to the
recipient list, not a mode that replaces it — and it does not touch
"Also encrypt to me". A message with neither recipients nor a password is
refused in the engine, because that is a valid OpenPGP message nothing
can decrypt and producing one would look like success.

What it is not: there is no identity, no key, and no forward secrecy. A
public-key message is readable by the holder of a private key that never
travelled; a symmetric message is readable by anyone holding a shared
secret that necessarily **did** travel, over a channel this app has no
view of — and can be read again later from a kept copy, because nothing
about the message expires. The only work factor between a captured
message and an offline dictionary attack is the S2K iteration count the
**sender** baked in; we read that parameter and cannot raise it.

A signature on such a message is still worth what a signature is worth: it is verified on this path exactly as on the
key path, and it is the one authenticity claim available. It comes from
the signature, never from the password. `T-SYMMETRIC-MESSAGE-PASSWORD`.

One format is refused outright: GnuPG's `--force-ocb` writes the
pre-RFC-9580 AED packet, which Sequoia's policy rejects. That is checked
**before** the password is used and reported as a format problem, because
telling a user with a correct password to go and check their password is
a loop with no exit. `T-SYMMETRIC-UNREADABLE-FORMAT`.

### 8.9 The deliberate trapdoor

A user social-engineered into typing `EXPORT` (see §2) and pasting
the result into an attacker-controlled chat leaks their key.
Unfixable in software given the feature exists.

### 8.10 Malicious code executing in the side-panel realm

A compromised UI dependency is **not** defended against.

**Calibration first, because the rest of this section is detailed and that
can read as alarm.** This is a statement about _consequence_, not
likelihood. It is downstream of §8.8: an attacker must first get code into
the side-panel realm, which means compromising a dependency, our build, or
the Web Store account. We already accept that risk there. §8.10 exists to
say honestly what it would cost us if it happened, rather than to claim a
new or probable attack.

The preconditions are not trivial. The extension ships seven runtime
dependencies plus transitives, runs no content scripts unless the user
turns on the Gmail add-on (§17, which carries no keys or wasm), loads no remote
code, and the CSP forbids fetching any. So the realistic path is a
poisoned package or a poisoned release, not something a website or another
tab can reach.

What makes it worth writing down anyway is that §1's WASM-isolation
guarantee is easy to over-read — someone could reasonably assume the
sandbox protects keys from in-panel JS in general, and it does not.

What _is_ opaque to such code: WASM linear memory (no in-page API
enumerates a `WebAssembly.Memory` it doesn't already hold — reading ours
needs a debugger capability like CDP `queryObjects`), and the React tree,
which carries only public metadata plus opaque `u32` handles.

What is **not** opaque is the module's _export table_. The wasm-bindgen
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
  even a perfectly gated export path leaks when the _user_ legitimately
  exports.
- `Crypto.prototype.getRandomValues` — the WASM module's only entropy
  source. A hook returning constants makes every subsequently generated
  key predictable. `getrandom`'s wasm backend caches the `Crypto`
  **object** and looks the method up on that instance per call, so the
  own slot on `globalThis.crypto` is pinned as well as the prototype.
- `navigator.clipboard.writeText` — read at write time, so the 30s/60s
  auto-clear (a defence against clipboard _managers_) does not apply.

Two layers are needed for these, and they block different routes: freezing
the prototype defeats plain assignment (`[[Set]]` walks the prototype chain
and refuses when it finds a non-writable data property there), while only
pinning the instance's own slot defeats `Object.defineProperty`, which
skips that check. `hostile-dep.spec.ts` probes both separately — a single
probe reported "blocked" while the `defineProperty` route was still open.

What _does_ still apply: the size of the unlocked window (§6 — no handle
survives a lock, so the attack window is exactly the unlocked window,
which makes auto-lock load-bearing security rather than convenience) and
the network lockdown (§7 — exfiltration still has to leave the process).

The honest general statement: you cannot defend against arbitrary JS in
your own realm using in-realm mechanisms. Freezing the primitives above
and shrinking the unlocked window raise an attacker's cost; only moving
the engine into a separate realm would change the structure.

**We considered moving the engine into a Worker and decided against it.**
This is a deliberate decision, not an oversight, so it should not be
silently reopened:

- A Worker alone does **not** stop a compromised panel dependency. It can
  post messages to the Worker as easily as it can call the exports today.
  Relocating the engine relocates the code, not the authority.
- It only pays off combined with gating the two export paths on a proof
  the panel realm cannot forge — e.g. a challenge minted inside WASM and
  satisfied by a fresh WebAuthn assertion verified inside WASM. That turns
  silent exfiltration into exfiltration the user sees a passkey prompt
  for, which is the real property on offer.
- But that gate is a **protocol we would have to design ourselves.** This
  project's rule is that every algorithm it relies on is one designed and
  reviewed by someone else; we do not invent constructions. That rules the
  gate out, and without the gate the rewrite buys close to nothing.
- The cost is not small: every `wasm-secrets.ts` call becomes async over
  `postMessage`, `Uint8Array` transfers need care not to create fresh
  un-zeroized copies, and the CDP-based `wasm-memory.ts` harness that
  several of our strongest tests depend on would need rebuilding.

**We also considered requiring re-authentication for the export paths**
(the PGP export rides the live session handle; the CRX path already opens
a transient handle from the password/passkey). Rejected, and the reason
generalises:

- A user who sees a passkey prompt inside a PGP tool will approve it. That
  is not user error — prompts in context get approved, and an attacker
  chooses the context.
- Worse, an in-realm attacker **owns the UI**, so it can fabricate a
  convincing prompt whenever it likes. For a password vault it can simply
  phish the password. Re-authentication through an interface the attacker
  controls is not authentication.
- The only unforgeable element is the OS passkey dialog chrome, and that is
  precisely the element habituation defeats.

What remains is that the attacker must be interactive rather than
passively harvesting, and cannot exfiltrate while the user is away — and
auto-lock already covers the unattended case. Not worth the friction.

So the limit stated above is the posture, not a temporary state. The
effort goes instead to the two levers that need no new design and route
around no user decision: shrinking the unlocked window (§6 — no handle
survives a lock, so the attack window _is_ the unlocked window, which
makes auto-lock load-bearing security rather than convenience), and the
supply-chain precondition itself (§8.8), since that is the actual cause
rather than the symptom. The primitive freeze above and the network
lockdown (§7) raise cost within the window.

Pinned by `e2e/hostile-dep.spec.ts`, which asserts both the gaps and the
two genuine wins (linear memory and React state stay opaque).

### 8.11 Composer and output plaintext across a lock (fixed)

Unlike the rest of §8, this was **not** an accepted boundary — it was a
defect. It is recorded in full because the diagnosis is the useful part:
the first fix attempt was wrong in an instructive way.

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
`inputVersion`) enter state. `doMasterLock` _pulls_ the draft via
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

**Also fixed: decrypted output.** `s.output` was ordinary render state and
was retained by the identical mechanism (measured count 1 after a real
encrypt→decrypt→lock cycle). It now lives in `outputRef` plus the result
`<pre>`'s `textContent`, with only the boolean `hasOutput` derived into
state; `wipe()` clears both. The display node is written imperatively
through a callback ref rather than as a React child — rendering
`{output}` as JSX would put the string straight back into the fiber's
element tree, which is the whole thing being avoided. The `<pre>` was
kept rather than swapped for a textarea, so the existing wrapping and
select-all behaviour are untouched.

**And the other two output slots, which could not be fixed that way.**
`binaryOutput` (a `Uint8Array`) and `fileResults` (a `FileResult[]`) are
also decrypted content, and the paragraph above describes a remedy that
is unavailable to them: the results card renders a row per file, so they
_must_ stay in render state, and they are retained past unmount by the
same `fiber.alternate` chain. Dropping them at lock time does not work
either — `resetOutput()` is a `setState` pair, and on the lock path that
is batched with the unmount and never commits, leaving the previous
fiber's `lastRenderedState` holding the same buffer. So `wipePlaintext`
**zeroes those buffers in place** rather than releasing references.
Measured with the wipe removed: 8 retainers for the binary branch, named
`binaryOutput` / `memoizedState` / `baseState` / `lastRenderedState`, and
one per file via `FileResult.data` for the multi-file branch. Guarded by
two tests in `e2e/draft-memory.spec.ts`.

**Measurement note, and read this before writing the next one.** The
snapshot helpers in `e2e/heap.ts` search the heap snapshot's STRING
table, so they cannot see bytes at all — V8 records string values there,
and a typed array is a node with a size and no contents. A canary held
in a `Uint8Array` returns zero from them forever, which looks exactly
like a pass. `Runtime.queryObjects` is not the way out either: V8's
filter skips typed arrays, so `Uint8Array.prototype` yields an empty
array (verified against a blank page: `Object.prototype` → 1104 objects,
`Uint8Array.prototype` → 0). The byte-level scanner in
`draft-memory.spec.ts` therefore queries plain objects and inspects what
they point at, which works precisely because the retainers here ARE
object literals — React's hook records and each `FileResult`. Any future
"absent from the heap" test for non-string material needs that approach
and a non-zero pre-condition measurement, or it will ship a vacuous
zero.

Guarded by a third test in `e2e/draft-memory.spec.ts`, validated against a
deliberate negative control: with an effect closing over the output the
count is 1 via `alternate → updateQueue.lastEffect.create → … →
lastRenderedState`; without it, 0 on both the retainer walk and the plain
heap scan — absent from the snapshot entirely, not merely weakly held.

Note this is distinct from §8.5's accepted "plaintext is observable in
the rendered UI." That accepts plaintext being visible _while composing_.
This is plaintext persisting _after_ the lock, when nothing is rendered.

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
- **Identity binding.** The AAD only covers the extension id _string_, not
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
  _unlocks_ each key and _re-seals_ it under the single export passphrase so
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

Opt-in, off by default. Records what the user _produces_ (encrypt/sign),
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
about a slot. It is the _key_, not the storage area, so a `local`↔`sync`
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
> _from_ the contacts session key, so it inherits that key's lifetime
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
  viewer. Because adoption only happens for segments it _actually
  decrypted_, this is a rigorous demonstration that the AEAD accepts a
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
references to the _actual_ buffers that crossed the wasm boundary and
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

---

## 12. Randomness

All randomness inside WASM ultimately comes from one place:
`crypto.getRandomValues`. On `wasm32-unknown-unknown` the `getrandom`
crate has no other source, so there is no independent entropy in the
sandbox. That is the fixed constraint everything below works within.

**A ChaCha20 CSPRNG sits between us and that source** (`gpg-wasm/src/rng.rs`,
`rand_chacha`). It is seeded once with 32 bytes from the platform RNG and
**never reseeded** — reseeding means re-reading the source we distrust, and
would let a later poisoning replace good state with attacker-chosen state.
`getrandom` is called in exactly one place in the crate.

It backs: AES-256-GCM nonces (every protected blob, every draft, every
`encrypt_store`), Argon2id salts on the PGP, CRX and SSH paths, the draft
session key, CRX RSA-2048 key generation, and the probe plaintext
`age.rs` uses to prove an unlocked SSH identity matches its fingerprint
(§13).

**What this defends:** a platform RNG that is poisoned _after_ our first
draw, or that returns constant/degenerate output. The important case is
AES-GCM nonce reuse under a fixed key — that leaks the keystream and the
GHASH key across every blob we have ever written, so it is worth ruling
out even under an unlikely precondition.

**What it does not defend, stated plainly:**

- Poisoning that lands **before** the first draw. The attacker then knows
  the seed and therefore the entire stream, and this construction buys
  nothing. `rng.rs` carries a test (`a_known_seed_still_yields_a_known_stream`)
  asserting exactly this, so the suite cannot be misread as a claim of
  unpredictability.
- **OpenPGP key generation** — the primary asset — is not covered at all.
  Sequoia's `CertBuilder::generate` takes no RNG parameter and its
  `crypto-rust` backend hard-codes `OsRng`, both via `Backend::random()`
  and in per-algorithm paths (X25519, Ed25519, RSA, the PQC algorithms).
  There is no trait object, thread-local hook, or feature flag to
  intercept. Overriding it would require forking or patching Sequoia,
  which we deliberately have not done.
- **age's own randomness** (§13) is not covered either, and for the same
  structural reason. `age::Encryptor::with_recipients` draws the file key
  (`new_file_key()`) and the payload nonce (`Nonce::random()`), and
  `age::ssh::Recipient`'s `wrap_file_key` draws the ephemeral X25519
  secret (`ssh-ed25519`) and the RSA-OAEP randomness (`ssh-rsa`). All of
  them construct their own `rand::rngs::OsRng` and take no RNG argument,
  so there is no injection point short of patching the dependency. On
  `wasm32-unknown-unknown` those draws resolve `crypto.getRandomValues`
  per call and are exposed to §8.10 in full. What `age.rs` _does_ control
  — the Argon2id salt and AES-GCM nonce of the at-rest envelope, and the
  identity-validation probe — goes through this CSPRNG.
  `T-AGE-RNG-UNHOOKABLE`.

No jitter, allocation-address, or timing-based entropy sources were added.
Combining entropy sources is a design activity, and this project's rule is
that it relies only on constructions designed and reviewed elsewhere — so
the CSPRNG is used exactly as its authors intended and nothing is mixed.

This narrows one window. It is not a fix for `T-ENTROPY-POISON`, which
remains gated on the same supply-chain precondition as §8.10.

---

## 13. age encryption to SSH keys

A second, non-OpenPGP crypto engine: encrypt and decrypt files in the
[age](https://age-encryption.org/) format using an SSH key the user
already has. All of it lives in `apps/pgp/gpg-wasm/src/age.rs`.

**Scope, deliberately narrow.**

- **Import only.** There is no `generate*` export in `age.rs`. The app
  never creates an SSH key; `ssh-keygen` does.
- **Encrypt and decrypt only.** age has no signing operation, so there is
  nothing sign-shaped to expose. Signatures remain OpenPGP-only.
- **SSH keys only.** Native age keys (`age1…` recipients,
  `AGE-SECRET-KEY-1…` identities) are not implemented. The seams are
  marked as extension points in the source.
- **`ssh-ed25519` and `ssh-rsa` only.** ECDSA, DSA (`ssh-dss`) and FIDO
  `sk-*` keys are rejected at parse time, each with its own message
  naming why. `ssh-rsa` is accepted between 2048 and 4096 bits — the
  upper bound is `rsa::RsaPublicKey::MAX_SIZE` in Rust age, which Go age
  does not share, so a file encrypted elsewhere to a larger key (GitLab
  hands out 8192-bit keys) cannot be decrypted here. That is surfaced as
  its own message, not a generic parse error.

**At rest.** Identical scheme to the PGP and CRX keys, through the same
shared envelope (`protected::seal_with_*` / `open_*`, §5): Argon2id or
WebAuthn-PRF → AES-256-GCM. The AAD prefixes are
`gpg-tools:ssh-password:` and `gpg-tools:ssh-passkey:`, and the HKDF info
string for the PRF path is `gpg-tools-ssh-prf-v1` — all three distinct
from, and not a string-prefix of, the PGP, CRX and store equivalents, so
the same authenticator and PRF output cannot derive the same AES key for
two key types and no `(prefix, identity)` pair can collide across types.
`lib/protection/aad-prefixes.test.ts` asserts both properties against the
Rust literals.

**The source passphrase is stripped at import.** age 0.12 exposes no way
to unwrap a passphrase-protected SSH key into reusable material — the
unencrypted type is `pub(crate)`, and the only public path
(`Identity::with_callbacks`) needs a synchronous `request_passphrase`,
which a browser cannot provide. So the RustCrypto `ssh-key` crate
decrypts the OpenSSH file with the user's passphrase and re-emits it
**unencrypted**, and those bytes are what gets sealed. Stated plainly,
because it is the security-relevant consequence: **after import, the
user's original SSH passphrase protects nothing here.** The vault
password or passkey is the only thing between an attacker holding the
blob and the key. This is the same trade the OpenPGP path makes, and the
source passphrase is zeroized the moment it has been used (§5).

**Key isolation.** The normalized key lives in a separate `SSH_KEY_STORE`
behind a `u32` handle (§4), populated only by `unlockSshIdentityWith*`.
No export in this module returns private key material to JS; the only
secret that crosses the boundary is the decrypted message, which is the
point of the call.

This is measured, not only read off the code. `e2e/ssh-memory.spec.ts`
finds a slice of the ed25519 **seed** in linear memory while an identity
is unlocked (password and passkey alike) and finds it gone after a
per-key lock, after a master lock, and after a passkey ceremony that
completes _behind_ a lock screen — each absence paired with a moment the
same needle is present, so none of them can pass vacuously. The JS heap
holds the key only where the import UI necessarily does: the file the
user supplied crosses as an immutable `String` in `ImportKeyPage`'s ref
(§5), and the spec pins it there and then shows it gone once the import
finishes. What that evidence does _not_ reach — ed25519 only, no
passphrase-protected source file, no `ssh-rsa`, and nothing about the
transient copies `age` makes while decrypting — is stated in
`T-SSH-KEY-MEMORY` rather than glossed here.

**Identity binding.** The AAD covers the key's SSH SHA-256 fingerprint —
a _public_ string — so binding to it proves nothing on its own, exactly
as with the CRX extension id (§10). Two checks close that on unlock,
inside `HandleStore::insert_validated`, before the key is reachable:

1. the public blob carried inside the decrypted OpenSSH key must hash to
   the bound fingerprint (identity → public key); and
2. a live round-trip — encrypt a random probe to the recipient derived
   from that public blob, then decrypt it with the identity (public key →
   private key).

Check 1 alone would accept a file whose cleartext public section was
copied from the victim; check 2 alone would accept a self-consistent
foreign key. A payload failing either is dropped, and so zeroized, rather
than stored.

**Randomness.** The envelope's Argon2id salt and AES-GCM nonce, and the
validation probe, all come from the crate CSPRNG. age's _own_ draws — the
file key, the payload nonce, the ephemeral X25519 secret, the RSA-OAEP
randomness — construct their own `OsRng` and take no RNG argument, so
they bypass it entirely and remain exposed to §8.10 in full. See §12 and
`T-AGE-RNG-UNHOOKABLE`. This is an unclosable gap given the dependency,
recorded rather than papered over.

**Recipients are not anonymous.** An age file encrypted to an SSH key
carries a short identifier of that public key in its stanza, so the file
is linkable to the key. Upstream is explicit about it; `age/src/ssh.rs`:

> these recipient types are not anonymous: the encrypted message will
> include a short 32-bit ID of the public key

and the `age` man page:

> This feature employs more complex cryptography, and should only be used
> when a native key is not available for the recipient. Note that SSH
> keys might not be protected long-term by the recipient, since they are
> revokable when used only for authentication.

Both halves matter: the file leaks _who it is for_ to anyone who holds it
and a candidate public key (and SSH public keys are routinely published —
`https://github.com/<user>.keys`), and the recipient's long-term custody
of an authentication key is weaker than that of an encryption key.
`T-AGE-SSH-STANZA-LINKABLE`; related in kind to §8.5's filename metadata,
but here the leak is inside the ciphertext and survives renaming.

**Cross-tool compatibility is the only specification.** The `ssh-rsa` and
`ssh-ed25519` stanza types are **not** in the C2SP age spec — they are a
convention shared by Go age and Rust age. `age.rs`'s test module
therefore pins vectors in both directions: ciphertexts produced by the
real Go `age` CLI (v1.2.1) that we must decrypt, and a live check that
the CLI decrypts ours when it is installed.

**No plaintext export path.** The OpenPGP trapdoor of §2 / §8.9
(`getKeyArmored`) has no SSH sibling: no export in `age.rs` returns
private key material, and `lib/age/` has no plaintext-export flow. An
imported SSH key leaves this app only as ciphertext the app itself
produced. That removes one route, not the class — §8.10 still applies,
since in-realm code that can call `unlockSshIdentityWith*` can decrypt
with the resulting handle for as long as it is held.

### 13.1 Getting someone else's public key

Two ways in, and they converge immediately.

- **Paste.** The user pastes an `ssh-ed25519 …` or `ssh-rsa …` line.
  Fully offline, no network, no third party. This is the original path
  and it stays first-class.
- **GitHub lookup.** The user types a GitHub username and presses a
  button; the background service worker does one
  `GET https://api.github.com/users/<u>/keys` (§7) and returns the key
  strings. GitHub already strips comments and email addresses from that
  response, so the strings carry no identity beyond the account name the
  user typed.

**The username never becomes an arbitrary path.** `lib/github/username.ts`
holds no `https://api.github.com` literal at all — it is handed the origin
— and admits only GitHub's own account-name grammar (alphanumerics and
single interior hyphens, ≤39 chars: no `/`, `.`, `%`, `?`, `#`, `@`, `\`
or whitespace). The URL is then built with `new URL()` and the origin,
pathname, search, hash, username and password are each re-asserted before
the request is issued. Belt and braces on purpose: without it, "fetch a
user's SSH keys" is an arbitrary-GET primitive against api.github.com
driven by the untrusted side of the message boundary.

**Redirects are refused.** The request sets `redirect: "error"`. GitHub
301-redirects renamed accounts, and following one silently would import
the keys of whoever holds that name _now_ under the name the user typed —
exactly the confusion this feature must not create. A rename surfaces as
an error the user resolves, not a silent substitution.

**The worker is a transport that shape-checks; the engine decides.** The
worker bounds the response before it is in memory, not merely before it
is parsed: a 15-second request deadline, a `Content-Length` pre-check
that cancels without reading a byte, and a reader loop that stops at
64 KiB — measured in BYTES, not UTF-16 code units, so a body of astral
characters cannot reach three times the stated cap. Then 20 keys and
4096 characters per key string. It requires a JSON content type, runs
`JSON.parse` and nothing else — no eval, no dynamic import — takes
`entry.key` when it is a non-empty string, ignores every other field,
and returns tagged result codes rather than any prose GitHub wrote.

The worker does **not** filter by key type, and that is deliberate: it
forwards any `<algorithm> AAAA<base64>`-shaped line and lets the engine
refuse what it cannot use. It briefly did filter, and the consequence is
worth recording — an account whose only key was ECDSA was reported as
having published no SSH keys at all, which was false and sent the user
to fix something that was not broken. Anything held back by a cap is
counted and surfaced as a refusal rather than dropped silently, because
the preview tells the user their message goes to every key listed. It never concludes that a
string is a key. Every string is re-parsed by `parseSshRecipient` in the
panel, the identical wasm path a pasted line takes, and a string the
engine refuses shows up as a rejected row with the engine's own message.
**A key that reaches storage has been through wasm, whatever its source.**
`T-GITHUB-UNTRUSTED-PARSE`.

**What none of that establishes is that the key is the right one.**
`/users/<u>/keys` is an assertion by GitHub. There is no transparency
log, no signature over the response, no certificate pinning. GitHub,
anyone who compromises the target's account, or anyone who can mint a
certificate for `api.github.com` can substitute a key the user will then
encrypt to — cleanly, with no error and nothing to see. The import
preview shows every fingerprint before storing, which **only helps a user
who already knows the real one**; for the common case of looking someone
up precisely because you don't have their key, it is a number with
nothing to compare it against and must not be read as verification. The
contact records a `source` so the UI can distinguish "GitHub said so"
from "I verified this myself" — that is a provenance label, and the app
deliberately ships **no affordance to record an out-of-band
verification**, because a half-built one that shows a tick for something
nobody checked would be worse than the honest label.
`T-GITHUB-KEY-SUBSTITUTION`.

**And the lookup itself is a disclosure.** It tells GitHub which username
you are about to encrypt to, from your IP, at that moment, before the
message exists. That is the feature working, not a bug in it, and nothing
mitigates it. See §7 for exactly what the request does and does not
carry. If that matters to you, paste.

**Scope of this section.** It documents the Rust engine and the trust
boundary around it. The JS side (`lib/age/`) carries recipient lines and
opaque handles only, and is described here no further than that.

---

## 14. Unlock keys with the vault (`unlockKeysOnOpen`)

Off by default. When on, and the master protection is a passkey, the
one WebAuthn ceremony that opens the vault also opens every key
**sealed under the master's credential and PRF salt**, with no per-key
prompt. Nothing else changes: every lock trigger in §6 still drops
every handle, and the at-rest format is untouched.

**Why it works without new crypto.** A PRF-sealed blob is
`AES-GCM(HKDF(prfOutput, storedSecret), cert, aad=fingerprint)`. Two
blobs sealed under the same `(credentialId, prfSalt)` share
`prfOutput` but not `storedSecret`, so they have distinct AES keys and
distinct AAD. Onboarding's first key has always been sealed this way
(`prfReuse`); the feature extends that to any key the user chooses.

**Eligibility is exact** (`lib/protection/vault-unlock.ts`,
`isSealedUnderMaster`): credential _and_ salt must match. A key on its
own salt (every single-key import before this feature), on a different
passkey, or on a password is skipped and keeps its own prompt.

**There is no migration step.** A key on the master credential but
its own salt cannot be opened by the master's output (one salt's PRF
says nothing about another's), and the keyring where those salts live
is only readable after the master ceremony -- so nothing can be done
at vault-unlock time. What CAN be done is at the key's own prompt: the
PRF extension evaluates up to two salts per ceremony, so when the user
unlocks such a key the way they always have, `unlockWithPasskey` asks
for the master salt as the `second` evaluation, unlocks the key with
the first output, and re-seals it under the master with the second
(`needsMasterReseal`, `resealUnderMaster`, `replaceKeyProtection`) --
same prompt, zero extra interaction. From the next vault unlock on
that key opens with the vault. A key on a DIFFERENT passkey cannot be
carried this way (wrong authenticator secret) and a password key has
no ceremony at all; both simply keep their own prompt.
`reprotect_key_with_prf` / `reprotect_ssh_identity_with_prf` do the
re-seal from the live handle in wasm under a fresh stored secret; the
plaintext never crosses to JS and the handle is read rather than
consumed. Two guards on the write: wasm reports back the fingerprint the new blob's
AAD was derived from (from the key the HANDLE holds), and
`resealUnderMaster` refuses to proceed unless it equals the keyring
entry's id -- so a handle/id mix-up can never overwrite key X with
key Y's ciphertext; and the write goes through the store's `update`
(`replaceKeyProtection`), which swaps only the three sealing fields
under the store lock rather than putting back a stale snapshot. While the
option is on, new keys that reuse the master credential are sealed
under the master salt directly (`ProtectionInput.prfSalt`); while it is
off they get a random salt as before. Two honest caveats about "off":
onboarding's first key has always been master-sealed (`prfReuse`),
and a key re-sealed while the option was on STAYS master-sealed after
it is turned off -- off means the extension will not open them off the
vault ceremony, not that no such blob exists. The at-rest exposure is
the same either way (a vault dump without the authenticator opens
nothing); a user who wants per-key salts back re-imports the key.

**The unlock path.** `MasterUnlockScreen` loans its `prfOutput` to
`onUnlocked` for the duration of that call and `.fill(0)`s it in a
`finally`. That loan spans one settings read even when the option is
off (the preference is encrypted, so it cannot be known sooner); the
cost is one IndexedDB round trip of extra PRF lifetime, bounded and
accepted. App reads the preference (an encrypted setting, so readable
only once the session is live), reads the keyring, partitions it, and
hands the eligible blobs to `KeySessionStore.unlockMany` -- as a
LOADER, so the batch's lock generation is captured before the
preference and keyring reads, and a lock landing during either cancels
the batch. Each unlock then goes through the same generation-checked
funnel as a manual unlock, and the loop **stops** if a lock landed
since the batch started -- otherwise the iteration after a mid-batch
lock would begin under the new generation and insert a live key behind
the lock screen.

**What it costs**, recorded as T-VAULT-UNLOCK-OPENS-KEYS: an attacker
who can obtain one ceremony now gets the migrated keys as well as the
vault. That is the trade the option exists to make, and the reason it
is off by default, mutually exclusive with `neverCacheKeys`, pinned
off by the Paranoid preset, and never auto-prompted after a system
lock (§6).

It also widens what an open key does without a click: a message opened
from the context menu decrypts by itself when its key is already open
(§15), and this option is the usual way a key is open on first launch.

**Verified by:** `lib/protection/vault-unlock.test.ts` (eligibility,
re-seal blob shape), `hooks/useKeySession.test.ts` (a lock mid-batch
stops the batch), `gpg-wasm/src/tests.rs` and `age.rs` (re-seal round
trip, wrong material and wrong AAD both fail, handle survives), and
`e2e/unlock-on-open.spec.ts`, which asserts the virtual authenticator's
sign count rose by **exactly one** across an unlock that left the key
live.

## 15. Context-menu auto-run

A selection opened with "Open in PGP Tools" that classifies as decrypt
or verify runs without a click (`WorkspaceView`, the auto-run effect;
`useWorkspaceOperations.executeUnattended`). Verify always -- it needs
nothing secret. Decrypt **only when the key the message is addressed to
already has an open handle**; a locked key, a password-only message, or
no matching key falls back to the Decrypt button exactly as before.

**Unattended means no secret is asked for and nothing reaches disk.**
The flag is checked at the point of each prompt, not decided up front,
because a key can close (idle timer, OS lock, master lock) between the
auto-run's handle check and the decrypt: `ensureUnlocked` returns null
instead of starting a passkey ceremony or showing the password row, the
message-password prompt is skipped, and `maybeAutoDownload` does nothing
-- the "Auto-download text results" preference is for results the user
asked for, and this input is whatever a web page put in the selection.
History never records decrypts (§11), and translation only runs on a
click, so neither changes.

**Ordering.** The run waits while the vault is settling (`vaultSettling`:
contacts and keyring being read back, keys opening off the unlock
ceremony) so a verdict is not reached against an empty contact list. A
generation counter bumped by every unlock and every lock stops a stale
unlock from clearing that flag. The user editing the input, clearing it,
or changing mode cancels the run; waiting for the default key selection
to land is bounded at 2s.

**What it costs**, recorded as T-AUTORUN-UNATTENDED-DECRYPT: with a key
open, one right-click on attacker-chosen text puts its plaintext on
screen with no further confirmation. Nothing leaves the panel -- the page
cannot read it, and the download is suppressed -- so this is not an
oracle; the exposure is shoulder-surfing and heap residue (a decrypt
already running when a lock lands, the existing T-OUTPUT-HEAP-RESIDUE
window, is now more likely because nobody need be at the panel). With
`neverCacheKeys` on, handles are dropped after each operation, so
decrypt never qualifies.

**Verified by:** `e2e/context-menu-autorun.spec.ts` (runs when the key
is open; with it locked, no prompt and no plaintext until the click;
a verify delivered to a locked panel runs on unlock; first open off one passkey
ceremony with exactly one assertion; no download with auto-download on).

## 16. Reply: the reader tab

Reply, on a decrypted message from a verified signer, moves the message
into a **reader tab** (`reader.html#<nonce>`) and turns the panel into
the reply: empty, encrypt mode, addressed to the signer.

**The tab is a view, not a second app.** No vault, no keys, no wasm, no
storage and no network: it connects one runtime port named for its
128-bit nonce and writes whatever the panel sends into a `<pre>`'s
`textContent`, never into React state (`entrypoints/reader/Reader.tsx`,
`lib/reader-protocol.ts`). The signer is shown with the panel's own
read-only `ContactCard`, sent only the fields that card displays (no
public key, top-level or per-key `recipients`) and dropped from the
tab's state on lock with the text, since contact data is lock-protected
too. The card's pure record helpers live in
`lib/storage/contact-recipients.ts`, so the page's import graph contains
no store and no wasm.
The URL holds only the nonce; nothing about the message or its sender is
written to any storage area.

**The panel owns the message** (`hooks/useReaderTabs.ts`). It is sealed
under the in-WASM draft key the moment Reply is pressed, the workspace
output is wiped by the reset that follows, and it is unsealed only to
post it to every connected tab while the vault is open -- every tab, since
a duplicated reader connects with the same nonce. `doMasterLock` calls
`lockNow` first, synchronously, which posts `locked` to all of them and
stops any in-flight `show` from posting after it; unlocking sends the
message again. When the last tab for a message closes, the sealed bytes
are zeroed and dropped (also if opening the tab fails, and on panel
unmount). Closing or reloading the panel disconnects every port -- each
tab clears its text and closes itself -- and the draft key dies with the
page (nothing calls `dropDraftSession`; the WASM instance is torn down),
so nothing survives. Without a master password there is no master lock,
so nothing ever sends `locked` -- the same as the panel's own output view
in that setup.

**Measuring it.** The panel and its reader tabs run in one renderer
process, so a heap snapshot of either page covers both. The heap test
reads the reader's text in the page's own context rather than with
Playwright's `toHaveText`/`getByText` on the canary: those match text in
Playwright's injected context, which then holds it as its last RegExp
match (and caches it on the DOM node it inspected) -- retainers that are
the test's, not ours. The app-side counterpart of that mechanism is real,
though: every successful regex match records its subject in the realm,
and the app runs regexes over plaintext, so every wipe path also calls
`forgetLastRegExpMatch` (`lib/utils/regexp-residue.ts`). An unknown or forged nonce gets no answer and
the tab shows nothing. Recorded as T-READER-TAB-PLAINTEXT.

**Verified by:** `lib/reader-protocol.test.ts` and
`e2e/reply-tab.spec.ts` (reader shows the message and the panel becomes
the reply; Reply by shortcut and palette; no Reply without a verified
signer; lock clears the reader and nothing in either page's heap holds
the message, with a positive control while shown, and unlock restores
it; a duplicated reader is locked too; closing the panel closes the
reader tab; an unopened nonce shows nothing; no storage area holds the
canary).

## 17. The Gmail add-on

Settings → Gmail turns on an integration with mail.google.com: encrypted
and signed blocks in opened emails are read IN PLACE, in a reader frame
the add-on embeds where the block was; public keys and clipped blocks
get a banner (Import / View entire message); encrypted attachments get a
Decrypt button; and compose windows get a lock pill beside Send that,
when on, covers Gmail's text box and makes the side panel the composer,
with "Encrypt & send" putting the ciphertext in and pressing Gmail's
Send. It was designed
against the two established integrations (FlowCrypt, Mailvelope; notes
in `lib/gmail/dom.ts` and `entrypoints/gmail.content.ts`), keeping their
reach into Gmail and dropping what this extension's model cannot accept.

**Off by default, and the switch is the permission.** The only host
access the manifest can ever hold is the OPTIONAL
`https://mail.google.com/*`, requested from that Settings switch inside
the user's click. The content script is not in the manifest: WXT's
`registration: "runtime"` keeps it out, and the worker registers it with
`chrome.scripting` while the permission is held and unregisters it when it
is not (on every worker start and on `permissions.onAdded/onRemoved`). No
preference mirrors it, so revoking access in `chrome://extensions` turns
the add-on off with nothing left to disagree. There is no OAuth, no Gmail
API and no server: it works with what Gmail has already rendered.

**What the content script is.** No keys, no wasm, no storage, and one
network call (the attachment fetch below; the audit's `content` census is
exactly that one `fetch`, init pinned, and it cannot import
`network-lockdown.ts`, whose non-configurable hooks would throw on a
second injection). It reads armored text
out of message bodies with `innerText` (layout-aware, so armor keeps its
line breaks, unlike the context menu's `selectionText`), and the draft the
user typed into Gmail's own box. Its UI lives in CLOSED shadow roots built
with `createElementNS`/`textContent` only (Gmail enforces Trusted Types;
the test stand-in does too), shows only fixed locale copy, and ignores
untrusted (`isTrusted === false`) clicks.

**Reading in place: the frame.** A `PGP MESSAGE` or `PGP SIGNED MESSAGE`
block is not shown through a banner but through `gmail-frame.html`, an
extension page the content script embeds (an `<iframe>` in a closed
shadow host) where the block was rendered. The frame's document is
cross-origin to Gmail: the page can place and size it and that is all;
it cannot read into it, so plaintext may be shown there where it never
may be in Gmail's DOM. The frame is the one `web_accessible_resources`
entry, framable by the Gmail pattern and nothing else (pinned by the
audit, alongside the rule that the panel, reader tab and welcome page
are NOT web-accessible); it carries the panel's `connect-src 'self'`
meta CSP (also pinned); it refuses to run unless it is framed, by a
Gmail origin (`ancestorOrigins`); and it delegates no permissions (an
empty `allow`, so no WebAuthn in particular -- a passkey ceremony cannot
run in a frame Gmail embeds, and is not asked to). Like Reply's reader
tab (§16) it is a DUMB VIEW: no vault, keys, wasm or storage.

Two channels, both in `lib/gmail/frame-protocol.ts`. (1) Frame ↔ page by
`postMessage`: the content script hands the frame the armored block
(ciphertext the page already had) and the message's sampled colours; the
frame reports its height, its state and a "show original" toggle. Each
side checks `event.source` (the one window it expects), `event.origin`
(the extension origin / a manifest-derived Gmail origin) and the nonce
the frame was created with; Gmail's scripts can post the same shapes,
which is the accepted "the page chooses the ciphertext" case, and
nothing in this channel carries plaintext. (2) Frame ↔ panel by a runtime
port named for the nonce: the frame asks the panel to read the block; the
panel accepts the port only from our extension, at the frame page's URL
as Chrome reports it, inside a tab and not its top frame
(`isGmailFramePort`), and answers with the message or with why not.
Plaintext travels panel → frame over this port and nowhere else.

**The §15 rules, unchanged.** `useGmailFrames` decrypts for a frame
UNATTENDED: only when the key the message is addressed to already has an
open handle. A locked vault, a closed key, or a password-only message is
answered `locked` or `failed` -- never a ceremony, never a prompt, never
a write to disk. With `neverCacheKeys` on, a decrypt is never answered
at all (the hook is told, and treats every handle as closed), so a frame
cannot ride on a key the user opened for something else. Verify needs
no secret and runs whenever the vault is open (contacts are behind the
lock too). The plaintext exists in the panel only for the call
that posts it (not kept, not sealed, not in React state; the armor is
kept per port so an unlock can answer again). `doMasterLock` tells every
frame `locked` first and synchronously; an unlock, or any key opening
(`unlockedKeyIds`), answers the waiting frames again. A frame with no
panel to talk to (the port disconnects with nobody listening) waits for
the panel's `GMAIL_PANEL_READY` broadcast and reconnects.

**"Unlock to read".** When the frame is told `locked` it shows one
button. The click is a user gesture inside an extension page; it sends
`GMAIL_FRAME_OPEN` to the worker, which accepts it only from our own
extension at the frame page's URL inside a tab's subframe, derives the
action from the text (decrypt or verify only), opens the side panel
inside the gesture, re-checks the permission and writes the block to the
pending-op channel -- exactly a banner click's path. The panel then runs
the normal flow with its prompts (password row, passkey ceremony), and
when the key opens the frame fills in. So the open side panel is, by
construction, the "unlocked" indicator: keys live in it (§6), and closing
it clears every frame.

**What the frame costs**, recorded as T-GMAIL-FRAME: plaintext in a
second page's heap and on screen, the same class as the reader tab
(T-READER-TAB-PLAINTEXT) and the panel's own output box, in a page that
follows the panel's lock state rather than having its own. What the
page learns from the frame is ONE BIT -- showing the message or not --
plus, while showing, its height (so roughly how long the message is):
the frame reports no size and sits at one fixed height in every other
state, and its finer states (locked, no key, failed) never cross to the
page, because "locked for key K" versus "no key K" versus "shown" would
be an oracle for which keys the user holds and when the vault is open.
The page can hide, cover or remove the frame (costing the user the
convenience, not a secret), can lay a real button of its own over the
frame's "Unlock to read" so a trusted click lands on it (which opens the
panel on ciphertext of the page's choosing, with the normal prompts --
the banner's exposure), and can frame the page itself with such
ciphertext, which is T-AUTORUN-UNATTENDED-DECRYPT's accepted exposure
again (shoulder-surfing, not an oracle: the result stays in the frame).
The frame's theme is two CSS colours, validated as colours (hex, rgb(),
a name) so the value cannot name a host.

**Compose: the panel is the composer, Gmail keeps the envelope.** While
a compose window is ON, its body is hidden under a card (an attribute
the add-on's one stylesheet rule turns into `display: none`) and its
attach control is inert; To, Cc, Subject and Send stay Gmail's. The card
takes no input: it says the message is written in the side panel and
has one button that brings the panel up (`GMAIL_OPEN` with `focus`,
which opens the panel and writes nothing). Drops on a covered window
are stopped at the document, in the capture phase, before Gmail's own
handler could attach the file in the clear; the add-on's own synthetic
drops of encrypted files are let through under a flag that is set only
for the synchronous dispatch. "Encrypt & send" in the panel is
`GMAIL_INSERT` with `send`: the ciphertext goes in (same checks as
before), the cover comes off so Gmail shows what it will send, and
Gmail's Send is pressed as a pointer would; "sent" is the window going
away within four seconds, otherwise the panel tells the user to press
Send. A window turns itself ON when the thread on screen holds PGP (a
reader frame, an encrypted attachment or a clipped encrypted block) AND
a side panel answers `GMAIL_PANEL_PING` (a pong from an extension page;
the worker never answers, so no panel means no pong): it sends
`GMAIL_OPEN` with `silent`, which writes the op without trying to open
a panel (there is no gesture), and covers the box. The pill is the
switch either way. A `view=cm` tab the panel opened for "Add to Gmail"
is never armed: it is the panel's to fill. The reader frame's Reply
presses Gmail's own Reply control (`pgp-frame:reply`, nothing else
crosses) and the window that opens arms itself.

WHY INPUT NEVER GOES IN AN IN-PAGE FRAME. Showing plaintext in a frame
is safe because a swapped frame can only show something false; taking
input in one is not, because a swapped frame takes the real plaintext,
and nothing inside mail.google.com is a surface the user can trust by
looking at it -- Gmail's own scripts, or another extension holding the
same host permission, can replace any element. The side panel is
browser chrome: nothing in the page can draw over it or imitate it. So
the design never asks the user to type into the page; a text box
appearing where the card should be is itself the tell, and the panel's
own "Writing a Gmail draft to …" header (unspoofable) says which side is
real. A page that fakes the card or the pill costs the user the cover,
not a secret: text typed into a real Gmail box is Gmail's, which is
T-GMAIL-DRAFT-PLAINTEXT exactly as before.

**Gmail → panel.** A click sends `GMAIL_OPEN` to the worker, which drops
it unless it comes from our own extension, a tab's top frame, and an
origin derived from the manifest's optional host pattern (no Gmail
literal is in any bundle). The worker then DERIVES the action from the
text (`classifyAction`) and acts only on decrypt, verify or public-key
import; a compose request is always encrypt. `sidePanel.open` runs
synchronously inside the relayed gesture, the permission is re-checked,
and the text lands in the existing pending-op channel (T-PENDING-OP-AT-REST
applies unchanged). A decrypt then follows §15's unattended rules. The
worker's key-lookup messages now also refuse any sender that is not an
extension page.

**Panel → Gmail: ciphertext only, checked twice.** After encrypting for a
compose window, "Add to Gmail" sends `GMAIL_INSERT` with one armored
block. `isArmoredMessageOnly` (`lib/gmail/protocol.ts`) is run by the
panel before sending and by the content script before writing; it accepts
only a lone `PGP MESSAGE` block whose body is, line by line, at most four
allowlisted armor headers and radix-64, and whose FIRST PACKET is a
session-key packet (PKESK or SKESK). That last check is what rules out
plaintext in base64: a signed-only message (compressed, one-pass
signature) or a bare literal packet is armored as `PGP MESSAGE` too.
Shape is not proof of encryption, but no plaintext the panel can produce
passes. The content script accepts the message only from an extension
page (`sender.tab` unset) and writes it with `textContent`; the panel
sends it only while the permission is still held, and pinned to the
`documentId` the worker recorded for the Encrypt click (taken from
`sender.documentId`, never from the page), so a tab that navigated or
reloaded receives nothing. Decrypted text has no message type that could
carry it into Gmail. After a successful insert the panel resets, keeping
neither plaintext nor ciphertext.

**Files, both ways, ciphertext only.** An attachment chip whose name ends
in `.pgp`, `.gpg`, `.asc` or `.age` gets a Decrypt button. The click
sends `GMAIL_OPEN` with the chip's id (stamped on it by the click, like a
compose id) and name -- no bytes; the worker writes a `decrypt` pending op
carrying that ref (`gmailAttachment`, accepted only on an empty-text
decrypt). The panel then asks the tab for the bytes
(`GMAIL_FETCH_ATTACHMENT`, through the single `sendToGmailTab` site,
pinned to the click's `documentId`), and the content script fetches the
chip's `download_url` -- re-read from Gmail's attribute at fetch time
(name and URL both re-validated), refused unless the URL is this origin
under `/mail/`, capped at 25 MB before the body is read in full -- as
the page, with Gmail's own session, which is the only way to an
attachment without an API. This is the one network call in the content
bundle; the audit pins its count, its init (a plain `GET`,
`same-origin`, `no-store`, `redirect: "follow"`) and that its
destination resolves statically to no remote origin. Redirects ARE
followed, stated plainly: Gmail serves some attachments off a redirect
to another Google host, and the request URL is the only hop the content
script chooses. `same-origin` credentials mean no cookie goes on a
cross-origin hop, and whatever comes back is treated as what the page
could have handed over anyway -- attacker-chosen ciphertext, the
accepted case. The bytes reach the panel as base64 in the message
reply, are checked there as a `GmailFile` (name and base64 shape) like
any message from a tab, and are staged as a dropped file would be, then
run unattended under §15 (an armored `.asc` is routed by what it is: a
message, a signed message, or a public key → import; a PRIVATE key is
refused, as the worker refuses it from a banner). The panel cannot name
a chip the user did not press, and nothing is fetched on scan.

Outbound, encrypted files are handed to the draft as a user dropping them
would: `GMAIL_ATTACH` (or `GMAIL_FILL` with `files`) carries base64 bytes,
each checked by `isEncryptedFileBytes` -- binary OpenPGP whose FIRST
PACKET is a session-key packet, an armored `PGP MESSAGE` under the same
rule, or an age file by its magic -- in the panel before sending and
again in the content script before a `DataTransfer` of `File`s is
dropped on the compose body. Any file failing the check means NONE is
dropped. A signed-only file, a decrypt result or a zip is refused by
shape, the same discipline as `isArmoredMessageOnly`. Not yet verified
against live Gmail's drop handler (the stand-in's records what lands);
if Gmail ignores synthetic drops the fallback is Download.

**"Add to Gmail" with no draft.** With the add-on on, "Add to Gmail"
replaces Download for any encrypted text result, including one written
entirely in the panel (and "Attach to Gmail" for encrypted files). Without a draft to return to, the panel opens
Gmail's own compose URL (`/mail/?view=cm`, To line from the picked
contacts' addresses, built from the manifest's origin) in a new tab, and
sends `GMAIL_FILL` to that tab once it has loaded on Gmail's origin. The
body is NOT put in the URL (it would sit in history and can exceed what
Google's front end accepts). The content script writes it only into a
single compose window whose body is empty, waiting at most 15 seconds;
more than one compose window, or one with text in it, is refused rather
than guessed at. Same armor check, same single send path.

**Which draft, which people.** An empty Gmail draft joins what is in the
panel only in the Reply flow (Reply on a decrypted message, then Encrypt
on Gmail's reply window); anything else starts the panel clean, so a
half-written note to someone else cannot be carried into this draft.
Recipients are To and Cc only. **Bcc is never read**: every OpenPGP
message lists the key id of each recipient, so encrypting to a Bcc'd key
would show it to everyone on the To line. Gmail's Bcc row is skipped
wherever it is recognisable (`SEL.bccArea`); a Bcc chip Gmail marks some
other way would be read as To/Cc, which is why the strip shows every
address it took. The worker filters the addresses again before storing
them.

**"Search for key" is the existing lookup, on a click.** An address with
no key gets a button that opens the import page with that address typed
into the lookup and runs it: the same worker request to keys.openpgp.org
as typing it by hand (§7.1, T-KEYSERVER-LOOKUP-DISCLOSURE), one press per
address, and absent (replaced by "Add a key") when `keyDiscoveryEnabled`
is off. Nothing is looked up automatically when a draft opens. A key
imported while the draft is open is matched against its addresses and
selected; the warning is computed from the current selection, so it
always says who cannot read the message as it stands.

**Recipients go back to Gmail too.** A contact picked in the panel who is
not on the draft yet is added to its To line (`GMAIL_ADD_RECIPIENTS`):
the key's first address that passes `isEmailAddress`, typed into Gmail's
own To box so Gmail makes the chip. Addresses only, validated by the
panel and again by the content script, sent through the same single
panel send path as an insert (so the audit's pinned `tabs.sendMessage`
count did not change) with the same permission and `documentId` checks.
The user's own keys are never added, and removing a recipient in the
panel does not remove anyone from Gmail.

**Turning it off.** Revoking the permission only stops future injections,
so Settings first sends `GMAIL_TEARDOWN` to every open Gmail tab (while the
permission still lets it find them), and each running copy removes its UI
and stops answering. The worker also remembers the last known grant and
refuses a `GMAIL_OPEN` without opening the panel when it knows access is
off. A newer copy of the script takes over from an older one in the same
page.

**`scripting` is a channel, so it is pinned.** With the Gmail grant held,
`chrome.scripting.executeScript({world: "MAIN", func, args})` from any
extension realm would run code inside mail.google.com, outside the
panel's `connect-src` and the worker's pinned fetches. The network census
cannot see that, so `audit-network.mjs` pins the privileged calls
separately: exactly one `registerContentScripts` and one `executeScript`
in the worker, each with an exact literal options shape (`files` only; a
`func`, `world`, `args` or `css` key fails the build), none anywhere else,
and exactly two `tabs.sendMessage` sites in the panel (`sendToGmailTab`,
which insert, add-recipients, fill, attach and fetch-attachment all go
through, and teardown). A compromised dependency in the panel or worker realm (§8.10)
that used `scripting` would have to change these counts.

**What Gmail still sees, stated rather than hidden.** Gmail necessarily
sees what the add-on reads (it rendered it), the ciphertext and files it
writes, and the reader frame's size and state (never its contents).
If the user types into Gmail's own compose box before pressing Encrypt,
Gmail has that text and has probably saved it as a server-side draft; the
Settings page says so and the flow invites writing in the panel instead.
Compose ids and banners are visible to Gmail's scripts; neither carries
anything secret, and the insert path cannot be driven from the page.
Recorded as T-GMAIL-PAGE-BOUNDARY and T-GMAIL-DRAFT-PLAINTEXT.

**Not yet handled.** PGP/MIME (`encrypted.asc` wrapping a MIME body)
decrypts to raw MIME text in the panel; no MIME parsing is attempted.
Clipped messages get a
banner that opens Gmail's own "View entire message" page, where the add-on
runs again. The banner follows ONLY an anchor in Gmail's `.iX` footer,
never one inside the email body, and only to the current origin under
`/mail/` with `view=lg`, rebuilt from its parts; a hostile email cannot
make a PGP Tools-branded button open a page of its choosing. A verified
signature from a forwarded message shows its real signer, which may not
be the Gmail sender; the panel names the signer, not the sender.

**Verified by:** `lib/gmail/protocol.test.ts`, `lib/gmail/dom.test.ts`,
`lib/gmail/recipients.test.ts`, `lib/pending-op.test.ts`,
`scripts/audit-network.mjs` (content census, manifest pins), and
the privileged-API pins in the same audit, and
`e2e/gmail.spec.ts` (banner → panel decrypt with no plaintext anywhere in
Gmail's page; compose → draft + recipients into the panel → only
ciphertext back; a non-armor `GMAIL_INSERT` refused; a `GMAIL_OPEN` from a
non-Gmail sender refused with no pending op written). The e2e grants the
host permission at load, because Chrome's prompt cannot be driven
headless (`e2e/gmail-fixture.ts`).
