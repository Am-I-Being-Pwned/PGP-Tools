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
- Outbound network exfiltration (§7) — with one deliberate exception as
  of the GitHub recipient lookup: the background service worker may reach
  `https://api.github.com/users/`, and only that. The side panel, which is
  the realm that holds key handles and composed plaintext, is still
  pinned to
  `connect-src 'self'`. Read §7 before relying on this line.

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

| #   | File                                       | What's in it                                                                                                                                                                                                   |
| --- | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `apps/pgp/SECURITY.md` (this file)         | The contract                                                                                                                                                                                                   |
| 2   | `apps/pgp/gpg-wasm/src/lib.rs`             | The WASM crate. The actual sandbox.                                                                                                                                                                            |
| 2a  | `apps/pgp/gpg-wasm/src/crx.rs`             | RSA-2048 CRX (Chrome extension) signer/verifier. Separate `CRX_KEY_STORE`; see §10.                                                                                                                            |
| 2b  | `apps/pgp/gpg-wasm/src/age.rs`             | age encrypt/decrypt to imported SSH keys (`ssh-ed25519`, `ssh-rsa`). Separate `SSH_KEY_STORE`; see §13.                                                                                                        |
| 2c  | `apps/pgp/gpg-wasm/src/protected.rs`       | The at-rest envelope every key type is sealed by (`seal_with_*` / `open_*`), plus the generic `HandleStore`. See §5, §13.                                                                                      |
| 5b  | `apps/pgp/lib/age/`                        | JS-side age coordinator and SSH-identity import/unlock/drop. Holds recipient lines and `u32` handles; no key material.                                                                                         |
| 5a  | `apps/pgp/lib/crx/`                        | JS-side CRX key storage, sign/verify coordinator, and backup (de)serialization.                                                                                                                                |
| 3   | `apps/pgp/lib/pgp/wasm.ts`                 | JS-side barrel.                                                                                                                                                                                                |
| 4   | `apps/pgp/lib/pgp/wasm-public.ts`          | Wasm wrappers that don't carry secrets.                                                                                                                                                                        |
| 5   | `apps/pgp/lib/pgp/wasm-secrets.ts`         | Wasm wrappers that do, each with a `@secret-handling` block.                                                                                                                                                   |
| 6   | `apps/pgp/lib/protection/protect-flow.ts`  | Generate/import/protect. Owns the `Uint8Array.fill(0)` calls.                                                                                                                                                  |
| 7   | `apps/pgp/hooks/useKeySession.ts`          | KEY_STORE lifetime in JS (handle map, idle-/visibility-/OS-idle locks).                                                                                                                                        |
| 8   | `apps/pgp/entrypoints/sidepanel/App.tsx`   | Auto-lock wiring + workspace-draft persistence.                                                                                                                                                                |
| 8a  | `apps/pgp/entrypoints/welcome/Welcome.tsx` | First-install welcome page; only does `chrome.sidePanel.open` from a user-gesture click. No secret material.                                                                                                   |
| 8b  | `apps/pgp/entrypoints/background.ts`       | Service worker. Context menus + welcome tab, the one GitHub key lookup (§7), and the pending-op channel. No wasm, no keys -- but it writes the user's raw selection to `chrome.storage.session` unsealed (§7). |
| 9   | `apps/pgp/lib/network-lockdown.ts`         | Frozen `globalThis.fetch`; blocks XHR/WS/EventSource/RTC/sendBeacon.                                                                                                                                           |
| 10  | `apps/pgp/scripts/audit-network.mjs`       | Build-time per-context census: worker = 1 pinned fetch to api.github.com; pages = no code that can name a remote destination.                                                                                  |
| 11  | `apps/pgp/lib/storage/history.ts`          | Opt-in operation history. Segmented AES-256-GCM blobs under the contacts session key; holds message content. See §11.                                                                                          |
| 12  | `apps/pgp/lib/workspace-draft.ts`          | In-progress composer text, encrypted under a separate in-WASM draft session key (§6).                                                                                                                          |
| 13  | `apps/pgp/lib/security/threat-model.ts`    | This document's attack model as typed data. `threat-model.test.ts` fails if a claimed defence names no live test.                                                                                              |
| 14  | `apps/pgp/scripts/audit-invariants.mjs`    | Build-time enforcement of §9. Replaces running those greps by hand.                                                                                                                                            |
| 15  | `apps/pgp/gpg-wasm/src/rng.rs`             | ChaCha20 CSPRNG between us and `crypto.getRandomValues`. See §12 for what it does and does not cover.                                                                                                          |

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
| Decrypted message text (user data, not key)    | `decryptWithHandle`                                                        | UI-controlled; cleared on view dismiss / panel close                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `WorkspaceView.tsx`                                                                           |
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
     requested. `host_permissions` and `optional_host_permissions` are
     both absent from the manifest, and the build audit fails if either
     appears.
   - **What it does not buy.** Omitting the cookie means the request is
     not joinable to the user's GitHub account _from the request alone_.
     It is not anonymity. GitHub still learns the username looked up,
     the IP, and the time, and can join on IP with any logged-in
     browsing from the same address. Pasting an `ssh-ed25519 …` line
     does the same job with no network at all and stays first-class.
     `T-GITHUB-LOOKUP-DISCLOSURE`.

**The CSP is no longer uniform, and `connect-src 'self'` is no longer an
extension-wide claim.** It is now two policies:

- **Manifest** (`wxt.config.ts`, applies to every extension realm
  including the MV3 service worker — CSP does reach the worker, verified:
  with plain `connect-src 'self'` the worker's fetch fails, and widened it
  returns 200):
  `connect-src 'self' https://api.github.com/users/`.
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
blocked, so the prefix itself works. What this means: a compromised
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

- **worker bundle** — exactly one `fetch` call site beyond the lockdown's
  own reference to `globalThis.fetch`, pinned to the GitHub call; exactly
  one `https://` origin literal, and it is `https://api.github.com`; that
  literal appears in exactly one built file in the whole output, and that
  file is `background.js`; and `background.js` has no module imports, so
  worker code cannot be hiding in a chunk shared with the panel.
- **panel and welcome bundles** — no `fetch` beyond the two wasm loaders,
  no XHR / WebSocket / EventSource / RTCPeerConnection / sendBeacon /
  `new Worker` / `new Function` / `eval` at all, and no absolute URL
  literal outside a pinned set of XML namespaces and href targets.
- **manifest** — `connect-src` exactly as written above (not a substring
  match), no host permissions of either kind, and the panel's meta tag
  present in the built HTML.

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
dependencies plus transitives, runs no content scripts, loads no remote
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
