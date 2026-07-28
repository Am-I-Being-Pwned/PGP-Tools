/**
 * The attack model, as data.
 *
 * `SECURITY.md` is the prose contract; this file is its machine-checked
 * backbone. Every threat is either **defended** (and names the tests that
 * hold the line) or **accepted** (and says why we don't defend it). The
 * companion `threat-model.test.ts` fails the suite if a threat claims a
 * defence without naming a live test, or accepts a risk without a reason.
 *
 * Why this exists: SECURITY.md §9 used to be five shell greps a human was
 * expected to run by hand, and it drifted -- the checklist began reporting
 * a false alarm, and a whole new persistence surface (encrypted operation
 * history) shipped without ever reaching the document. Prose asserting
 * things about code, checked by a busy human, decays. This decays loudly.
 *
 * Adding a security-relevant feature? Add its threats here first. A
 * `pending` entry is an honest TODO; a missing entry is a blind spot.
 */

/**
 * Repo-relative path to a test or audit script, from the repo root.
 *
 * CAVEAT on heap-snapshot evidence: V8 records a string node's value in a
 * heap snapshot **truncated to the first 1024 characters**. A canary needle
 * taken from beyond that offset returns zero hits whether or not the string
 * is retained -- the assertion passes for the wrong reason and the test is
 * silently vacuous. `e2e/heap.spec.ts` happens to be safe (its needle sits
 * at ~690) but by luck rather than by rule. Any new heap assertion must
 * constrain its needle offset and carry a positive control, as
 * `e2e/crx-memory.spec.ts` does. Treat `verifiedBy` on a heap-based test as
 * only as strong as its needle placement.
 */
export type EvidencePath = string;

export type ThreatStatus =
  /** We defend this, and tests prove it. */
  | "defended"
  /** We defend part of it; the gap is real and stated in `rationale`. */
  | "partial"
  /** Out of scope by design. `rationale` says why. */
  | "accepted"
  /** Known threat, defence intended but not yet built or not yet tested. */
  | "pending";

export interface Threat {
  /** Stable id. Referenced from commit messages and advisories; never reuse. */
  id: string;
  title: string;
  /** The capability the attacker is assumed to have. Be concrete. */
  attacker: string;
  /** What stands in their way. "Nothing" is a valid answer for `accepted`. */
  defence: string;
  status: ThreatStatus;
  /**
   * Why we don't fully defend. Required for `accepted` and `partial` --
   * an accepted risk without a stated reason is just an unexamined one.
   */
  rationale?: string;
  /**
   * Tests or audit scripts that would fail if this defence regressed.
   * Required for `defended` and `partial`. Paths are existence-checked.
   */
  verifiedBy?: EvidencePath[];
  /** The SECURITY.md section that documents this in prose. */
  section: string;
}

export const THREAT_MODEL: Threat[] = [
  // ---------------------------------------------------------------------
  // Key material at rest and in memory
  // ---------------------------------------------------------------------
  {
    id: "T-HEAP-SCRAPE",
    title: "Private key scraped from the JS heap",
    attacker:
      "Malicious JS running in the side-panel realm (e.g. a compromised UI dependency) that can take or induce a heap snapshot, or read reachable JS objects.",
    defence:
      "Key bytes live in WASM linear memory behind an opaque handle; JS never holds the plaintext cert except on the two explicit export paths (§2).",
    status: "defended",
    verifiedBy: ["apps/pgp/e2e/heap.spec.ts"],
    section: "§1, §2",
  },
  {
    id: "T-ACTIVE-WASM-CALL",
    title: "Malicious in-panel JS calls the WASM export path directly",
    attacker:
      "Malicious JS in the side-panel realm that, rather than scraping memory, calls the wasm exports itself while a key is unlocked.",
    defence:
      "None effective. The plaintext export is gated by a type-to-confirm UI, which is React state, not a capability check.",
    status: "accepted",
    rationale:
      "LIKELIHOOD: this is a consequence of T-SUPPLY-CHAIN, not an independent or probable attack. It requires an attacker to already be running code in the side-panel realm -- a poisoned package, build, or Web Store release. Seven runtime dependencies, no content scripts, no remote code, CSP forbids loading any. Do not read the detail below as alarm; it documents what a supply-chain compromise would cost, which is worth knowing precisely because §1's WASM-isolation guarantee is easy to over-read. IMPACT, once that precondition holds, is confirmed by test rather than theorised. The wasm-bindgen glue ships as an ES module chunk whose hashed filename appears verbatim in the readable entry chunk; the ES module registry is keyed by resolved URL, so import()-ing it returns the ALREADY-INITIALISED instance with the live KEY_STORE rather than a fresh empty one. In-page JS doing import() + getKeyArmored(1) returns plaintext secret key material with no user gesture, no CDP and no debugger. Sequential handles from 1 make the sweep trivial but are not the root cause -- randomising them would not fix this, since the attacker can also read the handle off the React tree or the decoder path. Accepted rather than pending because it is not fixable with in-realm mechanisms. DECISION ON RECORD, so it is not silently reopened: moving the engine into a Worker was considered and declined. A Worker alone does not stop a compromised panel dependency (it can post messages as easily as it calls exports today); it only pays off combined with gating the export paths on a proof the panel cannot forge, e.g. a WASM-minted challenge satisfied by a WebAuthn assertion verified in WASM. That gate is a protocol we would have to design ourselves, and this project's rule is that every algorithm it relies on is designed and reviewed by someone else. Without the gate the rewrite buys close to nothing, while costing async-over-postMessage on every wasm-secrets call, careful Uint8Array transfer handling to avoid fresh un-zeroized copies, and a rebuild of the CDP-based wasm-memory harness. What limits it: no handle survives a lock (§6), so the attack window is exactly the unlocked window, and §7 still constrains exfiltration. Documented in §8.10.",
    verifiedBy: ["apps/pgp/e2e/hostile-dep.spec.ts"],
    section: "§1, §2, §8.10",
  },
  {
    id: "T-PRIMITIVE-HOOK",
    title: "Hostile in-realm code hooks the primitives the boundary rests on",
    attacker:
      "A compromised UI dependency that patches prototype methods rather than attacking WASM directly.",
    defence:
      "Partial. `network-lockdown.ts` freezes `TextEncoder.prototype.encode`/`encodeInto`, `TextDecoder.prototype.decode`, `Crypto.prototype.getRandomValues` and `Clipboard.prototype.writeText` non-writable/non-configurable at first import, AND pins the own slot on the `navigator.clipboard` and `globalThis.crypto` instances. Both layers are needed and block different routes: freezing the prototype defeats plain assignment (`[[Set]]` refuses when it finds a non-writable inherited data property), while only the instance pin defeats `Object.defineProperty`, which bypasses that check. Each is verified by its own differential in e2e/hostile-dep.spec.ts.",
    status: "partial",
    rationale:
      "Originally confirmed exploitable by e2e/hostile-dep.spec.ts: an encode hook captured the unlock password verbatim as React converted the input string, a decode hook tapped every string WASM returns (so even a perfectly gated export leaks during a LEGITIMATE user export), and a clipboard hook read at write time, which the 30s/60s auto-clear cannot touch since it defends against clipboard managers rather than in-realm readers. The freeze works only because network-lockdown.ts is the first import in every entrypoint, so it defeats a dependency loaded AFTER us -- it does nothing against one earlier in the module graph, and nothing at all against a hostile realm calling the wasm exports directly (T-ACTIVE-WASM-CALL). Raises cost; does not close the hole.",
    verifiedBy: ["apps/pgp/e2e/hostile-dep.spec.ts"],
    section: "§8.10",
  },
  {
    id: "T-ENTROPY-POISON",
    title: "Hooked getRandomValues makes generated keys predictable",
    attacker:
      "A compromised UI dependency that patches `Crypto.prototype.getRandomValues` to return attacker-chosen or constant bytes.",
    defence:
      "Partial, on two fronts. (1) `Crypto.prototype.getRandomValues` is frozen AND the own slot on the `globalThis.crypto` instance is pinned non-configurable, which together block both the assignment and defineProperty shadowing routes. (2) A thread-local ChaCha20 CSPRNG (`rand_chacha`, seeded once from the platform RNG, never reseeded) now backs AES-GCM nonces, Argon2id salts, the draft session key, and CRX RSA keygen.",
    status: "partial",
    rationale:
      "The most severe variant of T-PRIMITIVE-HOOK and the one with the longest blast radius: it does not exfiltrate an existing key, it makes keys generated afterwards predictable, silently, with valid-looking output and no artefact left in the vault. WHAT THE CSPRNG BUYS: poisoning that lands AFTER the first draw, and poisoning that is constant/degenerate, no longer propagates -- most importantly it prevents AES-GCM nonce reuse under a fixed key, which would leak the keystream and the GHASH key across every blob and every draft. Never reseeded on purpose: reseeding means re-reading the source we distrust, and would let a later poisoning replace good state. WHAT IT DOES NOT BUY, and this is the important half: poisoning that lands BEFORE the first draw gives the attacker the seed and therefore the whole stream, so it buys nothing there; and it does NOT cover OpenPGP key generation at all, which is the primary asset. Sequoia's CertBuilder::generate takes no RNG and the crypto-rust backend hard-codes OsRng in ~28 places plus per-algorithm direct uses, with no trait object, thread-local hook, or feature flag -- overriding it needs a fork or patch, which was deliberately not done. A test (a_known_seed_still_yields_a_known_stream) asserts the limitation so the suite cannot be misread as a claim of unpredictability. There is no independent entropy source inside WASM; getrandom on wasm32 bottoms out at crypto.getRandomValues and that is the only door. No jitter or address-based sources were added -- combining entropy sources is a design activity and out of scope.",
    verifiedBy: ["apps/pgp/e2e/hostile-dep.spec.ts"],
    section: "§8.10",
  },
  {
    id: "T-UNLOCK-PARAM-NOT-OWNED",
    title: "Password / PRF bytes left in a freed WASM allocation after unlock",
    attacker:
      "Anyone who can read WASM linear memory after an unlock completes -- the same capability assumed by T-HEAP-SCRAPE and the OS-level threats in §8.1.",
    defence:
      "FIXED. `unlock_with_password`, `unlock_with_prf` and `init_contacts_session_with_prf` now take their secret params as owned `Vec<u8>` and wrap them in `Zeroizing` on entry, matching the four generate/protect fns. Owning the wasm-bindgen marshalled copy is what makes it scrubbable.",
    status: "partial",
    rationale:
      "Previously these three took `&[u8]` and scrubbed only the derived AES key, leaving the raw password / PRF bytes in a freed allocation on the app's three most exercised secret entry points. Now deterministic rather than dependent on allocator reuse. Kept at `partial` rather than `defended` for an honest residual: §8.4 still applies to any inner copy wasm-bindgen makes before our binding sees the value, which we never get an address for. Also worth recording that e2e/memory.spec.ts passed while the borrowed-param gap was live, so that test was never the thing establishing this guarantee and a pass there should not be read as proof of deliberate zeroization. Enforced going forward by the owned-secret-params-zeroized invariant, which fails the build on a borrowed secret param.",
    verifiedBy: [
      "apps/pgp/e2e/memory.spec.ts",
      "apps/pgp/scripts/audit-invariants.mjs",
    ],
    section: "§5, §8.4, §9 check 4",
  },
  {
    id: "T-FORENSIC-AFTER-LOCK",
    title: "Key material recoverable after lock / idle / drop",
    attacker:
      "Anyone who can inspect process memory after the user is finished with a key.",
    defence:
      "`Drop for StoredKey` zeroizes; JS-side password and PRF buffers are `.fill(0)`ed in `finally`; auto-lock drops handles on six triggers (§6).",
    status: "defended",
    verifiedBy: [
      "apps/pgp/e2e/memory.spec.ts",
      "apps/pgp/e2e/lifecycle.spec.ts",
    ],
    section: "§5, §6",
  },
  {
    id: "T-KEYSTORE-BACKDOOR",
    title: "Key enters KEY_STORE without a user-initiated unlock",
    attacker:
      "A future code change (ours or a contributor's) that inserts into KEY_STORE from a path the user did not authorise.",
    defence:
      "Exactly one non-test `insert_key` call site, reachable only from `unlock_with_password` / `unlock_with_prf`. Asserted mechanically at build time.",
    status: "defended",
    verifiedBy: ["apps/pgp/scripts/audit-invariants.mjs"],
    section: "§4, §9",
  },
  {
    id: "T-BLOB-SUBSTITUTION",
    title: "Cross-blob substitution on disk",
    attacker:
      "Someone with write access to extension storage who swaps one encrypted key blob for another to confuse identity.",
    defence:
      "AES-256-GCM AAD binds each blob to its cert fingerprint; CRX blobs use distinct AAD prefixes and re-derive the extension id from the key itself on unlock.",
    status: "defended",
    verifiedBy: [
      "apps/pgp/e2e/storage.spec.ts",
      "apps/pgp/e2e/edge-import.spec.ts",
    ],
    section: "§1, §10",
  },

  // ---------------------------------------------------------------------
  // Brute force
  // ---------------------------------------------------------------------
  {
    id: "T-BRUTE-OFFLINE",
    title: "Offline brute force of a stolen encrypted blob",
    attacker:
      "Someone who has exfiltrated the encrypted key blob and attacks it offline with GPUs.",
    defence: "Argon2id, 64 MB memory, 3 iterations, per-blob salt.",
    status: "defended",
    rationale:
      "The KDF cost is the whole defence and is the correct one: an attacker holding the blob never touches our UI, so no amount of UI-side throttling would apply. There is deliberately no exponential-backoff mechanism -- an earlier README claim to that effect described code that never existed and has been removed.",
    verifiedBy: ["apps/pgp/e2e/keys.spec.ts"],
    section: "README security model",
  },

  // ---------------------------------------------------------------------
  // Exfiltration channels
  // ---------------------------------------------------------------------
  {
    id: "T-NETWORK-EXFIL",
    title: "Outbound network exfiltration of secrets",
    attacker:
      "Malicious code in any extension context attempting to POST key material or plaintext to a remote host.",
    defence:
      "Manifest CSP `connect-src 'self'` blocks non-extension destinations at the network layer. Defence in depth: `network-lockdown.ts` freezes `fetch` non-configurable and stubs XHR / WebSocket / EventSource / RTCPeerConnection / sendBeacon. Re-asserted at build time.",
    status: "partial",
    rationale:
      "Both layers are static or same-realm. The build-time audit proves no unexpected network code ships; it does not prove the runtime stubs cannot be circumvented in a realm we do not control. A runtime assertion suite for the lockdown does not exist yet.",
    verifiedBy: ["apps/pgp/scripts/audit-network.mjs"],
    section: "§7",
  },
  {
    id: "T-CLIPBOARD-EXFIL",
    title: "Exported key lingers on the clipboard",
    attacker:
      "Any local process or later paste target that reads the clipboard after a key export.",
    defence:
      '`scheduleClipboardClear` overwrites with `""` after 30s (plaintext) / 60s (encrypted).',
    status: "partial",
    rationale:
      "OS-level clipboard managers (Windows Clipboard History, macOS Universal Clipboard, Klipper, Raycast) retain copies our overwrite cannot reach. Documented in §8.5.",
    verifiedBy: ["apps/pgp/e2e/keys.spec.ts"],
    section: "§1, §8.5",
  },
  {
    id: "T-FILENAME-METADATA",
    title: "Download filenames leak recipient identity and timing",
    attacker:
      "Anyone with filesystem access, a search index (Spotlight / Windows Search), or the user's synced `chrome://downloads` history.",
    defence:
      "None. Encrypt output is named `message.to-<recipient>.<timestamp>.gpg` in cleartext.",
    status: "accepted",
    rationale:
      "Deliberate usability trade: a Downloads folder of identically-named .gpg blobs is unusable. The consequence is that the encrypt-to-file path protects message contents but NOT recipient identity or activity timing. Documented in §8.5 so users can rename before sharing. Revisit if a metadata-sensitive threat profile becomes a target audience.",
    section: "§8.5",
  },

  // ---------------------------------------------------------------------
  // Signature integrity
  // ---------------------------------------------------------------------
  {
    id: "T-SIG-BYPASS",
    title: "Signature verification bypass / TOCTOU",
    attacker:
      "Someone supplying a message with a forged, absent, or mismatched signature, hoping plaintext is released before verification completes.",
    defence:
      "Decrypt and verify return in a single packed response; a bad signature yields no plaintext. No window between the two.",
    status: "defended",
    verifiedBy: [
      "apps/pgp/e2e/keys.spec.ts",
      "apps/pgp/e2e/revocation.spec.ts",
    ],
    section: "README, §2",
  },
  {
    id: "T-CRX-ID-SPOOF",
    title: "CRX signature valid under an unrelated key spoofs an extension id",
    attacker:
      "Someone presenting a validly-signed CRX whose signing key is not the one the extension id derives from.",
    defence:
      "`verifyCrx` requires a valid signature AND that SHA-256(SPKI) matches the signed crx_id. Unlock re-derives the id and rejects a mismatched key. Parser is panic-free on malformed input.",
    status: "partial",
    rationale:
      "The panic-free claim rests on hand review and unit tests, not fuzzing. The protobuf header encoder/parser is hand-rolled. cargo-fuzz coverage would upgrade this to `defended`.",
    verifiedBy: ["apps/pgp/gpg-wasm/src/crx.rs"],
    section: "§10",
  },

  // ---------------------------------------------------------------------
  // User-data surfaces (not key material, but user secrets)
  // ---------------------------------------------------------------------
  {
    id: "T-HISTORY-AT-REST",
    title: "Operation history exposes past message content at rest",
    attacker:
      "Someone with read access to `browser.storage.local` on a locked or unattended device.",
    defence:
      "Opt-in, off by default. Entries are AES-256-GCM segments under the in-WASM contacts session key; the plaintext manifest holds only segment numbers and byte sizes. No plaintext cached at module level, so a master lock leaves nothing readable.",
    status: "defended",
    rationale:
      "Confirmed by canary coverage: the manifest holds only {n,bytes} with no entry data, the canary is absent from local/sync/session storage, and after an in-app master lock the JS-heap count is 0 -- including in a probe that never opens the viewer, proving nothing module-level caches decrypted entries. The entry is still readable after re-unlock, so the zero measured a live secret dropping rather than a scan that never worked.",
    verifiedBy: [
      "apps/pgp/lib/storage/history.test.ts",
      "apps/pgp/e2e/history-memory.spec.ts",
    ],
    section: "§11",
  },
  {
    id: "T-HISTORY-AAD-SHARED",
    title: "History segments are not bound to their slot or their store",
    attacker:
      "Anyone who can write browser.storage.local -- another process on the device, a synced device, or malicious in-realm code -- with NO knowledge of the vault key.",
    defence:
      "FIXED. Every store sealed under the master session -- keyring, contacts, settings, CRX keys, and each history segment -- is sealed for a DOMAIN, and the domain is the browser.storage key the blob lives under. Both an HKDF-SHA256 subkey and the AEAD's AAD derive from it (`gpg-tools:store-subkey:v1:<key>`, `gpg-tools:store:v1:<key>`), so a blob only opens in the slot it was written to.",
    status: "defended",
    rationale:
      "Was demonstrated, not theorised: copying pgp_history_seg_0 to seg_1 made adoptStraySegments adopt it (rigorous, since adoption only happens for a segment actually decrypted), and the same blob written to pgp_public_contacts read as a legitimately EMPTY contact list -- so the next contact import would have persisted over the user's real contacts permanently. Two bindings deliberately: the AAD alone suffices for a correct AEAD, but a distinct key means a future bug that drops or mismatches the AAD still cannot cross a domain boundary. Using the storage key as the domain means no mapping table to keep in sync and no way for read and write paths to disagree about a slot; it is the key not the storage area, so local<->sync moves are unaffected. All five stores were separated, not just history, since keyring<->contacts<->settings<->CRX substitution is the same bug. Migration: openEnvelope tries the domain scheme then falls back to legacy -- history re-seals on read (it already holds its lock), shared stores re-seal on next mutation, and normalizePadding (which runs on unlock) upgrades a store the user only ever reads, including when its padding is already canonical. Reads never write, so an upgrade cannot race a mutation. Verified by a negative control: collapsing every domain to one constant makes both e2e tests fail on their own separate assertions.",
    verifiedBy: [
      "apps/pgp/e2e/history-memory.spec.ts",
      "apps/pgp/e2e/migration.spec.ts",
      "apps/pgp/lib/storage/envelope.test.ts",
      "apps/pgp/lib/storage/history.test.ts",
      "apps/pgp/lib/storage/upgrade.test.ts",
    ],
    section: "§11.1",
  },
  {
    id: "T-HISTORY-PLAINTEXT-NOT-ZEROIZED",
    title: "History message content is never zeroized",
    attacker:
      "Anyone who can inspect JS-heap or WASM memory after a history write or read.",
    defence:
      "FIXED in all three places: writeSegment does json.fill(0) in a finally, `encrypt_contacts` and `encrypt_store` take the plaintext by value under Zeroizing::new, and readSegment does plaintext?.fill(0) in a finally.",
    status: "defended",
    rationale:
      "Up to 64 KB of user message content per call, and the same class of gap as T-UNLOCK-PARAM-NOT-OWNED. The draft path already did all three correctly, so this was an inconsistency to close rather than a design constraint. Proven behaviourally, not by inspection: the vitest mock retains references to the ACTUAL buffers that crossed the wasm boundary and asserts they are non-empty before the call and all-zero after -- on write, on read, on an unparseable segment, and on the legacy-migration path where the same buffer is both decrypt output and re-seal input. NOTE: the intermediate JSON.stringify string remains genuinely unzeroizable (JS strings are immutable); avoiding it means hand-serialising entries into a byte buffer, judged a larger change than the residual leak justifies, and called out in writeSegment's doc comment. Enforcement gap found and closed separately: audit-invariants.mjs did not originally match encrypt_store/encrypt_contacts or the `plaintext` param, so it passed either way and this claim was unenforced -- SECRET_FN_RE and SECRET_PARAM_NAMES were extended, and the extension was verified to fail on a deliberate regression.",
    verifiedBy: [
      "apps/pgp/lib/storage/history.test.ts",
      "apps/pgp/scripts/audit-invariants.mjs",
    ],
    section: "§11.2",
  },
  {
    id: "T-HISTORY-KEY-COUPLING",
    title: "History is sealed under the contacts session key, not its own",
    attacker: "n/a -- design observation rather than an external actor.",
    defence:
      "None needed for confidentiality: the contacts key is itself master-protected and zeroized on master lock.",
    status: "accepted",
    rationale:
      "Reusing the contacts session key couples two unrelated features' lifetimes: anything that initialises a contacts session also makes history readable, and a future change to contacts-session scope silently changes history's exposure window. Accepted because both are gated on the same master unlock, so there is no confidentiality gap today, and canary coverage confirms it. CORRECTION: an earlier version of this entry claimed the T-HISTORY-AAD-SHARED fix would resolve this coupling as a side effect. That was wrong. The per-store subkey is derived FROM the contacts session key via HKDF, so it inherits that key's lifetime exactly, and possession of the contacts key still yields it. Domain separation buys cryptographic separation between stores, not lifetime independence. Resolving this properly needs an independently generated history key persisted under master protection -- a new stored blob and a new unlock path. Asserted rather than glossed by the Rust test test_store_envelope_unreadable_after_the_session_drops.",
    verifiedBy: ["apps/pgp/e2e/history-memory.spec.ts"],
    section: "§5, §11.1",
  },
  {
    id: "T-DRAFT-AT-REST",
    title: "In-progress message draft survives a lock",
    attacker:
      "Someone inspecting memory or storage after an auto-lock fires mid-composition.",
    defence:
      "Draft text is encrypted under a separate in-WASM draft session key (with its own versioned AAD) and held at App level as ciphertext only; the key is dropped on panel close.",
    status: "partial",
    rationale:
      "The ciphertext mechanism is proven: the canary is absent from WASM linear memory after encryptDraft, absent from all three storage areas, and rehydrates correctly after unlock (so the scans measured a live secret). But a plaintext copy survives the lock in the DOM -- see T-DRAFT-DOM-RESIDUE. The draft is the best-engineered secret path in the codebase and still leaks, via a mechanism that has nothing to do with the crypto.",
    verifiedBy: ["apps/pgp/e2e/draft-memory.spec.ts"],
    section: "§5, §6",
  },
  {
    id: "T-DRAFT-HEAP-RESIDUE",
    title: "Composed draft plaintext survives master lock in the JS heap",
    attacker:
      "Anyone who can read the V8 heap after a master lock -- the T-HEAP-SCRAPE capability, or any of the §8.1 OS-level routes.",
    defence:
      "FIXED. The composer input is uncontrolled: the message lives in a ref and the DOM node, never in React render state. doMasterLock pulls the draft via WorkspaceDraftSource.getDraft(), encrypts it, then calls wipe() (input ref + DOM value + clear-undo buffer) before flipping masterUnlocked.",
    status: "defended",
    rationale:
      "Renamed from T-DRAFT-DOM-RESIDUE: the retainer was never the DOM, and that misnomer cost a round of work. Sequence worth preserving. Original chain: GC roots -> C++ Persistent roots -> autofill::FormTracker (pinning the textarea) -> React value-tracker closure -> plaintext; durable across six forced GCs over ten seconds with string churn. Blanking the DOM value removed THAT chain and revealed a second: (Global handles) -> closure -> property[alternate] -> updateQueue.lastEffect.create -> context -> workspace -> input. React double-buffers hook state onto fiber.alternate and keeps effect closures hanging off it reachable from a GC root, so a controlled value={input} retained the string regardless of the DOM -- clearing the DOM could never have been sufficient. The fix was to stop holding it in render state at all, following ImportKeyPage's uncontrolled paste box. This also deleted App.tsx's latestDraftRef, which had held a live plaintext copy for the whole panel session. Explicitly NOT the same as T-PLAINTEXT-IN-UI, which accepts plaintext being visible while composing. MEASUREMENT NOTE: this test only passes with tracing off -- Playwright's __playwright_snapshot_cache_ retains a textarea's value and masks the app-owned chain, so the spec sets test.use({ trace: 'off' }). A retainer walk should be validated against a deliberate negative control before its zero is believed. Decrypted output is covered by a separate test in the same spec (T-OUTPUT-HEAP-RESIDUE); this entry's test asserts only on the input draft.",
    verifiedBy: ["apps/pgp/e2e/draft-memory.spec.ts"],
    section: "§8.11",
  },
  {
    id: "T-OUTPUT-HEAP-RESIDUE",
    title: "Decrypted output survives master lock in the JS heap",
    attacker:
      "Same capability as T-DRAFT-HEAP-RESIDUE: anyone reading the V8 heap after a master lock.",
    defence:
      "FIXED. `outputRef` plus the result `<pre>`'s textContent; only the boolean `hasOutput` reaches render state. doMasterLock's `wipe()` clears the ref and the node. The `<pre>` is written imperatively via a callback ref, never as a React child, so the string never enters the fiber element tree.",
    status: "defended",
    rationale:
      "Found while fixing T-DRAFT-HEAP-RESIDUE and measured, not inferred: count 1 after a real encrypt->decrypt->lock cycle. This is decrypted MESSAGE plaintext, so the exposure was comparable to the draft. Fixed by the same move that fixed T-DRAFT-HEAP-RESIDUE. Validated by differential rather than a bare zero: reintroducing an effect that closes over the output puts the count at 1 with the chain alternate -> updateQueue.lastEffect.create -> context -> workspace -> lastRenderedState; removing it gives 0 on BOTH strongRetainers and scanJsHeap, i.e. absent from the snapshot entirely rather than merely weakly held. Needle sits at offset 0 of the message because of the 1024-char snapshot truncation, and the spec inherits the file's trace:'off'. Kept the <pre> rather than switching to a textarea so the existing wrapping and select-all behaviour are untouched -- the thing that mattered was not rendering {output} as a JSX child.",
    verifiedBy: ["apps/pgp/e2e/draft-memory.spec.ts"],
    section: "§8.11",
  },
  {
    id: "T-CRX-KEY-MEMORY",
    title: "CRX RSA signing key persists in memory after use",
    attacker:
      "Anyone inspecting the JS heap or WASM linear memory after a CRX signing operation.",
    defence:
      "The PKCS#8 DER lives only in CRX_KEY_STORE as Zeroizing<Vec<u8>>, populated solely by unlockCrxWith*, zeroized on drop / dropCrxKey. Only the SPKI public half and derived extension id cross to JS.",
    status: "defended",
    rationale:
      "Verified in the strong present-then-absent form rather than absence-only: with a CRX_KEY_STORE handle held open across a user step (the bulk-export flow), a needle from the interior of RSA prime p is FOUND in linear memory; after unmount runs closeCrxKey it is gone, with a liveness re-assert proving the zero was not a dead scan. The JS-heap side is also clean across a real unlock/sign/drop cycle, including after the import page closes -- despite the PEM arriving as an unzeroizable JS String.",
    verifiedBy: ["apps/pgp/e2e/crx-memory.spec.ts"],
    section: "§10",
  },
  {
    id: "T-PLAINTEXT-IN-UI",
    title: "Plaintext observable in the rendered UI",
    attacker:
      "Screen capture, the accessibility tree, autofill, or a screen recorder.",
    defence: "None. The user's message must be rendered to be composed.",
    status: "accepted",
    rationale:
      "Unfixable at the application layer -- a composer that the user cannot see is not a composer. Documented in §8.5.",
    section: "§8.5",
  },

  // ---------------------------------------------------------------------
  // Explicitly out of scope
  // ---------------------------------------------------------------------
  {
    id: "T-OS-MEMORY",
    title: "Swap, hibernation, crash dumps, cold boot",
    attacker:
      "Someone with disk or physical access recovering memory pages written out before our zeroize ran.",
    defence: "None at the application layer.",
    status: "accepted",
    rationale:
      "The OS may page WASM linear memory to disk before we can zeroize it, and we never learn the address. Mitigated only by full-disk encryption, which is the user's responsibility. Enumerated in §8.1.",
    section: "§8.1",
  },
  {
    id: "T-V8-GC",
    title: "Secrets persist in V8 after we drop our reference",
    attacker: "Anyone taking a heap snapshot in the window before GC runs.",
    defence:
      '`setX("")` drops our reference promptly; secrets are kept out of JS strings wherever possible.',
    status: "accepted",
    rationale:
      "GC timing, string interning, generational copies and JIT artefacts are all outside our control. This is precisely why key material lives in WASM rather than JS. Enumerated in §8.2.",
    section: "§8.2",
  },
  {
    id: "T-VARIABLE-TIME-CRYPTO",
    title: "Timing side channel in crypto primitives",
    attacker:
      "A same-realm attacker who can time crypto operations precisely enough to extract key bits.",
    defence: "None. `allow-variable-time-crypto` is enabled.",
    status: "accepted",
    rationale:
      "RustCrypto cannot guarantee constant-time on wasm32-unknown-unknown. Documented in gpg-wasm/Cargo.toml and §8.3. Note this compounds T-ACTIVE-WASM-CALL: both assume a hostile same-realm actor.",
    section: "§8.3",
  },
  {
    id: "T-SUPPLY-CHAIN",
    title: "Malicious code ships via dependency or Web Store update",
    attacker:
      "A poisoned transitive dependency, or a compromised Web Store publisher account pushing a silent update.",
    defence:
      "Open source, so the repo is auditable. Build-time network audit limits one exfil route.",
    status: "accepted",
    rationale:
      "Builds are not reproducible, so verifying source is not verifying the shipped binary. Sequoia, RustCrypto, wasm-bindgen, React and WXT are all trusted. Enumerated in §8.8. Reproducible builds would be the real fix.",
    section: "§8.8",
  },
  {
    id: "T-EXPORT-SOCIAL-ENG",
    title: "User is socially engineered into exporting their key",
    attacker:
      "Someone who persuades the user to type EXPORT and paste the result into a chat.",
    defence: "Type-to-confirm friction and explicit warning copy.",
    status: "accepted",
    rationale:
      "Unfixable in software while the export feature exists, and it must exist -- key portability is a requirement. §8.9 calls this the deliberate trapdoor.",
    section: "§8.9",
  },
  {
    id: "T-DEVTOOLS",
    title: "DevTools attached to the side panel",
    attacker:
      "Anyone who can open DevTools on our page, or another extension with browser.debugger.",
    defence: "None.",
    status: "accepted",
    rationale:
      "Equivalent to root on our realm. Also covers other extensions holding browser.debugger or broad tabs permissions. §8.5, §8.6.",
    section: "§8.5, §8.6",
  },
];
