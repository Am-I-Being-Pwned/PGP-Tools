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
      "The most severe variant of T-PRIMITIVE-HOOK and the one with the longest blast radius: it does not exfiltrate an existing key, it makes keys generated afterwards predictable, silently, with valid-looking output and no artefact left in the vault. WHAT THE CSPRNG BUYS: poisoning that lands AFTER the first draw, and poisoning that is constant/degenerate, no longer propagates -- most importantly it prevents AES-GCM nonce reuse under a fixed key, which would leak the keystream and the GHASH key across every blob and every draft. Never reseeded on purpose: reseeding means re-reading the source we distrust, and would let a later poisoning replace good state. WHAT IT DOES NOT BUY, and this is the important half: poisoning that lands BEFORE the first draw gives the attacker the seed and therefore the whole stream, so it buys nothing there; and it does NOT cover OpenPGP key generation at all, which is the primary asset. Sequoia's CertBuilder::generate takes no RNG and the crypto-rust backend hard-codes OsRng in ~28 places plus per-algorithm direct uses, with no trait object, thread-local hook, or feature flag -- overriding it needs a fork or patch, which was deliberately not done. A test (a_known_seed_still_yields_a_known_stream) asserts the limitation so the suite cannot be misread as a claim of unpredictability. There is no independent entropy source inside WASM; getrandom on wasm32 bottoms out at crypto.getRandomValues and that is the only door. No jitter or address-based sources were added -- combining entropy sources is a design activity and out of scope. The age engine has the same carve-out for the same structural reason and is tracked separately as T-AGE-RNG-UNHOOKABLE, because the APIs, the affected values and the blast radius all differ.",
    verifiedBy: ["apps/pgp/e2e/hostile-dep.spec.ts"],
    section: "§8.10",
  },
  {
    id: "T-AGE-RNG-UNHOOKABLE",
    title: "age's internal randomness bypasses the ChaCha20 hardening",
    attacker:
      "The same capability as T-ENTROPY-POISON: a compromised UI dependency that patches `Crypto.prototype.getRandomValues` to return attacker-chosen or constant bytes.",
    defence:
      "Partial, and unevenly. Everything age.rs itself draws goes through the crate CSPRNG: the Argon2id salt and AES-GCM nonce of the at-rest envelope (inside protected.rs) and the random probe validate_identity round-trips on unlock. Everything age draws internally does not, and cannot -- `age::Encryptor::with_recipients` (new_file_key(), Nonce::random()) and `<age::ssh::Recipient as age::Recipient>::wrap_file_key` (the ephemeral X25519 secret for ssh-ed25519, the RSA-OAEP randomness for ssh-rsa) each construct their own `rand::rngs::OsRng` and take no RNG argument. The frozen `Crypto.prototype.getRandomValues` plus the pinned own slot on `globalThis.crypto` (T-PRIMITIVE-HOOK) is the only layer that applies to those draws.",
    status: "partial",
    rationale:
      "Recorded as its own entry rather than folded into T-ENTROPY-POISON because the shape is identical but the facts are not: different crate, different APIs, and a different blast radius -- there is no long-lived asset to make predictable here, since the app never GENERATES an age or SSH key (import only, §13). What a poisoned draw costs instead is per-file: a predictable file key or ephemeral X25519 secret makes that message's contents recoverable to the attacker, and a repeated payload nonce under a repeated file key is the usual catastrophic AEAD failure. Keeping it separate also keeps it findable -- someone auditing the age surface greps for `age`, not for `Sequoia`. STRUCTURALLY THE SAME CARVE-OUT AS SEQUOIA'S CertBuilder::generate: no trait object, no thread-local hook, no feature flag; intercepting would need a fork or patch of the age crate, which was deliberately not done, exactly as for Sequoia. On wasm32-unknown-unknown those OsRng draws resolve crypto.getRandomValues per call, so they sit fully inside T-ENTROPY-POISON / §8.10 and inherit its supply-chain precondition. WHAT IS NOT CLAIMED: no test asserts anything about age's internal draws, because there is no seam to observe them through -- the evidence below covers the primitive freeze and the CSPRNG's own documented limits, not age's behaviour. Reading rng.rs's tests as coverage of this entry would be a misreading.",
    verifiedBy: [
      "apps/pgp/e2e/hostile-dep.spec.ts",
      "apps/pgp/gpg-wasm/src/rng.rs",
    ],
    section: "§8.10, §12, §13",
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
      "KEY_STORE entries are `Zeroizing<Vec<u8>>`, zeroized on drop; JS-side password and PRF buffers are `.fill(0)`ed in `finally`; auto-lock drops handles on six triggers (§6).",
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
      "Per-context, and no longer uniform -- the extension-wide `connect-src 'self'` claim this entry used to make stopped being true when the GitHub SSH-key lookup shipped. PANEL AND WELCOME REALMS: still exactly `connect-src 'self'`, now via the `<meta http-equiv=\"Content-Security-Policy\">` tag in `sidepanel.html` rather than via the manifest. Meta CSP can only tighten, never loosen, and the browser enforces it. WORKER REALM: the manifest CSP is `connect-src 'self' https://api.github.com/users/` -- one origin, narrowed to one path prefix, GET only. Defence in depth in both realms: `network-lockdown.ts` freezes `fetch` non-configurable (forcing `credentials: \"omit\"`, stripping Cookie/Authorization/X-Api-Key, rejecting plain HTTP and POST/PUT/PATCH/DELETE) and stubs XHR / WebSocket / EventSource / RTCPeerConnection / sendBeacon. Re-asserted at build time per context: the audit pins the worker bundle to exactly one `fetch` call site and exactly one `https://` origin literal, and the page bundles to the two wasm loaders and a fixed set of non-connect URL literals.",
    status: "partial",
    rationale:
      "Both layers are static or same-realm. The build-time audit proves no unexpected network code ships; it does not prove the runtime stubs cannot be circumvented in a realm we do not control. A runtime assertion suite for the lockdown does not exist yet. The CSP half is browser-enforced and so does not share that weakness -- but it is now only as narrow as `https://api.github.com/users/` in the worker, and CSP does not path-match query strings, which is T-GITHUB-CSP-SCOPE. The audit's URL-literal checks are a change detector, not a proof: a destination assembled at runtime from fragments never appears as a literal.",
    verifiedBy: ["apps/pgp/scripts/audit-network.mjs"],
    section: "§7",
  },
  {
    id: "T-GITHUB-LOOKUP-DISCLOSURE",
    title: "The GitHub lookup tells GitHub who the user is about to encrypt to",
    attacker:
      "GitHub itself, and anyone with access to its request logs or to the network path (the user's ISP, employer, or a state observer of TLS metadata). No compromise of anything is required -- this is the ordinary operation of the feature.",
    defence:
      "None, and none is possible. Asking api.github.com for `/users/<u>/keys` IS the feature. The request discloses the username being looked up, the requester's IP, and the time -- before any message exists.",
    status: "accepted",
    rationale:
      'Stated so a user can calibrate rather than guess. WHAT IS SENT: the username, in the URL path, over TLS. Nothing else -- no message content, no key material, no vault identifier, no extension id, no installation id, no telemetry, and no body (the request is a GET). WHAT IT IS NOT JOINED TO: `network-lockdown.ts` forces `credentials: "omit"` and strips `Cookie` and `Authorization`, and no host permission exists (the endpoint answers unauthenticated CORS with `access-control-allow-origin: *`, measured), so the request does not carry the user\'s GitHub session and cannot be attributed to their account FROM THE REQUEST ALONE. That is a narrower statement than "anonymous" and should not be read as one: it can still be joined on IP address, and it WILL be if the same IP browses github.com while logged in, which for most users it does. Tor, a VPN or a different network are the user\'s tools here, not ours. WHEN IT FIRES: only on an explicit button press in the import UI. Never on a timer, never as a background refresh, never on encrypt, never on unlock, never on install. One press, one request. THE ALTERNATIVE STAYS FIRST-CLASS: pasting an `ssh-ed25519 …` line does exactly the same thing with no network at all, and it is the same code path once the string exists -- the lookup is a convenience that fetches a string the user could have typed. A user who does not want GitHub to learn their correspondents should paste. Accepted rather than partial because there is no partial version: an anonymising proxy would only move the disclosure to whoever runs the proxy, and this project does not run servers. Related in kind to T-FILENAME-METADATA and T-AGE-SSH-STANZA-LINKABLE: contents stay confidential, identity and timing do not.',
    section: "§7, §13",
  },
  {
    id: "T-GITHUB-KEY-SUBSTITUTION",
    title: "GitHub asserts a key; nothing proves it is the right one",
    attacker:
      "GitHub (or an insider there); anyone who compromises the target's GitHub account long enough to add an SSH key; anyone who can mint a publicly-trusted certificate for api.github.com and sit on the path.",
    defence:
      "None cryptographic. `/users/<u>/keys` is an ASSERTION BY GITHUB, not a proof of anything. There is no transparency log, no signature over the response, no certificate pinning, and no out-of-band confirmation. The import preview shows every key's SHA-256 fingerprint before anything is stored, and the resulting contact records `source` so the UI can say where the key came from.",
    status: "accepted",
    rationale:
      'Written down because the failure is silent and the UI is reassuring: a substituted key produces a message that encrypts cleanly, looks correct, and is readable by the attacker. Adding a key to a GitHub account is a normal, unremarkable action that generates no alert the sender will see. THE PREVIEW IS NOT VERIFICATION. Showing the fingerprint before storing only helps a user who already knows the real one; for the common case -- looking up a person precisely because you do NOT have their key -- it is a display of a number with nothing to compare it against, and it must not be read as a check. Nor does the shape of the key help: GitHub strips comments and emails, so the string carries no identity claim beyond the account name in the URL. WHAT `source` DOES AND DOES NOT BUY: it lets the UI distinguish "GitHub said so" from "I verified this myself", which is worth having; it is a provenance label, not a trust decision, and the app ships NO affordance for a user to record an out-of-band verification and upgrade the label. That gap is deliberate rather than overlooked -- a verification affordance is a UX and key-management design problem, and shipping a half-built one that produces a green tick for something nobody checked would be worse than shipping the honest label. Say it plainly rather than let the label imply it. Accepted, not pending: the fixes are TOFU pinning with change alerts, or a real web of trust, and both are features this app has deliberately not taken on (§13 is import-only by design). Distinct from T-GITHUB-UNTRUSTED-PARSE, which is about safely handling the BYTES: parsing them correctly says nothing about whether the key they encode is the right person\'s.',
    section: "§7, §13",
  },
  {
    id: "T-GITHUB-UNTRUSTED-PARSE",
    title: "Attacker-controlled response bytes parsed in the service worker",
    attacker:
      "Anyone who controls what api.github.com returns: a compromised GitHub account choosing the key strings it serves, a TLS interceptor returning an arbitrary body, or a captive portal or proxy substituting HTML for JSON.",
    defence:
      "A deliberately boring parse. `JSON.parse` and nothing else -- no eval, no dynamic import, no Function constructor, no regex over the body beyond a shape check. Hard caps applied before the body is in memory, not merely before the parse: a 15s request deadline, a `Content-Length` pre-check that cancels without reading, and a bounded reader that stops at 64 KiB measured in BYTES (a code-unit count would have admitted up to 3x that). Then 20 keys and 4096 chars per key string, with anything held back counted and surfaced as a refusal rather than dropped silently. Content type must be JSON. Unknown fields are ignored rather than rejected, because GitHub adds fields. Error text from the response never crosses the message boundary -- results are tagged codes, not prose GitHub wrote.",
    status: "defended",
    rationale:
      "Recorded because this is the first time in the app's life that bytes chosen by a remote party are parsed in the service worker, a context with no wasm, no keys and no plaintext but privileged extension APIs. THE INVARIANT THAT KEEPS THE WORKER BORING: the worker is a transport that shape-checks; the wasm engine is the only thing that decides validity. The worker NEVER concludes that a string is a key -- it forwards strings, and every one is re-parsed by `parseSshRecipient` in the panel, the identical path a pasted `.pub` line already takes, before it can become a recipient. A string the engine refuses surfaces as a rejected row carrying the engine's own message. So a key that reaches storage has been through wasm, whatever its source. WHAT THIS DOES NOT CLAIM: nothing here says the key is TRUSTWORTHY. A perfectly well-formed, correctly-parsed, engine-accepted key can still be the attacker's -- that is T-GITHUB-KEY-SUBSTITUTION, and the two entries deliberately do not overlap.",
    verifiedBy: [
      "apps/pgp/lib/github/response.test.ts",
      "apps/pgp/lib/github/username.test.ts",
    ],
    section: "§7, §13",
  },
  {
    id: "T-PENDING-OP-AT-REST",
    title: "The context-menu selection is written to session storage unsealed",
    attacker:
      "Anything that can read `chrome.storage.session`: the extension's own realms (worker, panel, welcome page) under the T-SUPPLY-CHAIN precondition, or DevTools / chrome.debugger (T-DEVTOOLS).",
    defence:
      "Lifetime, not confidentiality. `openPanelWithOperation` writes the raw selection to `SESSION_PENDING_OP`; the panel removes it on read, and `sweepStalePendingOp` (every service-worker start) evicts anything stale or malformed that no panel ever collected.",
    status: "accepted",
    rationale:
      "SEALING WAS CONSIDERED AND REJECTED, for a structural reason rather than a cost trade. The workspace draft solves the same-looking problem by sealing under an in-WASM draft key (T-DRAFT-AT-REST); that is not available here, because the worker has no wasm instance -- its import graph is entirely pure and audit-network.mjs asserts background.js has no module imports. Giving it one would put a session key in the realm T-GITHUB-CSP-SCOPE relies on NOT having one. More decisively, sealing would defend nobody: the worker is the SOURCE of this plaintext (contextMenus.onClicked hands it info.selectionText), so a compromised worker holds the value before it is ever stored, and the only other reader is the panel, which is the intended recipient. Keeping the payload in worker memory and answering a request from the panel was the ORIGINAL design and was removed for cause -- MV3 workers terminate after ~30s idle, so the case that needs the channel most (the panel opening onto a master-unlock screen while the user types a password or completes a WebAuthn ceremony) is exactly the case where the worker is gone; see usePendingOperation's doc comment. WHAT WAS ACTUALLY WRONG, and is fixed: removal depended entirely on the panel mounting to consume the entry, and PENDING_OP_TTL_MS gated whether a stale op was APPLIED, never whether it was STORED. Every path where the panel never mounts -- sidePanel.open rejecting (its rejection is deliberately swallowed), the panel dismissed before its mount effect, a crashed panel realm -- left the selection in session storage for the rest of the browser session, and a malformed value under that key was never removed by anyone. sweepStalePendingOp bounds that to the worker's next wake after the TTL; its removal is guarded by an id re-read, because a cold worker start is usually CAUSED by the context-menu click itself and an unguarded get-then-remove would delete the selection the user just made. WHAT IS NOT CLAIMED: chrome.storage.session is memory-backed and defaults to TRUSTED_CONTEXTS, so this is not a disk-at-rest exposure and content scripts cannot see it -- but neither of those is a defence against the realms above, and neither is offered as one. THE SECOND COPY, now closed. Once the hook consumed the entry the same plaintext also lived in the panel's React state, and doMasterLock released only the storage one -- measured as a live retainer through `property[lastRenderedState] -> property[text]`, T-OUTPUT-HEAP-RESIDUE's class. The leak was not the lock ordering but the CONSUME: usePendingOperation read the entry on mount regardless of what the panel was showing, so an op delivered while the master-unlock screen was up (the case session storage exists to serve) sat in App state for the whole locked window with nothing mounted that could route it. The hook now defers the consume until App is rendering a tree that can act on the op, so the payload waits in session storage -- the exposure this entry already bounds -- rather than in the heap; doMasterLock additionally calls clearPending() for a lock landing between consume and route, and that one line is NOT covered by a red test (stated in its comment). TRADE-OFF ON RECORD: freshness is now judged at consume time, so an unlock slower than PENDING_OP_TTL_MS drops the selection instead of applying it.",
    verifiedBy: [
      "apps/pgp/lib/pending-op.test.ts",
      "apps/pgp/e2e/draft-memory.spec.ts",
    ],
    section: "§7, §8.10",
  },
  {
    id: "T-GITHUB-CSP-SCOPE",
    title: "Widening connect-src for the worker widens it for every realm",
    attacker:
      "Malicious code already running in the background service worker -- the T-SUPPLY-CHAIN precondition, applied to the worker bundle rather than the panel.",
    defence:
      "Two-tier CSP. The manifest's `content_security_policy.extension_pages` is extension-WIDE, so `connect-src 'self' https://api.github.com/users/` reaches the panel too; `sidepanel.html` pulls the panel realm back to `connect-src 'self'` with a `<meta http-equiv=\"Content-Security-Policy\">` tag. Meta CSP can only tighten, never loosen. CSP path-prefix matching is real, not folklore: verified in a real build that `/users/<u>/keys` returns 200 while `/gists` is blocked, and that with the manifest widened the WORKER fetch succeeded while the same fetch from the PANEL failed.",
    status: "partial",
    rationale:
      "IMPORTANT DISTINCTION FROM §8.10: the meta tag is enforced by the browser before any of our JS runs, so it is NOT subject to the same-realm hook problem that limits `network-lockdown.ts`. A compromised panel dependency can unhook the lockdown; it cannot unhook a CSP the browser parsed at document load. THE RESIDUAL, stated because it is real: CSP path-matches the PATH and not the QUERY STRING -- verified that `/users/x/keys?leak=SECRET` is permitted by this policy. So a compromised WORKER bundle could exfiltrate by appending a query string to an allowed `/users/` path. That is inherent to CSP and cannot be closed by a narrower policy. WHAT THE WORKER REALM CAN ACTUALLY REACH, corrected: an earlier version of this entry said the worker holds 'no key material, no wasm instance and no message plaintext -- it is a transport and a context-menu router', and the last third of that was false. The worker has the `storage` permission and it is the ORIGIN of one plaintext, not merely a router of it: `chrome.contextMenus.onClicked` hands it `info.selectionText` (and `info.pageUrl`), and `openPanelWithOperation` writes that selection UNSEALED into `chrome.storage.session` under `SESSION_PENDING_OP`. It can also read every key in `chrome.storage.local`/`sync`: the sealed blobs (`pgp_keyring`, `pgp_public_contacts`, `pgp_settings`, `pgp_crx_keys`, `pgp_history_seg_*`) and the cleartext ones (`pgp_master_protection`, `pgp_preferences`, the `pgp_history` manifest). WHAT GENUINELY BOUNDS IT, as separate facts rather than one sweeping one. (1) No key material and NO WASM INSTANCE -- structural, not assumed: background.ts's import graph is entirely pure, and the build audit asserts `background.js` has no module imports at all, so wasm-bearing code cannot have been split into a chunk the worker loads. No session key means every sealed store above is OPAQUE to it: it can exfiltrate ciphertext, and what stands behind that ciphertext is T-BRUTE-OFFLINE's Argon2id, not this policy. (2) The one plaintext it holds is the one the user just handed it, and its lifetime is now bounded -- see T-PENDING-OP-AT-REST. Sealing that write was considered and rejected: the worker has no key to seal with, and sealing defends a READER whereas the attacker assumed here is the WRITER, who holds the value before it is ever stored. (3) GET only, one origin, one path prefix, and no credentials sent. (4) The panel realm, which does hold key handles and message plaintext, is on `connect-src 'self'` and is unaffected by this allowance. WHAT IS NOT CLAIMED: that the channel is too narrow to matter. A query string is low bandwidth per request but the worker can issue many, so bandwidth is not a bound and is not offered as one -- the most valuable single thing it could send is `pgp_master_protection`, which is cleartext and for the password path is a verifiable offline brute-force oracle (kdfSalt + encryptedCanary). And `scripts/audit-network.mjs` asserts the worker bundle's exact contents: one pinned `fetch` call site, one `https://` origin literal, that origin named in exactly one built file, no module imports (so worker code cannot be hiding in a shared chunk), plus that `host_permissions` and `optional_host_permissions` are both ABSENT and that the meta tag is present in the built `sidepanel.html`. Partial rather than defended because the query-string gap is unfixable at the CSP layer and the audit is a build-time check, not a runtime one.",
    verifiedBy: ["apps/pgp/scripts/audit-network.mjs"],
    section: "§7, §8.10, §13",
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

  {
    id: "T-AGE-SSH-STANZA-LINKABLE",
    title: "An age file names the SSH public key it was encrypted to",
    attacker:
      "Anyone holding an age ciphertext plus a candidate SSH public key -- which for most users is public (`https://github.com/<user>.keys`, `https://gitlab.com/<user>.keys`, an authorized_keys file, a leaked backup).",
    defence:
      "None. The stanza type is chosen by the age format, not by us, and the identifier is what the recipient's own client uses to find its matching key.",
    status: "accepted",
    rationale:
      "Upstream states this plainly rather than us inferring it. age/src/ssh.rs: 'these recipient types are not anonymous: the encrypted message will include a short 32-bit ID of the public key'. The age man page: 'This feature employs more complex cryptography, and should only be used when a native key is not available for the recipient. Note that SSH keys might not be protected long-term by the recipient, since they are revokable when used only for authentication.' So two things are accepted, not one: the ciphertext leaks WHO IT IS FOR to anyone who can test a candidate public key, and the recipient's custody of an authentication key is weaker than that of a dedicated encryption key -- neither is something this app can fix from the sender side. Accepted rather than pending because the alternative is native age recipients (age1...), which are anonymous, and those are deliberately out of scope (§13: SSH keys only, import only). Related in kind to T-FILENAME-METADATA -- both leak recipient identity while the contents stay confidential -- but strictly worse in one respect: a filename can be changed before sharing, and this identifier is inside the ciphertext and survives any renaming, re-armoring or re-transport. A user who needs unlinkability must not use this engine. Worth recording alongside: the ssh-rsa and ssh-ed25519 stanza types are NOT in the C2SP age specification. They are a convention shared by Go age and Rust age, so cross-tool agreement is the only specification there is, which is why age.rs pins vectors from the Go CLI in both directions rather than testing against a spec document.",
    section: "§8.5, §13",
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
      "Someone with read access to `chrome.storage.local` on a locked or unattended device.",
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
      "Anyone who can write chrome.storage.local -- another process on the device, a synced device, or malicious in-realm code -- with NO knowledge of the vault key.",
    defence:
      "FIXED. Every store sealed under the master session -- keyring, contacts, settings, CRX keys, and each history segment -- is sealed for a DOMAIN, and the domain is the chrome.storage key the blob lives under. Both an HKDF-SHA256 subkey and the AEAD's AAD derive from it (`gpg-tools:store-subkey:v1:<key>`, `gpg-tools:store:v1:<key>`), so a blob only opens in the slot it was written to.",
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
      "FIXED. `outputRef` plus the result `<pre>`'s textContent; only the boolean `hasOutput` reaches render state. doMasterLock's `wipe()` clears the ref and the node. The `<pre>` is written imperatively via a callback ref, never as a React child, so the string never enters the fiber element tree. Additionally `wipe()` ZEROIZES the `binaryOutput` and `fileResults` buffers in place: those cannot leave render state (the results card renders a row per file), and a setState at lock time is batched away with the unmount, so dropping the reference is not available and only overwriting the bytes works.",
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
    id: "T-SSH-KEY-MEMORY",
    title: "Imported OpenSSH identity persists in memory after use",
    attacker:
      "Anyone inspecting the JS heap or WASM linear memory after an SSH identity has been unlocked -- including after a lock, when the UI says the key is gone.",
    defence:
      "The normalized (unencrypted) OpenSSH key lives only in SSH_KEY_STORE as Zeroizing<Vec<u8>>, populated solely by unlockSshIdentityWith{Password,Prf} and zeroized on dropSshIdentity / replace. No export in age.rs returns private key material to JS; the key text crosses into JS only on the import path, as the file the user supplied. Locks route through useKeySession's kind-aware dropHandle, and an unlock that resolves after a lock is dropped rather than stored (the lock generation is captured before the await and re-checked before insertion).",
    status: "defended",
    rationale:
      "Verified in the strong present-then-absent form, never absence-only: a 24-character slice of the ed25519 SEED (not the published public half) is FOUND in linear memory while the identity is unlocked, and gone after a per-key lock, after a master lock, and after a vault re-unlock -- each with a liveness re-assert so a zero cannot be a dead scan. The JS heap is clean after import and while unlocked, checked both by raw snapshot count and by retainer-walk. The lock race is covered end to end on the passkey path: a real ceremony is held open, the master lock lands with an EMPTY handle map, the ceremony is then released and observed to complete (so the wasm unlock really ran), and the seed is absent afterwards -- with the same sequence minus the lock asserted to leave the key PRESENT, so the absence cannot be vacuous. WHAT THE EVIDENCE DOES NOT COVER: only ed25519 keys that arrived WITHOUT a source passphrase are exercised, because the needle is derived from the source file's own base64 and that is byte-identical to the normalized form only in that case -- ssh-rsa, and keys whose passphrase is stripped at import, rest on the same code path but on code reading alone. The lock race is driven only on the passkey path (the password path awaits Argon2, which cannot be suspended from outside the wasm call), and only for a MASTER lock. Transient copies age itself makes while decrypting (age::ssh::Identity::from_buffer parses the seed out of the store on every call) are not asserted, and neither is OS paging -- see T-OS-MEMORY.",
    verifiedBy: [
      "apps/pgp/e2e/ssh-memory.spec.ts",
      "apps/pgp/hooks/useKeySession.test.ts",
    ],
    section: "§5, §13",
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
      "Anyone who can open DevTools on our page, or another extension with chrome.debugger.",
    defence: "None.",
    status: "accepted",
    rationale:
      "Equivalent to root on our realm. Also covers other extensions holding chrome.debugger or broad tabs permissions. §8.5, §8.6.",
    section: "§8.5, §8.6",
  },
];
