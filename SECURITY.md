# Security Policy

PGP Tools handles private key material, so we take security reports seriously and appreciate responsible disclosure.

## Supported versions

Only the latest release published on the [Chrome Web Store](https://chromewebstore.google.com/detail/pgp-tools-encrypt-decrypt/pgpcdgggohpbombhkffjoiiafdlfcpgp) (and the current `main` branch) receive security fixes. Older versions are not supported.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately via one of:

- **GitHub**: [Report a vulnerability](https://github.com/Am-I-Being-Pwned/PGP-Tools/security/advisories/new) (preferred)

Include as much of the following as you can:

- A description of the vulnerability and its impact
- Steps to reproduce (a minimal PoC is ideal)
- Affected version / commit and browser
- Any suggested fix

You can expect an acknowledgement within **72 hours** and a status update at least every **7 days** until resolution. We aim to ship fixes for confirmed vulnerabilities within **90 days**, usually much sooner. We'll credit you in the release notes and advisory unless you prefer to remain anonymous.

## Scope

Reports we especially care about:

- Private key or plaintext exposure (key material leaking to the JS heap, storage, logs, or other extensions/pages)
- Flaws in the unlock flows (WebAuthn PRF, Argon2id KDF, AES-256-GCM key storage, per-key AAD binding)
- Signature verification bypasses, including anything that breaks the atomic decrypt+verify guarantee
- Zeroization failures (key material persisting in WASM or JS memory after use)
- Sandbox or extension-isolation escapes, message-passing vulnerabilities between extension contexts
- Weaknesses in the encrypted backup format

Out of scope:

- Vulnerabilities requiring a compromised browser, OS, or physical access to an unlocked device
- Issues in upstream dependencies (e.g. Sequoia-PGP, Chromium) without a PGP Tools-specific exploit — report those upstream
- Social engineering, phishing, or issues in third-party websites the extension is used on
- Missing hardening without a demonstrable exploit path
- Denial of service against the user's own extension instance

## Disclosure

Please keep reports confidential until a fix is released. We'll coordinate a disclosure date with you and publish a GitHub security advisory once users have had a reasonable window to update (extension updates roll out automatically via the Web Store, so this is typically short).
