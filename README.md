# PGP Tools

A security-first browser extension for PGP encryption, decryption, and signing. Built with Rust/WebAssembly and designed so your private keys never touch the JavaScript heap (unless it's unavoidable).

## Why PGP Tools?

### UX

Existing PGP tools don't generally have great UX, they're commonly terminal based and the existing extension based ones are not opensource and transparent.
Would you really want to rely on a closed source tool for encrypting information secret enough to be worthy of encrypting?

### Private keys stay in WASM, not JavaScript

Most browser PGP tools run crypto in JavaScript, leaving your private keys on the JS heap where they can't be deterministically wiped - the GC decides when memory is freed, and even then the bytes aren't zeroed. If the browser crashes or a memory dump is taken, anything on the heap is captured as plaintext. PGP Tools runs all cryptographic operations inside a Rust/WebAssembly sandbox powered by [Sequoia-PGP](https://sequoia-pgp.org/). During normal operations (encrypt, decrypt, sign), JavaScript only holds an opaque integer handle to your key - the actual key material lives in WASM linear memory and is zeroized on drop using the `zeroize` crate. Private key material does briefly pass through JS during initial key generation and import, before it is encrypted and stored.

### Unlock keys with passkeys instead of passwords

PGP Tools supports **WebAuthn PRF** for key protection. Unlock your private keys with Touch ID, Face ID, Windows Hello, or a YubiKey - no password to remember if you don't want to, phishing-resistant by design. The PRF output is combined with a stored secret via HKDF-SHA256 to derive an AES-256-GCM encryption key, and the entire unlock flow runs inside WASM so the decrypted key never crosses into JavaScript.

### GPU-resistant password protection

If you prefer passwords, keys are protected with **Argon2id** (64 MB memory, 3 iterations) - not PBKDF2. This makes brute-force attacks orders of magnitude harder, especially on GPUs. The KDF runs in WASM, derives the AES-256-GCM key, decrypts the private key, and zeroizes all intermediates before returning a handle. Your password bytes are zeroed on both the JS and WASM sides immediately after use.

### Atomic decrypt + verify

Most PGP tools decrypt first, then verify the signature as a separate step. This creates a TOCTOU (time-of-check-time-of-use) window where you might read tampered plaintext before the signature check fails. PGP Tools returns the plaintext and signature verification result atomically in a single packed binary response - if the signature is bad, you never see the plaintext.

### Zeroization everywhere

Sensitive data is actively scrubbed from memory after use:

- **Rust side**: `zeroize` crate on all `StoredKey` structs, derived keys, and decrypted plaintext
- **JavaScript side**: `Uint8Array.fill(0)` on password bytes, PRF outputs, and derived keys immediately after use
- **No GC dependence**: WASM memory is not garbage-collected, so zeroization is deterministic

### Auto-lock and session management

- Configurable inactivity timeout (5, 15, 30, or 60 minutes)
- Lock all keys instantly when the side panel closes
- Never-cache mode for high-security environments (locks after every operation)
- Exponential backoff on failed password attempts (capped at 30s)

### Per-key authenticated encryption

Every private key is individually encrypted with AES-256-GCM using Additional Authenticated Data (AAD) bound to the key's fingerprint. This prevents an attacker from swapping encrypted blobs between keys - decryption fails if the ciphertext is moved to a different key slot.

## Features

- Generate ECC (Cv25519) or RSA-4096 key pairs
- Encrypt to multiple recipients with optional signing
- Decrypt with automatic signature verification
- Cleartext sign and verify messages
- Import/export armored keys
- Contact and key management
- Right-click context menu for encrypt/decrypt/sign/verify on selected text
- Auto-detect and decrypt PGP-encrypted downloads
- Auto-import public keys from `.asc` file downloads
- Optional Chrome sync storage (end-to-end encrypted by Chrome) or local-only

## Stack

- **PGP engine**: Rust ([Sequoia-PGP](https://sequoia-pgp.org/)) compiled to WebAssembly
- **Extension framework**: [WXT](https://wxt.dev/) + React + Tailwind
- **Key protection**: WebAuthn PRF (passkeys) or Argon2id (passwords)
- **Encryption at rest**: AES-256-GCM with per-key AAD
- **UI components**: shadcn/ui

## Requirements

- Node ^22.21.0
- pnpm ^10.19.0
- [Rust toolchain](https://rustup.rs/) + [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (for building the WASM module)

## Setup

```bash
pnpm install
```

## Development

```bash
pnpm dev
```

This starts the WXT dev server with hot reload. The extension will be loaded in Chrome automatically.

### Building the WASM module

The WASM module must be built from source before first use:

```bash
cd apps/pgp && pnpm build:wasm
```

This is done automatically by `pnpm build`.

## Build

```bash
pnpm build
```

## Package for distribution

```bash
pnpm zip
```

Produces a zip file ready for Chrome Web Store / Firefox Add-ons upload.

## Project structure

```
apps/pgp/              Extension source
  components/           React UI components
  entrypoints/          WXT entry points (background, sidepanel)
  hooks/                React hooks (keyring, sessions, contacts)
  lib/
    pgp/                WASM wrapper and PGP operations
    protection/         Key encryption (WebAuthn PRF, Argon2id, AES-256-GCM)
    storage/            Keyring persistence (chrome.storage with mutex)
  gpg-wasm/             Rust/WASM PGP engine (sequoia-openpgp)
  public/               Extension assets
packages/ui/            shadcn/ui component library
tooling/                Shared ESLint, Prettier, Tailwind, TypeScript configs
```

## Security model

| Layer            | Mechanism                                               |
| ---------------- | ------------------------------------------------------- |
| Crypto engine    | Sequoia-PGP in WASM (keys in JS only during gen/import) |
| Key unlock       | WebAuthn PRF (passkeys) or Argon2id 64 MB (passwords)   |
| Key storage      | AES-256-GCM with per-key AAD                            |
| Memory hygiene   | `zeroize` crate (Rust) + manual zeroing (JS)            |
| Signature safety | Atomic decrypt+verify (no TOCTOU)                       |
| Session          | Auto-lock on inactivity, panel close, or per-operation  |
| Brute-force      | Exponential backoff on failed unlocks                   |
| Extension scope  | No content scripts - runs entirely in extension sandbox |

## AI disclosure

This project was built with significant AI assistance (Claude 4.6). The UI components, React plumbing, storage layer, extension wiring, and general boilerplate were largely AI-generated or AI-assisted.

The cryptographic implementations - the Rust/WASM engine, key protection schemes, WebAuthn PRF integration, and Argon2id KDF configuration - were **human-designed and human-reviewed**.
We don't trust vibes-based crypto.

## License

MIT
