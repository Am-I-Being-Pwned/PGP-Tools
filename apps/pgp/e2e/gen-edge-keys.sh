#!/usr/bin/env bash
# Regenerate e2e/edge-keys.ts: "wild and whacky" real-world key fixtures --
# expired, revoked, multi-UID, RSA-4096, passphrase-protected, offline-primary
# (stripped secret), refreshed (extended expiry), binary export, and a
# bidi-override user ID. Companion to gen-keys.sh (happy-path fixtures).
# Run from apps/pgp:
#   ./e2e/gen-edge-keys.sh
# Requires gpg (2.4+) and python3. No faketime needed: gpg's own
# --faked-system-time generates the already-expired key.
set -euo pipefail
cd "$(dirname "$0")/.."

export GNUPGHOME="$(mktemp -d)"
trap 'rm -rf "$GNUPGHOME"' EXIT
OUT="$GNUPGHOME/out"
mkdir -p "$OUT"

MSG="The quick brown fox jumps over the lazy dog."
# Frozen clock for the expired key: generated mid-2023 with 1y validity,
# so it has been dead since mid-2024 regardless of when this reruns.
PAST="20230601T120000!"
PASS="super secret passphrase 42"

G(){ gpg --batch --pinentry-mode loopback "$@"; }
fpr(){ gpg --list-keys --with-colons "$1" 2>/dev/null | awk -F: '/^fpr:/{print $10;exit}'; }

# -- expired: generated in the (faked) past, 1y validity, long dead now.
#    Its signed message is also made at the faked time, while still valid.
G --passphrase '' --faked-system-time "$PAST" \
  --quick-generate-key "Xavier Expired <xavier@expired.example>" default default 1y >/dev/null 2>&1
EXPIRED=$(fpr xavier@expired.example)
printf '%s' "$MSG" | G --passphrase '' --faked-system-time "$PAST" \
  --clearsign -u "$EXPIRED" > "$OUT/expired.sig.asc" 2>/dev/null

# -- revoked: generated live, signs a message while valid, THEN revoked by
#    importing the revocation cert gpg auto-writes at generation time
#    (openpgp-revocs.d/<FPR>.rev, guarded by a leading colon we strip).
G --passphrase '' \
  --quick-generate-key "Rita Revoked <rita@revoked.example>" default default 1y >/dev/null 2>&1
REVOKED=$(fpr rita@revoked.example)
printf '%s' "$MSG" | G --passphrase '' --clearsign -u "$REVOKED" > "$OUT/revoked.sig.asc" 2>/dev/null
sed 's/^://' "$GNUPGHOME/openpgp-revocs.d/$REVOKED.rev" | G --import >/dev/null 2>&1

# -- multi-UID: a work UID plus a personal UID on one cert.
G --passphrase '' \
  --quick-generate-key "Mallory Multi <mallory@work.example>" default default 1y >/dev/null 2>&1
MULTIUID=$(fpr mallory@work.example)
G --passphrase '' --quick-add-uid "$MULTIUID" "Mallory Multi <mallory@home.example>" >/dev/null 2>&1

# -- rsa4096: the extension's own non-ECC generate suite; quick-gen makes
#    the RSA primary sign-only, so add the encryption subkey explicitly.
G --passphrase '' \
  --quick-generate-key "Rachel Rsa4096 <rachel@rsa4096.example>" rsa4096 default 1y >/dev/null 2>&1
RSA4096=$(fpr rachel@rsa4096.example)
G --passphrase '' --quick-add-key "$RSA4096" rsa4096 encr 1y >/dev/null 2>&1

# -- protectedPrivate: a private key whose secret material is S2K-encrypted
#    under a source passphrase (the classic "exported from GnuPG" shape).
G --passphrase "$PASS" \
  --quick-generate-key "Petra Protected <petra@protected.example>" default default 1y >/dev/null 2>&1
PROTECTED=$(fpr petra@protected.example)

# -- offlinePrimary: secret subkeys only, primary secret stubbed out
#    (gpg --export-secret-subkeys), the offline-primary-key workflow.
G --passphrase "$PASS" \
  --quick-generate-key "Oscar Offline <oscar@offline.example>" default default 1y >/dev/null 2>&1
OFFLINE=$(fpr oscar@offline.example)

# -- refreshed: the same cert exported twice -- v1 with a 1y expiry, then
#    the expiry extended to 3y and exported again (same fingerprint).
#    Models a contact refreshing their key before it lapses.
G --passphrase '' \
  --quick-generate-key "Ursula Update <ursula@update.example>" default default 1y >/dev/null 2>&1
REFRESHED=$(fpr ursula@update.example)
gpg --armor --export "$REFRESHED" > "$OUT/refreshed.v1.asc"
gpg --list-keys --with-colons "$REFRESHED" | awk -F: '/^pub:/{print $7}' > "$OUT/refreshed.v1.expires"
G --passphrase '' --quick-set-expire "$REFRESHED" 3y >/dev/null 2>&1

# -- binary: a normal key exported WITHOUT --armor (raw OpenPGP packets),
#    the .gpg file shape the import file-picker claims to accept.
G --passphrase '' \
  --quick-generate-key "Bianca Binary <bianca@binary.example>" default default 1y >/dev/null 2>&1
BINARY=$(fpr bianca@binary.example)
gpg --export "$BINARY" > "$OUT/binary.pub.gpg"

# -- bidiUid: a user ID carrying a U+202E RIGHT-TO-LEFT OVERRIDE that makes
#    "eve@bidi.example" render as a different, benign-looking address --
#    the display-spoofing probe. gpg may refuse exotic UIDs; tolerated.
BIDI_NAME="$(printf 'Eve \xe2\x80\xaemoc.doog@ecila\xe2\x80\xac Bidi')"
G --passphrase '' \
  --quick-generate-key "$BIDI_NAME <eve@bidi.example>" default default 1y >/dev/null 2>&1 || true
BIDI=$(fpr eve@bidi.example || true)

python3 - "$MSG" "$OUT" "$PASS" << 'PYEOF'
import base64, json, subprocess, sys, os

msg, out, source_pass = sys.argv[1], sys.argv[2], sys.argv[3]

def run(*args, binary=False, inp=None):
    r = subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", *args],
                       capture_output=True, input=inp)
    return r.stdout if binary else r.stdout.decode()

# Group the full listing into fpr -> {uids, expires} (primary key line).
listing = run("--list-keys", "--with-colons")
certs = {}
cur = None
for line in listing.splitlines():
    f = line.split(":")
    if f[0] == "pub":
        cur = {"expires": int(f[6]) if f[6] else None, "uids": [], "fpr": None}
    elif f[0] == "fpr" and cur is not None and cur["fpr"] is None:
        cur["fpr"] = f[9]
        certs[f[9]] = cur
    elif f[0] == "uid" and cur is not None:
        cur["uids"].append(f[9])

def by_email(email):
    for c in certs.values():
        if any(email in u for u in c["uids"]):
            return c
    return None

def pub(fpr): return run("--armor", "--export", fpr)
def sign(fpr): return run("--passphrase", "", "--clearsign", "-u", fpr,
                          inp=msg.encode())
def readf(name, binary=False):
    with open(os.path.join(out, name), "rb" if binary else "r") as fh:
        return fh.read()

rows = {}

def add(slug, cert, description, **extra):
    if cert is None:
        print(f"warning: fixture {slug} missing (gpg refused?), skipped",
              file=sys.stderr)
        return
    rows[slug] = {
        "slug": slug,
        "description": description,
        "uids": cert["uids"],
        "fingerprint": cert["fpr"],
        "publicKey": pub(cert["fpr"]),
        "expiresAt": cert["expires"] * 1000 if cert["expires"] else None,
        **extra,
    }

add("expired", by_email("xavier@expired.example"),
    "cert generated 2023 with 1y validity -- expired since mid-2024",
    signedMessage=readf("expired.sig.asc"))

add("revoked", by_email("rita@revoked.example"),
    "cert revoked by its own revocation certificate",
    signedMessage=readf("revoked.sig.asc"))

add("multiUid", by_email("mallory@work.example"),
    "one cert, two user IDs (work + personal email)")

add("rsa4096", by_email("rachel@rsa4096.example"),
    "RSA-4096 primary with RSA-4096 encryption subkey",
    signedMessage=sign(by_email("rachel@rsa4096.example")["fpr"]))

petra = by_email("petra@protected.example")
add("protectedPrivate", petra,
    "private key S2K-encrypted under a source passphrase",
    privateKey=run("--passphrase", source_pass, "--armor",
                   "--export-secret-keys", petra["fpr"]),
    passphrase=source_pass)

oscar = by_email("oscar@offline.example")
add("offlinePrimary", oscar,
    "secret subkeys only -- primary secret stubbed (offline-primary workflow)",
    privateKey=run("--passphrase", source_pass, "--armor",
                   "--export-secret-subkeys", oscar["fpr"]),
    passphrase=source_pass)

ursula = by_email("ursula@update.example")
v1_expires = int(readf("refreshed.v1.expires").strip())
add("refreshed", ursula,
    "same cert exported at 1y expiry (publicKey= v1) then extended to 3y "
    "(publicKeyUpdated)")
if "refreshed" in rows:
    rows["refreshed"].update(
        publicKey=readf("refreshed.v1.asc"),
        expiresAt=v1_expires * 1000,
        publicKeyUpdated=pub(ursula["fpr"]),
        updatedExpiresAt=ursula["expires"] * 1000 if ursula["expires"] else None)

add("binary", by_email("bianca@binary.example"),
    "raw (non-armored) OpenPGP export, the .gpg file shape",
    publicKeyBinaryB64=base64.b64encode(readf("binary.pub.gpg", binary=True)).decode())

add("bidiUid", by_email("eve@bidi.example"),
    "user ID containing U+202E RIGHT-TO-LEFT OVERRIDE (display spoofing probe)")

L = ['// AUTO-GENERATED by e2e/gen-edge-keys.sh -- do not edit by hand.',
     '// Adversarial / real-world "weird key" fixtures: expired, revoked,',
     '// multi-UID, RSA-4096, passphrase-protected, offline-primary,',
     '// refreshed-expiry, binary export, and bidi-override user IDs.', '',
     'export interface EdgeKey {',
     '  slug: string;',
     '  description: string;',
     '  /** Every user ID on the cert, in gpg listing order. */',
     '  uids: string[];',
     '  fingerprint: string;',
     '  /** Armored public key (for `refreshed`, the SHORT-expiry v1). */',
     '  publicKey: string;',
     '  /** Primary key expiry in epoch ms, or null for no expiry. */',
     '  expiresAt: number | null;',
     '  /** Cleartext-signed copy of MESSAGE (made while the key was valid). */',
     '  signedMessage?: string;',
     '  /** Armored private key (S2K-protected under `passphrase`). */',
     '  privateKey?: string;',
     '  passphrase?: string;',
     '  /** `refreshed` only: the same cert re-exported with a 3y expiry. */',
     '  publicKeyUpdated?: string;',
     '  updatedExpiresAt?: number;',
     '  /** `binary` only: raw non-armored export, base64 for transport. */',
     '  publicKeyBinaryB64?: string;',
     '}', '',
     f'export const MESSAGE = {json.dumps(msg)};', '',
     'export const EDGE_KEYS: Record<string, EdgeKey> = {']
order = ["expired", "revoked", "multiUid", "rsa4096", "protectedPrivate",
         "offlinePrimary", "refreshed", "binary", "bidiUid"]
for slug in order:
    if slug not in rows:
        continue
    d = rows[slug]
    L.append(f'  {slug}: {{')
    for key, val in d.items():
        L.append(f'    {key}: {json.dumps(val)},')
    L.append('  },')
L += ['};', '',
      '/** Look up an edge fixture by slug (throws if missing). */',
      'export function edgeKey(slug: string): EdgeKey {',
      '  const key = Object.values(EDGE_KEYS).find((k) => k.slug === slug);',
      '  if (!key) throw new Error(`No edge key with slug "${slug}"`);',
      '  return key;', '}', '']
open("e2e/edge-keys.ts", "w").write("\n".join(L))
print("wrote e2e/edge-keys.ts with", len(rows), "fixtures:", ", ".join(rows))
PYEOF
