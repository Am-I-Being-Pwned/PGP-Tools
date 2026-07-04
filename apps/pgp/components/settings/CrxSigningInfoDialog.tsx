import { Dialog } from "../shared/Dialog";

interface CrxSigningInfoDialogProps {
  open: boolean;
  onClose: () => void;
}

/**
 * Explainer subpage for CRX (Chrome extension) signing. Pure content - no
 * key material, no actions. The signing/verifying itself happens in the
 * Workspace via the normal drop-a-file flow.
 */
export function CrxSigningInfoDialog({
  open,
  onClose,
}: CrxSigningInfoDialogProps) {
  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="CRX signing"
      className="mx-4 max-h-[80vh] max-w-lg overflow-y-auto"
    >
      <div className="space-y-4 text-sm">
        <section className="space-y-1.5">
          <p className="text-muted-foreground text-xs leading-relaxed">
            The Chrome Web Store lets you require that every update to your
            extension is signed with a key only you hold - Google calls this{" "}
            <span className="text-foreground">Verified CRX Uploads</span>. It
            means that even if someone compromises your Web Store account or
            your build pipeline, they still can&rsquo;t ship a malicious update
            without your signing key.
          </p>
          <p className="text-muted-foreground text-xs leading-relaxed">
            The catch: that only works if the key lives somewhere an attacker
            can&rsquo;t reach. A key sitting in CI secrets defeats the purpose.
            PGP Tools keeps the key encrypted in your vault and unlocks it only
            for the signing act - behind your password or passkey, never in
            your pipeline.
          </p>
        </section>

        <section className="space-y-1.5">
          <h3 className="text-foreground text-xs font-semibold">
            This is not PGP
          </h3>
          <p className="text-muted-foreground text-xs leading-relaxed">
            A <span className="text-foreground">.crx</span> is signed with a raw
            RSA-2048 key (PKCS#1-SHA256), not an OpenPGP signature. PGP Tools
            generates and stores this key with the same protection as your PGP
            keys (Argon2id or passkey → AES-256-GCM, all inside the WASM
            sandbox), but the key itself is separate and used only for CRX
            signing.
          </p>
        </section>

        <section className="space-y-2">
          <h3 className="text-foreground text-xs font-semibold">How to use it</h3>
          <ol className="text-muted-foreground list-decimal space-y-1.5 pl-4 text-xs leading-relaxed">
            <li>
              Turn on the toggle above, then create or import a CRX signing key
              (RSA-2048). Keep the private key here - export it only if you need
              a backup.
            </li>
            <li>
              Copy the key&rsquo;s <span className="text-foreground">public</span>{" "}
              half and register it in the Chrome Web Store dashboard under{" "}
              <span className="text-foreground">
                Package → Verified CRX Uploads
              </span>
              .
            </li>
            <li>
              To cut a release, drop your packed extension{" "}
              <span className="text-foreground">.zip</span> into the Workspace.
              PGP Tools unlocks the key, signs it into a{" "}
              <span className="text-foreground">.crx</span>, and hands it back to
              download. Upload that .crx to the Web Store.
            </li>
            <li>
              To check any extension package, drop a{" "}
              <span className="text-foreground">.crx</span> into the Workspace -
              PGP Tools verifies its signature and shows the extension ID it
              claims to be.
            </li>
          </ol>
        </section>

        <section className="space-y-1.5">
          <h3 className="text-foreground text-xs font-semibold">
            Where this sits security-wise
          </h3>
          <p className="text-muted-foreground text-xs leading-relaxed">
            Stronger than a key in CI (which a poisoned dependency or leaked
            token would expose) because the key is encrypted at rest and gated
            behind your password/passkey. A dedicated hardware token (YubiKey /
            HSM) is stronger still - there the key never leaves the chip,
            whereas here it is briefly reconstructed in the WASM sandbox during
            signing and zeroized immediately after.
          </p>
        </section>

        <a
          href="https://developer.chrome.com/docs/webstore/update#protect-package-updates"
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary inline-block text-xs underline"
        >
          Chrome Web Store: protecting package updates ↗
        </a>
      </div>
    </Dialog>
  );
}
