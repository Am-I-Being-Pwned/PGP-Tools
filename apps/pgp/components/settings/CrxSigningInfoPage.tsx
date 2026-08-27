import { ExternalLinkIcon, ShieldCheckIcon } from "lucide-react";

import { SubPage } from "../shared/SubPage";

/** The four release steps, in order. */
const STEPS: React.ReactNode[] = [
  <>
    Turn on the toggle in Settings, then create or import a CRX signing key
    (RSA-2048). Keep the private key here - export it only if you need a backup.
  </>,
  <>
    Copy the key&rsquo;s <Term>public</Term> half into the Chrome Web Store
    dashboard under <Term>Package &rarr; Verified CRX Uploads</Term>.
  </>,
  <>
    To cut a release, drop your packed extension <Term>.zip</Term> into the
    Workspace and sign it. Use <Term>Save</Term> to write the <Term>.crx</Term>{" "}
    straight to disk with the right name (or drag the chip to your desktop),
    then upload it to the dashboard. Chrome intercepts plain <Term>.crx</Term>{" "}
    downloads and tries to install them, which is why we save rather than
    download.
  </>,
  <>
    To check any extension package, drop a <Term>.crx</Term> into the Workspace
    - PGP Tools verifies its signature and shows the extension ID it claims to
    be.
  </>,
];

/** Where this scheme sits between the weaker and stronger alternatives,
 *  weakest first. */
const LADDER: React.ReactNode[] = [
  <>
    <Term>A key in CI secrets</Term> is weaker: a poisoned dependency or a
    leaked token walks away with it.
  </>,
  <>
    <Term>A key encrypted in your vault</Term> - where you are - sits behind
    your password or passkey and is unlocked only for the signing act.
  </>,
  <>
    <Term>A hardware token (YubiKey / HSM)</Term> is stronger still: the key
    never leaves the chip, whereas here it is briefly reconstructed in the WASM
    sandbox during signing and zeroized immediately after.
  </>,
];

/** Inline emphasis for literals and UI labels inside the body copy. */
function Term({ children }: { children: React.ReactNode }) {
  return <span className="font-medium">{children}</span>;
}

/** Dash-led lines. Plain hyphens in their own column, so a wrapped line
 *  stays aligned under the text rather than under the dash. */
function DashList({ items }: { items: React.ReactNode[] }) {
  return (
    <ul className="space-y-1.5">
      {items.map((item, i) => (
        <li key={i} className="flex gap-2">
          <span aria-hidden="true">-</span>
          <span className="min-w-0 leading-relaxed">{item}</span>
        </li>
      ))}
    </ul>
  );
}

/** A titled block of explainer copy. */
function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-2">
      <h3 className="text-foreground font-semibold">{title}</h3>
      {children}
    </section>
  );
}

interface CrxSigningInfoPageProps {
  onClose: () => void;
}

/**
 * Explainer subpage for CRX (Chrome extension) signing. Pure content - no
 * key material, no actions. The signing/verifying itself happens in the
 * Workspace via the normal drop-a-file flow.
 */
export function CrxSigningInfoPage({ onClose }: CrxSigningInfoPageProps) {
  return (
    <SubPage title="CRX signing" onClose={onClose} bodyClassName="px-5 py-4">
      <div className="text-foreground/75 space-y-5 text-sm">
        {/* The pitch, given the weight of a card: it is the one thing to
            read if the user reads nothing else on the page. */}
        <section className="border-border flex gap-2.5 rounded-md border p-3">
          <ShieldCheckIcon className="text-primary mt-0.5 size-4 shrink-0" />
          <div className="space-y-2">
            <p className="text-foreground font-semibold">
              Verified CRX Uploads
            </p>
            <p className="leading-relaxed">
              The Chrome Web Store lets you require that every update to your
              extension is signed with a key only you hold. Even if someone
              compromises your Web Store account or your build pipeline, they
              still can&rsquo;t ship a malicious update without your signing
              key.
            </p>
            <p className="leading-relaxed">
              That only holds if the key lives somewhere an attacker can&rsquo;t
              reach - a key sitting in CI secrets defeats the purpose. PGP Tools
              keeps it encrypted in your vault and unlocks it only for the
              signing act, behind your password or passkey, never in your
              pipeline.
            </p>
          </div>
        </section>

        <Section title="How to use it">
          <DashList items={STEPS} />
        </Section>

        <Section title="What you get out of it">
          <p className="leading-relaxed">
            This <Term>.crx</Term> is an upload artifact for the Web Store
            dashboard, not a directly-installable package - Chrome only installs
            store-signed extensions. To run your extension locally, use{" "}
            <Term>Load unpacked</Term> on the folder.
          </p>
        </Section>

        <Section title="Where this sits security-wise">
          <DashList items={LADDER} />
        </Section>

        <Section title="This is not PGP">
          <p className="leading-relaxed">
            A <Term>.crx</Term> is signed with a raw RSA-2048 key
            (PKCS#1-SHA256), not an OpenPGP signature. PGP Tools generates and
            stores this key with the same protection as your PGP keys (Argon2id
            or passkey &rarr; AES-256-GCM, all inside the WASM sandbox), but the
            key itself is separate and used only for CRX signing.
          </p>
        </Section>

        <a
          href="https://developer.chrome.com/docs/webstore/update#protect-package-updates"
          target="_blank"
          rel="noopener noreferrer"
          className="border-border hover:border-muted-foreground/40 flex items-center justify-between gap-2 rounded-md border px-3 py-2.5 transition-colors"
        >
          <span>Chrome Web Store: protecting package updates</span>
          <ExternalLinkIcon className="text-muted-foreground size-4 shrink-0" />
        </a>
      </div>
    </SubPage>
  );
}
