import { useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { PublicContactKey } from "../../lib/storage/contacts";
import { IMPORT_SCENARIOS } from "../../lib/dev/import-fixtures";
import { ContactCard } from "../keys/ContactCard";
import { ImportPreviewPage } from "../keys/ImportPreviewPage";
import { SubPage } from "../shared/SubPage";

/**
 * DEV-ONLY harness for the key-import flow: every state of the preview
 * panel, plus the just-imported card highlight, driven by placeholder
 * data (lib/dev/import-fixtures) rather than real certificates.
 *
 * It exists so the flow can be reviewed and adjusted before the parsing
 * and storage half is wired up. Gated behind `import.meta.env.DEV` at
 * both call sites, so it is tree-shaken out of production builds.
 */

const DEMO_CONTACT: PublicContactKey = {
  keyId: "3A9E1F5C7B2D48E6A0C1938574FD62B0E4A75C11",
  userIds: ["Alice Example <alice@example.com>"],
  algorithm: "ed25519",
  armoredPublicKey: "",
  addedAt: Date.UTC(2026, 7, 23),
  lastUsedAt: Date.UTC(2026, 7, 23),
  expiresAt: null,
  usableForEncryption: true,
};

export function ImportFlowPreviewPage({ onClose }: { onClose: () => void }) {
  const [scenario, setScenario] = useState<string | null>(null);
  // Toggled off and back on so the CSS animation re-runs on each press.
  const [pulse, setPulse] = useState(false);

  const active = IMPORT_SCENARIOS.find((s) => s.id === scenario) ?? null;

  const replayPulse = () => {
    setPulse(false);
    requestAnimationFrame(() => setPulse(true));
  };

  return (
    <>
      <SubPage
        title="Import flow states"
        onClose={onClose}
        actions={[{ type: "outline", text: "Done" }]}
      >
        <div className="space-y-4 p-3">
          <p className="text-muted-foreground text-xs">
            Placeholder data - no parsing or storage is wired up yet. Each row
            opens the preview panel in that state.
          </p>

          <div className="space-y-2">
            {IMPORT_SCENARIOS.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => setScenario(s.id)}
                className="border-border hover:bg-muted/40 w-full rounded-md border p-3 text-left transition-colors"
              >
                <p className="text-sm font-medium">{s.label}</p>
                <p className="text-muted-foreground mt-0.5 text-xs">{s.hint}</p>
              </button>
            ))}
          </div>

          <div>
            <h3 className="mb-2 text-xs font-semibold">
              Just-imported highlight
            </h3>
            <p className="text-muted-foreground mb-2 text-xs">
              What the list does after the panel slides away: the card scrolls
              into view and pulses once.
            </p>
            <ContactCard contact={DEMO_CONTACT} justImported={pulse} readOnly />
            <Button
              variant="outline"
              size="sm"
              className="mt-2 w-full"
              onClick={replayPulse}
            >
              Replay highlight
            </Button>
          </div>
        </div>
      </SubPage>

      {active && (
        <ImportPreviewPage
          incoming={active.incoming}
          onConfirm={() => setScenario(null)}
          onBack={() => setScenario(null)}
        />
      )}
    </>
  );
}
