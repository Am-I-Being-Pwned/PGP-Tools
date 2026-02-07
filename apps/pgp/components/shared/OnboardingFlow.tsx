import { useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { StorageLocation } from "../../lib/storage/preferences";
import { savePreferences } from "../../lib/storage/preferences";
import { StorageLocationPicker } from "./StorageLocationPicker";

interface OnboardingFlowProps {
  onComplete: (storageLocation: StorageLocation) => void;
  onGenerateKey: () => void;
}

export function OnboardingFlow({
  onComplete,
  onGenerateKey,
}: OnboardingFlowProps) {
  const [location, setLocation] = useState<StorageLocation>("local");

  const finish = async (generateKey: boolean) => {
    await savePreferences({
      storageLocation: location,
      onboardingComplete: true,
    });
    onComplete(location);
    if (generateKey) setTimeout(onGenerateKey, 100);
  };

  return (
    <div className="flex h-full flex-col justify-between p-4">
      <div className="space-y-5">
        <div>
          <h1 className="text-lg font-semibold">PGP Tools</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Send private messages that only the right person can read, and
            verify messages really came from who they claim.
          </p>
        </div>

        <div>
          <h2 className="mb-2 text-sm font-semibold">
            Where should we store your data?
          </h2>
          <StorageLocationPicker value={location} onChange={setLocation} />
        </div>
      </div>

      <div className="space-y-2 pt-4">
        <Button className="w-full" onClick={() => finish(true)}>
          Create my identity
        </Button>
        <Button
          variant="outline"
          className="w-full"
          onClick={() => finish(false)}
        >
          I'll set up later
        </Button>
        <p className="text-muted-foreground text-center text-xs">
          A privacy tool by{" "}
          <a
            href="https://amibeingpwned.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary underline"
          >
            Am I Being Pwned
          </a>
        </p>
      </div>
    </div>
  );
}
