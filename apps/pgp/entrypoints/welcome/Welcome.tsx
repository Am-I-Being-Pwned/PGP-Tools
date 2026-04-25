import { useState } from "react";
import { ArrowRightIcon, LockKeyholeIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

export function Welcome() {
  const [opened, setOpened] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleStart = async () => {
    setError(null);
    try {
      // Must run in this user-gesture handler -- chrome.sidePanel.open
      // requires one. We can't do this from background's `onInstalled`,
      // hence this welcome page.
      const win = await chrome.windows.getCurrent();
      if (win.id === undefined) {
        throw new Error("No window id");
      }
      await chrome.sidePanel.open({ windowId: win.id });
      setOpened(true);
    } catch (e) {
      setError(
        e instanceof Error
          ? e.message
          : "Could not open the side panel. Click the PGP Tools icon in your toolbar.",
      );
    }
  };

  if (opened) {
    return (
      <div className="flex min-h-screen items-center justify-end p-12">
        <div className="flex max-w-md items-center gap-6 text-right">
          <p className="text-2xl font-medium leading-snug">
            Follow the instructions in the side panel to get started
          </p>
          <ArrowRightIcon className="text-primary h-16 w-16 shrink-0" />
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-6 text-center">
        <div className="bg-primary/10 mx-auto flex h-16 w-16 items-center justify-center rounded-full">
          <LockKeyholeIcon className="text-primary h-8 w-8" />
        </div>

        <div>
          <h1 className="text-xl font-semibold">PGP Tools is installed</h1>
          <p className="text-muted-foreground mt-2 text-sm">
            Click below to open the side panel and finish setting up your
            keys. After this, use the PGP Tools icon in the toolbar to
            re-open it any time.
          </p>
        </div>

        <Button className="w-full" onClick={() => void handleStart()}>
          Click here to get started
        </Button>

        {error && (
          <p className="text-destructive text-xs" role="alert">
            {error}
          </p>
        )}

        <p className="text-muted-foreground text-xs">
          A privacy tool by{" "}
          <a
            href="https://amibeingpwned.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary underline"
          >
            Am I Being Pwned
          </a>
          .
        </p>
      </div>
    </div>
  );
}
