import { useState } from "react";
import { ArrowRightIcon, LockKeyholeIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import { t } from "../../lib/i18n";

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
      setError(e instanceof Error ? e.message : t("app_welcome_open_failed"));
    }
  };

  if (opened) {
    return (
      <div className="flex min-h-screen items-center justify-end p-12">
        <div className="flex max-w-md items-center gap-6 text-right">
          <p className="text-2xl leading-snug font-medium">
            {t("app_welcome_opened")}
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
          <h1 className="text-xl font-semibold">{t("app_welcome_title")}</h1>
          <p className="text-muted-foreground mt-2 text-sm">
            {t("app_welcome_body")}
          </p>
        </div>

        <Button className="w-full" onClick={() => void handleStart()}>
          {t("app_welcome_start")}
        </Button>

        {error && (
          <p className="text-destructive text-xs" role="alert">
            {error}
          </p>
        )}

        <p className="text-muted-foreground text-xs">
          {t("app_welcome_credit_before")}{" "}
          <a
            href="https://amibeingpwned.com"
            target="_blank"
            rel="noopener noreferrer"
            className="text-primary underline"
          >
            {/* i18n-ignore */}
            Am I Being Pwned
          </a>
          {t("app_welcome_credit_after")}
        </p>
      </div>
    </div>
  );
}
