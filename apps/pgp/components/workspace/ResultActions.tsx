import { CheckIcon, ClipboardIcon, DownloadIcon } from "lucide-react";

import { ariaKeyShortcuts, Button, isMacPlatform } from "@amibeingpwned/ui";

import { ShortcutHint } from "~/components/shared/ShortcutHint";
import { COPY_SHORTCUT, DOWNLOAD_SHORTCUT } from "~/lib/actions/definitions";
import { t } from "~/lib/i18n";

/** Download (primary) and Copy for a finished result. The shortcuts live
 *  in hover popovers so they don't crowd the half-width buttons. */
export function ResultActions({
  onDownload,
  onCopy,
  copied,
  disabled,
}: {
  onDownload: () => void;
  /** Absent when there is no text to copy (file/binary results). */
  onCopy?: () => void;
  copied: boolean;
  disabled: boolean;
}) {
  return (
    <div className="flex flex-1 gap-2">
      <ShortcutHint shortcut={DOWNLOAD_SHORTCUT}>
        <Button
          className="flex-1"
          onClick={onDownload}
          disabled={disabled}
          aria-keyshortcuts={ariaKeyShortcuts(
            DOWNLOAD_SHORTCUT,
            isMacPlatform(),
          )}
        >
          <DownloadIcon className="h-4 w-4" />
          {t("common_download")}
        </Button>
      </ShortcutHint>
      {onCopy && (
        <ShortcutHint shortcut={COPY_SHORTCUT}>
          <Button
            variant="outline"
            className="flex-1"
            onClick={onCopy}
            disabled={disabled}
            aria-keyshortcuts={ariaKeyShortcuts(COPY_SHORTCUT, isMacPlatform())}
          >
            {copied ? (
              <CheckIcon className="text-good h-4 w-4" />
            ) : (
              <ClipboardIcon className="h-4 w-4" />
            )}
            {copied ? t("common_copied") : t("common_copy")}
          </Button>
        </ShortcutHint>
      )}
    </div>
  );
}
