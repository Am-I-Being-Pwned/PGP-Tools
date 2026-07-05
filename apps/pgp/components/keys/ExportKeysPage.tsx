import type { ExportKeysProps } from "../settings/ExportAllKeysDialog";
import {
  ExportKeysBody,
  useExportKeysFlow,
} from "../settings/ExportAllKeysDialog";
import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "../shared/SlideOver";

interface ExportKeysPageProps extends ExportKeysProps {
  /** Called after the slide-out finishes (parent unmounts the panel). */
  onClose: () => void;
}

/**
 * Slide-over shell for the bulk-export flow, used by the selection island so
 * export follows the same full-panel convention as the delete/rename/details
 * pages instead of a modal dialog. Shares all logic with the Settings
 * {@link ExportAllKeysDialog} via {@link useExportKeysFlow}.
 */
export function ExportKeysPage({ onClose, ...props }: ExportKeysPageProps) {
  const { entered, close } = useSlideOver(onClose);
  // Always "open" -- the panel only exists while it's on the nav stack; its
  // resetAndClose slides out via `close`, dropping any CRX handles first.
  const flow = useExportKeysFlow({ open: true, onClose: close, ...props });

  return (
    <SlideOverPanel entered={entered} ariaLabel="Export keys">
      <SlideOverHeader title="Export keys" onBack={flow.resetAndClose} />
      <div className="flex-1 overflow-y-auto p-3">
        <ExportKeysBody f={flow} />
      </div>
    </SlideOverPanel>
  );
}
