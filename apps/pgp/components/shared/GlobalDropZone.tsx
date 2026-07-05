import { useCallback, useEffect, useRef, useState } from "react";
import { UploadCloudIcon } from "lucide-react";

import type { DropRule } from "../../lib/drop-routing";
import { buildDropSample, resolveDropRule } from "../../lib/drop-routing";

interface GlobalDropZoneProps {
  /** Ordered routing rules; first match wins (see lib/drop-routing). */
  rules: DropRule[];
  children: React.ReactNode;
}

/** Whether a drag carries actual files (vs. an in-app text/element drag).
 *  We only surface the global overlay for file drags so we never hijack
 *  the in-panel textarea/paste drops. */
function dragHasFiles(e: DragEvent): boolean {
  return Array.from(e.dataTransfer?.types ?? []).includes("Files");
}

/**
 * App-wide dropzone. While a file drag is over the window it shows a
 * full-window overlay; on drop it classifies the payload via `rules` and
 * hands off to the matching route (keys → import, everything else →
 * workspace). Because the overlay covers the viewport while a file drag is
 * active, drops land on it rather than any in-panel dropzone, so there's a
 * single, consistent handler and no double-processing.
 */
export function GlobalDropZone({ rules, children }: GlobalDropZoneProps) {
  const [dragging, setDragging] = useState(false);
  // dragenter/dragleave fire for every element crossed, so a net counter
  // (not a boolean) is what actually tracks "is the cursor still inside".
  const depth = useRef(0);
  // Read fresh rules at drop time without re-registering listeners.
  const rulesRef = useRef(rules);
  useEffect(() => {
    rulesRef.current = rules;
  });

  const reset = useCallback(() => {
    depth.current = 0;
    setDragging(false);
  }, []);

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      reset();
      // Read the dataTransfer synchronously — it's cleared once the event
      // handler returns, so grab the File refs and text before any await.
      const files = Array.from(e.dataTransfer.files);
      const text = e.dataTransfer.getData("text/plain");
      // Treat a whitespace-only text drop as empty so it doesn't needlessly
      // switch tabs / clear a pending draft-restore for a no-op.
      if (files.length === 0 && !text.trim()) return;

      const payload = { files, text };
      const sample = await buildDropSample(payload);
      const rule = resolveDropRule(rulesRef.current, sample);
      await rule?.run(payload);
    },
    [reset],
  );

  useEffect(() => {
    const onEnter = (e: DragEvent) => {
      if (!dragHasFiles(e)) return;
      depth.current += 1;
      setDragging(true);
    };
    const onOver = (e: DragEvent) => {
      // preventDefault on dragover is required for the drop to be allowed.
      if (!dragHasFiles(e)) return;
      e.preventDefault();
    };
    const onLeave = (e: DragEvent) => {
      if (!dragHasFiles(e)) return;
      depth.current -= 1;
      if (depth.current <= 0) reset();
    };
    // A drop that somehow lands outside the overlay (e.g. the split-second
    // before it mounts) still needs the default file-open behavior stopped
    // and the overlay dismissed.
    const onWindowDrop = (e: DragEvent) => {
      if (!dragHasFiles(e)) return;
      e.preventDefault();
      reset();
    };
    window.addEventListener("dragenter", onEnter);
    window.addEventListener("dragover", onOver);
    window.addEventListener("dragleave", onLeave);
    window.addEventListener("drop", onWindowDrop);
    // A cancelled in-page drag (Escape) fires neither drop nor a final
    // dragleave, so clear the overlay explicitly to avoid it sticking.
    window.addEventListener("dragend", reset);
    return () => {
      window.removeEventListener("dragenter", onEnter);
      window.removeEventListener("dragover", onOver);
      window.removeEventListener("dragleave", onLeave);
      window.removeEventListener("drop", onWindowDrop);
      window.removeEventListener("dragend", reset);
    };
  }, [reset]);

  return (
    <>
      {children}
      {dragging && (
        <div
          className="bg-background/70 fixed inset-0 z-50 p-3 backdrop-blur-sm"
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
        >
          <div className="border-primary bg-primary/5 text-primary flex h-full w-full flex-col items-center justify-center gap-3 rounded-2xl border-2 border-dashed p-6 text-center">
            <UploadCloudIcon className="h-10 w-10" />
            <p className="text-base font-semibold">Drop to import</p>
            <p className="text-muted-foreground max-w-xs text-sm">
              Keys are added to your keyring; files and text go to the
              workspace.
            </p>
          </div>
        </div>
      )}
    </>
  );
}
