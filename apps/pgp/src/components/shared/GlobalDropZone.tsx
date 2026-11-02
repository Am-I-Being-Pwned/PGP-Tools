import { useCallback, useEffect, useRef, useState } from "react";
import { UploadCloudIcon } from "lucide-react";

import {
  buildDropSample,
  resolveDropRule,
  type DropRule,
} from "~/lib/drop-routing";
import { t } from "~/lib/i18n";

interface GlobalDropZoneProps {
  rules: DropRule[];
  children: React.ReactNode;
}

/** File drags only, so in-panel text drops are never hijacked. */
function dragHasFiles(e: DragEvent): boolean {
  return Array.from(e.dataTransfer?.types ?? []).includes("Files");
}

/** The overlay covers the viewport during a file drag, so every drop lands
 *  on one handler (no double-processing). */
export function GlobalDropZone({ rules, children }: GlobalDropZoneProps) {
  const [dragging, setDragging] = useState(false);
  // A counter: dragenter/dragleave fire for every element crossed.
  const depth = useRef(0);
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
      // Synchronously: dataTransfer is cleared once the handler returns.
      const files = Array.from(e.dataTransfer.files);
      const text = e.dataTransfer.getData("text/plain");
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
      if (!dragHasFiles(e)) return;
      e.preventDefault();
    };
    const onLeave = (e: DragEvent) => {
      if (!dragHasFiles(e)) return;
      depth.current -= 1;
      if (depth.current <= 0) reset();
    };
    // A drop outside the overlay (before it mounts) still needs stopping.
    const onWindowDrop = (e: DragEvent) => {
      if (!dragHasFiles(e)) return;
      e.preventDefault();
      reset();
    };
    window.addEventListener("dragenter", onEnter);
    window.addEventListener("dragover", onOver);
    window.addEventListener("dragleave", onLeave);
    window.addEventListener("drop", onWindowDrop);
    // A cancelled drag fires neither drop nor a final dragleave.
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
          <div className="surface-float flex h-full w-full flex-col items-center justify-center gap-3 rounded-xl p-6 text-center">
            <UploadCloudIcon className="text-good h-10 w-10" />
            <p className="text-base font-semibold">
              {t("shared_drop_to_import")}
            </p>
            <p className="text-muted-foreground max-w-xs text-sm">
              {t("shared_drop_desc")}
            </p>
          </div>
        </div>
      )}
    </>
  );
}
