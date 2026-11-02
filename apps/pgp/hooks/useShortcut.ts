import { useEffect, useRef } from "react";

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import { isMacPlatform } from "@amibeingpwned/ui/kbd-helpers";

import { hasOpenSlideOver } from "../components/shared/SlideOver";
import { isEditableTarget, matchesShortcut } from "../lib/shortcuts";

interface UseShortcutOptions {
  /** Defaults to true. */
  enabled?: boolean;
  /** Fire in text fields. Default: true for modifier combos, false for
   *  plain keys. */
  allowInInput?: boolean;
  /** Fire while a slide-over is open (the binding gates on `isTop()`). */
  allowInSlideOver?: boolean;
}

/**
 * Bind a global shortcut; matching keydowns are prevented. Escape is never
 * bound here: the slide-over stack owns it (SlideOver.tsx).
 */
export function useShortcut(
  spec: ShortcutSpec,
  handler: () => void,
  options: UseShortcutOptions = {},
) {
  const {
    enabled = true,
    allowInInput = spec.mod === true,
    allowInSlideOver = false,
  } = options;

  const handlerRef = useRef(handler);
  useEffect(() => {
    handlerRef.current = handler;
  });

  const { mod, shift, alt, key } = spec;

  useEffect(() => {
    if (!enabled) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (!matchesShortcut(event, { mod, shift, alt, key }, isMacPlatform())) {
        return;
      }
      if (!allowInInput && isEditableTarget(event.target)) return;
      if (!allowInSlideOver && hasOpenSlideOver()) return;
      event.preventDefault();
      handlerRef.current();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [enabled, allowInInput, allowInSlideOver, mod, shift, alt, key]);
}
