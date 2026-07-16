import { useEffect, useRef } from "react";

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import { isMacPlatform } from "@amibeingpwned/ui/kbd-helpers";

import { hasOpenSlideOver } from "../components/shared/SlideOver";
import { isEditableTarget, matchesShortcut } from "../lib/shortcuts";

interface UseShortcutOptions {
  /** Detach the listener entirely (e.g. the button it mirrors is
   *  disabled). Defaults to true. */
  enabled?: boolean;
  /** Fire even when a text field is focused. Defaults to true for
   *  modifier combos (mod+Enter should submit from a textarea) and
   *  false for plain keys (typing "c" must not trigger anything). */
  allowInInput?: boolean;
  /** By default shortcuts are suppressed while a slide-over subpage is
   *  open, so background surfaces don't react underneath it. A binding
   *  owned by a slide-over sets this and gates itself on `isTop()`. */
  allowInSlideOver?: boolean;
}

/**
 * Bind a global keyboard shortcut for the lifetime of the component.
 * Matching keydowns are prevented (so e.g. Ctrl+Enter doesn't also
 * insert a newline) and routed to `handler`.
 *
 * Escape is deliberately not bound through this hook anywhere: the
 * slide-over stack owns Escape (topmost panel only) in SlideOver.tsx.
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

  // Keep the latest handler without re-binding the listener each render.
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
