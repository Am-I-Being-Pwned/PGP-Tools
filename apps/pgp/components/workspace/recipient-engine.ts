import type {
  KindDiscriminated,
  StoredKeyKind,
} from "../../lib/storage/key-kind";
import { storedKeyKind } from "../../lib/storage/key-kind";

/**
 * Which engine the recipient picker is currently committed to, and which
 * of the remaining options that rules out.
 *
 * OpenPGP and age are different file formats: one message cannot address
 * both (see `lib/encrypt-recipients.ts`). The picker prevents that by
 * DISABLING the other engine's options with a reason, rather than
 * letting the selection be made and refusing it at encrypt time -- the
 * same rule the action registry states for its own disabled actions: a
 * dimmed option with a reason is discoverable, a vanished one looks like
 * it doesn't exist.
 *
 * Split out of the component (and kept free of JSX) so the indexing rule
 * below can be tested directly.
 */

/** The engine the current selection commits the message to, or null when
 *  nothing is selected and either engine is still open. The selection can
 *  never be mixed -- that is what this module prevents -- so the first
 *  entry decides. */
export function selectionEngine(
  selected: readonly KindDiscriminated[],
): StoredKeyKind | null {
  return selected.length === 0 ? null : storedKeyKind(selected[0]);
}

/** True when `key` belongs to the other engine and therefore cannot join
 *  this message. Nothing is blocked while no engine is committed. */
export function blockedByEngine(
  key: KindDiscriminated,
  engine: StoredKeyKind | null,
): boolean {
  return engine !== null && storedKeyKind(key) !== engine;
}

/**
 * The options a keyboard gesture may actually land on.
 *
 * Render order and pick order are NOT the same list once some rows are
 * disabled: if digit `3` indexed into what is rendered, a dimmed row
 * sitting third would swallow the keystroke and nothing would happen.
 * Both the digit shortcuts and the Enter-picks-the-top-match fallback
 * index into this, so a blocked row is invisible to the keyboard while
 * staying visible (and explained) on screen.
 */
export function pickableKeys<T extends KindDiscriminated>(
  visible: readonly T[],
  engine: StoredKeyKind | null,
): T[] {
  return visible.filter((k) => !blockedByEngine(k, engine));
}
