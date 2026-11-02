import { useEffect, useRef, useState, type RefObject } from "react";

import type { CrxSigningKeyBlob } from "~/lib/crx/types";
import { t, tn } from "~/lib/i18n";
import type { PublicContactKey } from "~/lib/storage/contacts";
import { isPgpRecord } from "~/lib/storage/key-kind";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { toast } from "~/lib/toast";
import { selId } from "./keys-routes";

export type KeySelection = ReturnType<typeof useKeySelection>;

/** One selection over own keys, shown CRX keys and contacts. `listRef`
 *  must wrap the rendered cards: shift-click ranges are read off it (owned
 *  by the caller -- react-hooks/refs flags a ref read off a hook result). */
export function useKeySelection(
  listRef: RefObject<HTMLElement | null>,
  {
    myKeys,
    crxKeys,
    contacts,
  }: {
    myKeys: ProtectedKeyBlob[];
    crxKeys: CrxSigningKeyBlob[];
    contacts: PublicContactKey[];
  },
) {
  const [selectionMode, setSelectionMode] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());

  // Leaving nothing selected exits selection mode.
  useEffect(() => {
    if (selectionMode && selected.size === 0) setSelectionMode(false);
  }, [selectionMode, selected]);

  // Where a shift-click measures its range FROM: the last card touched
  // without shift. Reset whenever the selection is torn down, so a stale
  // anchor can't sweep in a range the user can no longer see.
  const anchorRef = useRef<string | null>(null);

  // Read off the DOM so the range matches what is on screen (the contacts
  // search filters it). Scoped to this view's root -- a document-wide
  // query would also sweep up cards rendered by an open panel.
  const visibleIds = () =>
    Array.from(
      listRef.current?.querySelectorAll<HTMLElement>("[data-select-id]") ?? [],
    ).flatMap((el) => (el.dataset.selectId ? [el.dataset.selectId] : []));

  const toggleSelect = (id: string, extend = false) => {
    const anchor = anchorRef.current;
    if (extend && anchor && anchor !== id) {
      const ids = visibleIds();
      const from = ids.indexOf(anchor);
      const to = ids.indexOf(id);
      if (from !== -1 && to !== -1) {
        // The range REPLACES the selection and the anchor stays put (the
        // standard shift-click contract): re-clicking nearer the anchor
        // must shrink the run, which an additive sweep never would.
        setSelected(
          new Set(ids.slice(Math.min(from, to), Math.max(from, to) + 1)),
        );
        return;
      }
    }
    anchorRef.current = id;
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const startSelect = (id: string) => {
    anchorRef.current = id;
    setSelectionMode(true);
    setSelected((s) => new Set(s).add(id));
  };
  const exitSelection = () => {
    anchorRef.current = null;
    setSelected(new Set());
    setSelectionMode(false);
  };

  const selectedMyKeys = myKeys.filter((k) =>
    selected.has(selId("pgp", k.keyId)),
  );
  const selectedCrxKeys = crxKeys.filter((k) =>
    selected.has(selId("crx", k.extensionId)),
  );
  const selectedContacts = contacts.filter((c) =>
    selected.has(selId("contact", c.keyId)),
  );
  // An SSH identity has no private-key export (SECURITY.md): the export
  // page runs through `getKeyArmored`, the OpenPGP trapdoor, which has no
  // SSH sibling by design.
  const exportableMyKeys = selectedMyKeys.filter(isPgpRecord);

  const selectableIds = [
    ...myKeys.map((k) => selId("pgp", k.keyId)),
    ...crxKeys.map((k) => selId("crx", k.extensionId)),
    ...contacts.map((c) => selId("contact", c.keyId)),
  ];
  const allSelected =
    selectableIds.length > 0 && selectableIds.every((id) => selected.has(id));
  const toggleSelectAll = () => {
    if (allSelected) {
      exitSelection();
    } else {
      anchorRef.current = null;
      setSelectionMode(true);
      setSelected(new Set(selectableIds));
    }
  };

  // Export is non-destructive, so the toast's "Reselect" can bring the
  // same set back.
  const afterExport = (count: number, unsafe: boolean) => {
    const prev = new Set(selected);
    exitSelection();
    toast.success(
      unsafe ? tn("keys_exported_unsafe", count) : tn("keys_exported", count),
      {
        id: "keys-exported",
        action: {
          label: t("keys_reselect"),
          onClick: () => {
            setSelected(prev);
            setSelectionMode(true);
          },
        },
      },
    );
  };

  return {
    selectionMode,
    selected,
    allSelected,
    toggleSelect,
    startSelect,
    exitSelection,
    toggleSelectAll,
    afterExport,
    selectedMyKeys,
    selectedCrxKeys,
    selectedContacts,
    exportableMyKeys,
  };
}
