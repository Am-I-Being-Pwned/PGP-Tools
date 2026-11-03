import { useEffect, useEffectEvent, useRef, useState } from "react";

import { useCopyToClipboard } from "~/hooks";
import { t } from "~/lib/i18n";
import type { ReaderSigner } from "~/lib/reader-protocol";
import { toast } from "~/lib/toast";
import { saveCrxViaPrompt } from "~/lib/utils/download";
import { displayOnlySignerCard, signerCardState } from "./signer-card";
import type { Workspace } from "./useWorkspace";
import type { WorkspaceFlags } from "./workspace-view";

/** Copy, CRX save and Reply on the workspace's result. */
export function useResultActions(
  ws: Workspace,
  v: WorkspaceFlags,
  onOpenReply:
    ((text: string, signer: ReaderSigner) => Promise<void>) | undefined,
) {
  const { state: s, dispatch, myKeys, contacts, inputElRef } = ws;
  const resetAll = () => dispatch({ type: "reset-all" });
  // Save-As is the one download Chrome doesn't route to the CRX installer.
  const saveCrx = async () => {
    if (!v.crxResult) return;
    const result = await saveCrxViaPrompt(v.crxResult.data, v.crxResult.name);
    dispatch({
      type: "status",
      text:
        result === "saved"
          ? t("workspace_crx_saved", { name: v.crxResult.name })
          : result === "cancelled"
            ? null
            : t("workspace_crx_save_failed"),
    });
  };
  const autoSaveCrx = useEffectEvent(() => void saveCrx());
  const crxData = v.crxResult?.data;
  useEffect(() => {
    if (crxData) autoSaveCrx();
  }, [crxData]);
  /** The reset wipes the output: the panel keeps no copy. */
  const openReply = () => {
    if (!v.replyTo || !onOpenReply) return;
    // Display-only card: no public key travels to the tab.
    const signer = displayOnlySignerCard(
      signerCardState({
        signer: v.replyTo.signer,
        tone: v.replyTo.tone,
        note: v.replyTo.note,
        caveat: v.replyTo.caveat,
        statusText: s.result.status ?? undefined,
        contacts,
        myKeys,
      }),
    );
    void onOpenReply(ws.getOutput(), signer)
      .then(() => {
        resetAll();
        dispatch({ type: "encrypt-to", keyId: signer.contact.keyId });
        requestAnimationFrame(() => {
          window.focus();
          inputElRef.current?.focus();
        });
      })
      .catch(() => toast.error(t("workspace_reply_failed")));
  };

  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const { copy } = useCopyToClipboard();
  const handleCopy = async () => {
    if (!(await copy(ws.getOutput()))) return;
    setCopied(true);
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(false), 2000);
  };

  return { copied, handleCopy, saveCrx, openReply };
}
