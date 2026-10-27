import { useEffect, useRef, useState } from "react";
import { LockIcon } from "lucide-react";

import type { ReaderSigner } from "../../lib/reader-protocol";
import { SignerCard } from "../../components/workspace/SignerCard";
import { t } from "../../lib/i18n";
import {
  isReaderMessage,
  isReaderNonce,
  READER_PORT_PREFIX,
} from "../../lib/reader-protocol";
import { forgetLastRegExpMatch } from "../../lib/utils/regexp-residue";

type View = "waiting" | "shown" | "locked" | "unavailable";

/** Close this tab: the message it held is gone for good. */
function closeSelf(): void {
  void chrome.tabs
    .getCurrent()
    .then((tab) => {
      if (tab?.id !== undefined) return chrome.tabs.remove(tab.id);
      window.close();
    })
    .catch(() => window.close());
}

/**
 * Reply's reader tab: a view of one decrypted message, driven entirely
 * by the side panel over a nonce-named port (lib/reader-protocol). No
 * vault, keys or storage here. The message text is written into the
 * <pre> imperatively and never enters React state or the element tree,
 * as in the panel's own output box; only the signer card (public data)
 * and which view is up are state.
 */
export function Reader() {
  const [view, setView] = useState<View>("waiting");
  const [signer, setSigner] = useState<ReaderSigner | null>(null);
  const textRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    document.title = t("workspace_reader_title");
    const nonce = location.hash.slice(1);
    if (!isReaderNonce(nonce)) {
      setView("unavailable");
      return;
    }
    const clearText = () => {
      if (textRef.current) textRef.current.textContent = "";
      forgetLastRegExpMatch();
    };
    const port = chrome.runtime.connect({ name: READER_PORT_PREFIX + nonce });
    // Nobody answered: the panel that opened this is gone.
    const noAnswer = setTimeout(() => setView("unavailable"), 3_000);

    // Whether a panel ever answered: only then does a disconnect mean "the
    // panel closed" rather than "there was never one to talk to".
    let answered = false;
    port.onMessage.addListener((msg: unknown) => {
      if (!isReaderMessage(msg)) return;
      answered = true;
      clearTimeout(noAnswer);
      if (msg.type === "locked") {
        clearText();
        // The signer is contact data, which the lock protects too.
        setSigner(null);
        setView("locked");
        return;
      }
      if (textRef.current) textRef.current.textContent = msg.text;
      setSigner(msg.signer);
      setView("shown");
    });
    // The panel closed: the message went with it, so the tab goes too.
    port.onDisconnect.addListener(() => {
      clearTimeout(noAnswer);
      clearText();
      setSigner(null);
      if (answered) closeSelf();
      else setView("unavailable");
    });
    return () => {
      clearTimeout(noAnswer);
      port.disconnect();
    };
  }, []);

  const shown = view === "shown";
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col px-6 py-8">
      {shown && signer && (
        <div className="mb-3">
          {/* The panel's card state, rendered by the panel's own card:
              the same verdict, warnings and pills in both places. */}
          <SignerCard state={signer} />
        </div>
      )}
      {/* Always mounted, so the text has a node to go into; hidden
          (and emptied) whenever there is nothing to show. */}
      <pre
        id="message"
        ref={textRef}
        tabIndex={0}
        className={`bg-card rounded-xl p-4 font-mono text-xs break-all whitespace-pre-wrap focus:outline-none ${
          shown ? "" : "hidden"
        }`}
      />
      {(view === "locked" || view === "unavailable") && (
        <div className="flex flex-1 flex-col items-center justify-center gap-4 text-center">
          <div className="bg-card text-muted-foreground flex size-[72px] items-center justify-center rounded-[18px]">
            <LockIcon className="size-7" aria-hidden="true" />
          </div>
          <p className="text-muted-foreground text-sm">
            {view === "locked"
              ? t("workspace_reader_locked")
              : t("workspace_reader_unavailable")}
          </p>
        </div>
      )}
    </main>
  );
}
