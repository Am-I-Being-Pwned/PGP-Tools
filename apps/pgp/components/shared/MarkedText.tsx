import { t } from "../../lib/i18n";
import { codePointLabel, markLookalikes } from "../../lib/utils/lookalike";

/**
 * A name or address with its lookalike letters highlighted: the Cyrillic
 * А in "Аlice" is drawn in the warning colour, so the difference that
 * makes it someone else is visible rather than only flagged nearby.
 * Plain text, unchanged, for every ordinary name.
 */
export function MarkedText({ text }: { text: string }) {
  const runs = markLookalikes(text);
  if (runs.every((r) => !r.odd)) return <>{text}</>;
  return (
    <>
      {runs.map((run, i) =>
        run.odd ? (
          <mark
            // Runs are positional and never reorder.
            key={i}
            title={t("keys_lookalike_char", { code: codePointLabel(run.text) })}
            className="bg-warn/25 text-warn rounded-[2px] px-px"
          >
            {run.text}
          </mark>
        ) : (
          <span key={i}>{run.text}</span>
        ),
      )}
    </>
  );
}
