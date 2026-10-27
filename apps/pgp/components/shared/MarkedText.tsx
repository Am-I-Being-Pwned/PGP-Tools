import { t } from "../../lib/i18n";
import { codePointLabel, markLookalikes } from "../../lib/utils/lookalike";

/**
 * A name or address with its lookalike letters highlighted: the Cyrillic
 * А in "Аlice" is drawn in the warning colour, so the difference that
 * makes it someone else is visible rather than only flagged nearby.
 * An invisible character (a zero-width space, a variation selector, a
 * bidi control) is drawn as a marked placeholder, because it is exactly
 * the difference that would otherwise never be seen.
 * Plain text, unchanged, for every ordinary name.
 */
export function MarkedText({ text }: { text: string }) {
  const runs = markLookalikes(text);
  if (runs.every((r) => !r.odd)) return <>{text}</>;
  return (
    <>
      {runs.map((run, i) =>
        run.invisible ? (
          // A character that draws nothing: a highlight around nothing is
          // still nothing, so a dotted circle stands in for it, with the
          // code point in the hover text.
          <mark
            key={i}
            title={t("keys_invisible_char", {
              code: codePointLabel(run.text),
            })}
            className="bg-warn/25 text-warn rounded-[2px] px-px"
          >
            {"\u25cc"}
          </mark>
        ) : run.odd ? (
          <mark
            // Runs are positional and never reorder.
            key={i}
            title={
              run.confusable
                ? t("keys_confusable_char", { code: codePointLabel(run.text) })
                : t("keys_lookalike_char", { code: codePointLabel(run.text) })
            }
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
