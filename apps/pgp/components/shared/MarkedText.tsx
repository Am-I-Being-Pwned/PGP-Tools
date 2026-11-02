import { t } from "~/lib/i18n";
import { codePointLabel, markLookalikes } from "~/lib/utils/lookalike";

/** Lookalike letters highlighted and invisible characters drawn as marked
 *  placeholders: the difference that makes it someone else must be seen. */
export function MarkedText({ text }: { text: string }) {
  const runs = markLookalikes(text);
  if (runs.every((r) => !r.odd)) return <>{text}</>;
  return (
    <>
      {runs.map((run, i) =>
        run.invisible ? (
          // Draws nothing, so a dotted circle stands in for it.
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
