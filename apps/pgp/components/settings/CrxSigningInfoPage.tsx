import { ExternalLinkIcon, ShieldCheckIcon } from "lucide-react";

import { t } from "../../lib/i18n";
import { Emphasised } from "../shared/Emphasised";
import { SubPage } from "../shared/SubPage";

/** Inline emphasis for literals and UI labels inside the body copy. */
/** Dash-led lines. Plain hyphens in their own column, so a wrapped line
 *  stays aligned under the text rather than under the dash. */
function DashList({ items }: { items: React.ReactNode[] }) {
  return (
    <ul className="space-y-1.5">
      {items.map((item, i) => (
        <li key={i} className="flex gap-2">
          <span aria-hidden="true">-</span>
          <span className="min-w-0 leading-relaxed">{item}</span>
        </li>
      ))}
    </ul>
  );
}

/** A titled block of explainer copy. */
function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-2">
      <h3 className="text-foreground font-semibold">{title}</h3>
      {children}
    </section>
  );
}

interface CrxSigningInfoPageProps {
  onClose: () => void;
}

/**
 * Explainer subpage for CRX (Chrome extension) signing. Pure content - no
 * key material, no actions. The signing/verifying itself happens in the
 * Workspace via the normal drop-a-file flow.
 */
export function CrxSigningInfoPage({ onClose }: CrxSigningInfoPageProps) {
  // Literal file extensions and UI labels, emphasised inside the copy.
  const zip = ".zip";
  const crx = ".crx";
  const save = t("common_save");
  const loadUnpacked = t("settings_crx_info_term_load_unpacked");
  const publicTerm = t("settings_crx_info_term_public");
  const dashboardPath = t("settings_crx_info_term_dashboard_path");

  /** The four release steps, in order. */
  const steps: React.ReactNode[] = [
    t("settings_crx_info_step_1"),
    <Emphasised
      key="2"
      text={t("settings_crx_info_step_2", {
        public: publicTerm,
        path: dashboardPath,
      })}
      terms={[publicTerm, dashboardPath]}
    />,
    <Emphasised
      key="3"
      text={t("settings_crx_info_step_3", { zip, save, crx })}
      terms={[zip, save, crx]}
    />,
    <Emphasised
      key="4"
      text={t("settings_crx_info_step_4", { crx })}
      terms={[crx]}
    />,
  ];

  /** Where this scheme sits between the weaker and stronger alternatives,
   *  weakest first. */
  const ci = t("settings_crx_info_ladder_ci_term");
  const vault = t("settings_crx_info_ladder_vault_term");
  const hardware = t("settings_crx_info_ladder_hardware_term");
  const ladder: React.ReactNode[] = [
    <Emphasised
      key="ci"
      text={t("settings_crx_info_ladder_ci", { term: ci })}
      terms={[ci]}
    />,
    <Emphasised
      key="vault"
      text={t("settings_crx_info_ladder_vault", { term: vault })}
      terms={[vault]}
    />,
    <Emphasised
      key="hardware"
      text={t("settings_crx_info_ladder_hardware", { term: hardware })}
      terms={[hardware]}
    />,
  ];

  return (
    <SubPage
      title={t("settings_crx_info_title")}
      onClose={onClose}
      bodyClassName="px-5 py-4"
    >
      <div className="text-foreground/75 space-y-5 text-sm">
        {/* The pitch, given the weight of a card: it is the one thing to
            read if the user reads nothing else on the page. */}
        <section className="border-border flex gap-2.5 rounded-md border p-3">
          <ShieldCheckIcon className="text-primary mt-0.5 size-4 shrink-0" />
          <div className="space-y-2">
            <p className="text-foreground font-semibold">
              {t("settings_crx_info_pitch_title")}
            </p>
            <p className="leading-relaxed">{t("settings_crx_info_pitch_p1")}</p>
            <p className="leading-relaxed">{t("settings_crx_info_pitch_p2")}</p>
          </div>
        </section>

        <Section title={t("settings_crx_info_how_title")}>
          <DashList items={steps} />
        </Section>

        <Section title={t("settings_crx_info_get_title")}>
          <p className="leading-relaxed">
            <Emphasised
              text={t("settings_crx_info_get_body", {
                crx,
                load_unpacked: loadUnpacked,
              })}
              terms={[crx, loadUnpacked]}
            />
          </p>
        </Section>

        <Section title={t("settings_crx_info_ladder_title")}>
          <DashList items={ladder} />
        </Section>

        <Section title={t("settings_crx_info_not_pgp_title")}>
          <p className="leading-relaxed">
            <Emphasised
              text={t("settings_crx_info_not_pgp_body", { crx })}
              terms={[crx]}
            />
          </p>
        </Section>

        <a
          href="https://developer.chrome.com/docs/webstore/update#protect-package-updates"
          target="_blank"
          rel="noopener noreferrer"
          className="border-border hover:border-muted-foreground/40 flex items-center justify-between gap-2 rounded-md border px-3 py-2.5 transition-colors"
        >
          <span>{t("settings_crx_info_link")}</span>
          <ExternalLinkIcon className="text-muted-foreground size-4 shrink-0" />
        </a>
      </div>
    </SubPage>
  );
}
