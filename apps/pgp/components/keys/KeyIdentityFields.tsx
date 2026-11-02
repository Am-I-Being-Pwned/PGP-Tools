import { useState } from "react";
import { ChevronRightIcon } from "lucide-react";

import { Block, BlockLabel, BlockStack } from "@amibeingpwned/ui/block";
import { Input } from "@amibeingpwned/ui/input";
import { Segmented } from "@amibeingpwned/ui/segmented";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";

import type { ExpiryOption } from "../../lib/keys/expiry";
import { t } from "../../lib/i18n";

export type KeyAlgorithm = "ecc" | "rsa";

export interface KeyIdentity {
  name: string;
  email: string;
  comment: string;
}

export const EMPTY_IDENTITY: KeyIdentity = { name: "", email: "", comment: "" };

export function identityUserId(identity: KeyIdentity) {
  return {
    name: identity.name.trim(),
    email: identity.email.trim() || undefined,
    comment: identity.comment.trim() || undefined,
  };
}

/** Focus ring is inset so the stack's clip can't cut it. */
export function FieldBlock({
  label,
  optional,
  ...input
}: { label: string; optional?: boolean } & React.ComponentProps<"input">) {
  return (
    <Block className="focus-within:ring-ring/60 px-3.5 pt-2 pb-1.5 focus-within:ring-1 focus-within:ring-inset">
      <label className="text-muted-foreground block text-[11px]">
        {label}
        {optional && (
          <>
            {" "}
            <span className="text-muted-foreground/60">
              {t("keygen_optional")}
            </span>
          </>
        )}
        <Input variant="bare" className="text-foreground" {...input} />
      </label>
    </Block>
  );
}

interface KeyIdentityFieldsProps {
  identity: KeyIdentity;
  onIdentityChange: (identity: KeyIdentity) => void;
  algorithm: KeyAlgorithm;
  onAlgorithmChange: (algorithm: KeyAlgorithm) => void;
  expiry: ExpiryOption;
  onExpiryChange: (expiry: ExpiryOption) => void;
  allowCustomExpiry?: boolean;
}

export function KeyIdentityFields({
  identity,
  onIdentityChange,
  algorithm,
  onAlgorithmChange,
  expiry,
  onExpiryChange,
  allowCustomExpiry,
}: KeyIdentityFieldsProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const field = (key: keyof KeyIdentity) => ({
    value: identity[key],
    onChange: (e: React.ChangeEvent<HTMLInputElement>) =>
      onIdentityChange({ ...identity, [key]: e.target.value }),
  });

  return (
    <>
      <BlockStack>
        <FieldBlock
          label={t("keygen_name_label")}
          type="text"
          placeholder={t("keygen_name_placeholder")}
          {...field("name")}
        />
        <FieldBlock
          label={t("keygen_email_label")}
          optional
          type="email"
          placeholder={t("keygen_email_placeholder")}
          {...field("email")}
        />
        <FieldBlock
          label={t("keygen_comment_label")}
          optional
          type="text"
          placeholder={t("keygen_comment_placeholder")}
          {...field("comment")}
        />
      </BlockStack>

      <button
        type="button"
        aria-expanded={showAdvanced}
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="bg-card text-muted-foreground hover:text-foreground flex w-full items-center gap-1.5 rounded-xl px-3.5 py-3 text-xs font-medium transition-colors"
      >
        <ChevronRightIcon
          className={`h-3 w-3 transition-transform ${showAdvanced ? "rotate-90" : ""}`}
        />
        {t("keygen_advanced_options")}
      </button>

      {showAdvanced && (
        <div className="space-y-3">
          <div className="space-y-1.5">
            <BlockLabel>{t("keygen_algorithm_label")}</BlockLabel>
            <Segmented
              fill
              ariaLabel={t("keygen_algorithm_label")}
              value={algorithm}
              onValueChange={onAlgorithmChange}
              options={[
                // i18n-ignore
                { value: "ecc", label: "ECC (Ed25519)" },
                // i18n-ignore
                { value: "rsa", label: "RSA" },
              ]}
            />
            <p className="text-muted-foreground/60 px-1 text-[10px]">
              {algorithm === "ecc"
                ? t("keygen_algorithm_hint_ecc")
                : t("keygen_algorithm_hint_rsa")}
            </p>
          </div>

          {algorithm === "rsa" && (
            <div className="space-y-1.5">
              <BlockLabel>{t("keygen_key_size_label")}</BlockLabel>
              {/* RSA-4096 is the only size the engine generates. */}
              <Select value="4096">
                <SelectTrigger className="h-8 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="4096">
                    {t("keygen_key_size_4096")}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>
          )}

          <div className="space-y-1.5">
            <BlockLabel>{t("keygen_expiry_label")}</BlockLabel>
            {/* A dropdown: five options in a narrow panel would truncate. */}
            <Select
              value={expiry}
              onValueChange={(v) => onExpiryChange(v as ExpiryOption)}
            >
              <SelectTrigger className="h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="never">
                  {t("keygen_expiry_never")}
                </SelectItem>
                <SelectItem value="1y">{t("keygen_expiry_1y")}</SelectItem>
                <SelectItem value="2y">{t("keygen_expiry_2y")}</SelectItem>
                <SelectItem value="3y">{t("keygen_expiry_3y")}</SelectItem>
                {allowCustomExpiry && (
                  <SelectItem value="custom">
                    {t("keygen_expiry_custom")}
                  </SelectItem>
                )}
              </SelectContent>
            </Select>
          </div>
        </div>
      )}
    </>
  );
}
