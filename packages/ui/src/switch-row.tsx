import { Block } from "./block";
import { cn } from "./cn";
import { Switch } from "./switch";

/** The row is the switch's <label>: whole-row click, title+description
 *  as the accessible name. */
export function SwitchRow({
  title,
  description,
  checked,
  onCheckedChange,
  disabled,
  className,
}: {
  title: string;
  description?: string;
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  disabled?: boolean;
  className?: string;
}) {
  return (
    <Block className={className}>
      <label
        className={cn(
          "flex items-center justify-between gap-4 px-3.5 py-3",
          disabled ? "cursor-not-allowed" : "cursor-pointer",
        )}
      >
        <div>
          <span className="text-sm font-medium">{title}</span>
          {description && (
            <p className="text-muted-foreground text-xs">{description}</p>
          )}
        </div>
        <Switch
          checked={checked}
          onCheckedChange={onCheckedChange}
          disabled={disabled}
        />
      </label>
    </Block>
  );
}
