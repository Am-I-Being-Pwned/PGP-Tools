import { cn } from "@amibeingpwned/ui";
import { Block } from "@amibeingpwned/ui/block";
import { Switch } from "@amibeingpwned/ui/switch";

/** An on/off setting as a block: title and description left, switch
 *  right. The row is the switch's <label>, so its accessible name is the
 *  title plus the description and a click anywhere flips it. */
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
