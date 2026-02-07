/**
 * Theme Proposal - Current vs Proposed
 *
 * Problems with the current dark mode theme.css:
 *   1. --primary is too dim (L=0.72, chroma=0.14) - washed-out green
 *   2. --primary-foreground is white (L=0.98) - terrible contrast on green button
 *   3. Background/card/border are neutral grey with no green tint - loses the Pip-Boy feel
 *
 * This story renders both themes side by side using the same UI components.
 */

import type { Meta, StoryObj } from "@storybook/react";
import type { CSSProperties } from "react";
import { CheckCircle, ExternalLink, Loader2, ShieldCheck } from "lucide-react";

import { Badge } from "../badge";
import { Button } from "../button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "../card";
import { Input } from "../input";

// ---------------------------------------------------------------------------
// Current theme (mirrors theme.css dark mode exactly)
// ---------------------------------------------------------------------------

const CURRENT: Record<string, string> = {
  "--background": "oklch(0.07 0 0)",
  "--foreground": "oklch(0.93 0 0)",
  "--card": "oklch(0.17 0 0)",
  "--card-foreground": "oklch(0.93 0 0)",
  "--primary": "oklch(0.72 0.14 155)",
  "--primary-foreground": "oklch(0.98 0 0)", // <-- white on medium-green = bad contrast
  "--secondary": "oklch(0.15 0 0)",
  "--secondary-foreground": "oklch(0.93 0 0)",
  "--muted": "oklch(0.15 0 0)",
  "--muted-foreground": "oklch(0.55 0 0)",
  "--accent": "oklch(0.18 0 0)",
  "--accent-foreground": "oklch(0.93 0 0)",
  "--destructive": "oklch(0.65 0.20 25)",
  "--destructive-foreground": "oklch(0.98 0 0)",
  "--border": "oklch(0.28 0 0)",
  "--input": "oklch(0.17 0 0)",
  "--ring": "oklch(0.72 0.14 155)",
  "--radius": "0.375rem",
};

// ---------------------------------------------------------------------------
// Proposed theme - brighter primary, dark foreground, green-tinted base
// Matches the deepVars already used in aibp-deep.stories.tsx
// ---------------------------------------------------------------------------

const PROPOSED: Record<string, string> = {
  "--background": "oklch(0.16 0.014 160)", // green-tinted dark (not neutral black)
  "--foreground": "oklch(0.85 0.037 166)", // warm green-white text
  "--card": "oklch(0.19 0.018 155)", // green-tinted card
  "--card-foreground": "oklch(0.85 0.037 166)",
  "--primary": "oklch(0.84 0.204 154)", // bright Pip-Boy green
  "--primary-foreground": "oklch(0.16 0.014 160)", // dark text on green = high contrast
  "--secondary": "oklch(0.22 0.022 158)",
  "--secondary-foreground": "oklch(0.85 0.037 166)",
  "--muted": "oklch(0.22 0.022 158)",
  "--muted-foreground": "oklch(0.52 0.054 165)", // green-tinted mid grey
  "--accent": "oklch(0.29 0.028 165)",
  "--accent-foreground": "oklch(0.84 0.204 154)",
  "--destructive": "oklch(0.84 0.164 84)", // amber (Pip-Boy warning color)
  "--destructive-foreground": "oklch(0.16 0.014 160)",
  "--border": "oklch(0.29 0.028 165)", // green-tinted border
  "--input": "oklch(0.19 0.018 155)",
  "--ring": "oklch(0.84 0.204 154)",
  "--radius": "0.5rem", // slightly more rounded
};

// ---------------------------------------------------------------------------
// Shared demo UI - renders the same thing under both themes
// ---------------------------------------------------------------------------

function DemoUI({ label }: { label: string }) {
  return (
    <div
      className="dark flex min-h-screen flex-col gap-6 p-8"
      style={{
        backgroundColor: "var(--background)",
        color: "var(--foreground)",
      }}
    >
      <div className="text-xs font-bold tracking-widest uppercase opacity-40">
        {label}
      </div>

      {/* Join page mockup */}
      <section className="space-y-2">
        <div className="mb-3 text-xs opacity-50">Join page</div>
        <div
          className="w-72 space-y-4 rounded-xl border p-6 shadow-sm"
          style={{ background: "var(--card)", borderColor: "var(--border)" }}
        >
          <div className="flex flex-col items-center gap-2 text-center">
            <div
              className="rounded-xl p-2"
              style={{ background: "var(--accent)" }}
            >
              <ShieldCheck
                className="h-8 w-8"
                style={{ color: "var(--primary)" }}
              />
            </div>
            <p className="text-sm font-semibold">Am I Being Pwned?</p>
            <p className="text-xs" style={{ color: "var(--muted-foreground)" }}>
              Fleet device enrollment
            </p>
          </div>
          <div className="space-y-3">
            <div className="text-center">
              <p className="text-sm font-semibold">Install the extension</p>
              <p
                className="mt-1 text-xs"
                style={{ color: "var(--muted-foreground)" }}
              >
                You&apos;ve been invited to{" "}
                <span style={{ color: "var(--foreground)", fontWeight: 600 }}>
                  James Arnott
                </span>
                . Keep this tab open - enrollment is automatic.
              </p>
            </div>
            <Button className="w-full gap-2" size="sm">
              <ExternalLink className="h-3.5 w-3.5" />
              Install on Chrome
            </Button>
          </div>
        </div>
      </section>

      {/* Button variants */}
      <section className="space-y-2">
        <div className="mb-3 text-xs opacity-50">Button variants</div>
        <div className="flex flex-wrap gap-2">
          <Button>Default</Button>
          <Button variant="secondary">Secondary</Button>
          <Button variant="outline">Outline</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="destructive">Destructive</Button>
        </div>
      </section>

      {/* Color palette */}
      <section className="space-y-2">
        <div className="mb-3 text-xs opacity-50">Palette</div>
        <div className="flex gap-2">
          {[
            ["primary", "var(--primary)"],
            ["secondary", "var(--secondary)"],
            ["accent", "var(--accent)"],
            ["muted", "var(--muted)"],
            ["card", "var(--card)"],
            ["destructive", "var(--destructive)"],
          ].map(([name, color]) => (
            <div key={name} className="flex flex-col items-center gap-1">
              <div
                className="h-8 w-8 rounded-md border"
                style={{ background: color, borderColor: "var(--border)" }}
              />
              <span className="text-[9px] opacity-50">{name}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Badges + states */}
      <section className="space-y-2">
        <div className="mb-3 text-xs opacity-50">Badges + cards</div>
        <div className="flex flex-wrap gap-2">
          <Badge>default</Badge>
          <Badge variant="outline">outline</Badge>
          <Badge variant="secondary">secondary</Badge>
          <Badge variant="destructive">destructive</Badge>
        </div>
        <div
          className="mt-3 w-72 space-y-3 rounded-xl border p-4"
          style={{ background: "var(--card)", borderColor: "var(--border)" }}
        >
          <CardTitle className="text-sm">Fleet Overview</CardTitle>
          <div className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-emerald-500" />
            <span className="text-sm">12 devices enrolled</span>
          </div>
          <div className="flex items-center gap-2">
            <Loader2
              className="h-4 w-4 animate-spin"
              style={{ color: "var(--primary)" }}
            />
            <span className="text-sm">Syncing workspace...</span>
          </div>
          <Input placeholder="Search devices..." className="h-8 text-xs" />
        </div>
      </section>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Stories
// ---------------------------------------------------------------------------

const meta = {
  title: "Theme Proposal",
  parameters: { layout: "fullscreen" },
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

export const SideBySide: Story = {
  name: "Current vs Proposed",
  render: () => (
    <div className="flex min-h-screen">
      <div className="flex-1" style={CURRENT as CSSProperties}>
        <DemoUI label="CURRENT" />
      </div>
      <div className="w-px" style={{ background: "oklch(0.3 0 0)" }} />
      <div className="flex-1" style={PROPOSED as CSSProperties}>
        <DemoUI label="PROPOSED" />
      </div>
    </div>
  ),
};

export const CurrentOnly: Story = {
  name: "Current",
  render: () => (
    <div style={CURRENT as CSSProperties}>
      <DemoUI label="CURRENT" />
    </div>
  ),
};

export const ProposedOnly: Story = {
  name: "Proposed",
  render: () => (
    <div style={PROPOSED as CSSProperties}>
      <DemoUI label="PROPOSED" />
    </div>
  ),
};
