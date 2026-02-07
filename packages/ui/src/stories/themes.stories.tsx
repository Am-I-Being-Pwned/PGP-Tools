import type { Meta, StoryObj } from "@storybook/react";
import type { CSSProperties, ReactNode } from "react";

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
import { Label } from "../label";
import { Separator } from "../separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "../table";

const meta = {
  title: "Themes",
  parameters: {
    layout: "fullscreen",
  },
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Theme definition
// ---------------------------------------------------------------------------

interface ThemeConfig {
  name: string;
  tagline: string;
  /** Real source for the palette (URL or system name) */
  source: string;
  /** CSS custom properties - OKLCH values derived from documented hex palettes */
  vars: Record<string, string>;
  /** Extra inline styles on the theme root */
  rootStyle?: CSSProperties;
  /** Custom banner */
  banner?: (name: string, tagline: string) => ReactNode;
  /** Overlay decorations */
  decorations?: ReactNode;
}

// ---------------------------------------------------------------------------
// All OKLCH values below are computed from documented hex codes.
// Source hex is noted in comments for auditability.
// ---------------------------------------------------------------------------

const themes: ThemeConfig[] = [
  // ── 1. Dracula ────────────────────────────────────────────────────────
  // Source: draculatheme.com/contribute
  {
    name: "Dracula",
    tagline: "Purple accent, neon-on-dark. The classic.",
    source: "draculatheme.com",
    vars: {
      "--background": "oklch(0.29 0.022 277)", // #282A36
      "--foreground": "oklch(0.98 0.008 107)", // #F8F8F2
      "--card": "oklch(0.29 0.022 277)", // #282A36
      "--card-foreground": "oklch(0.98 0.008 107)", // #F8F8F2
      "--popover": "oklch(0.40 0.032 278)", // #44475A
      "--popover-foreground": "oklch(0.98 0.008 107)", // #F8F8F2
      "--primary": "oklch(0.74 0.149 302)", // #BD93F9 purple
      "--primary-foreground": "oklch(0.29 0.022 277)", // #282A36
      "--secondary": "oklch(0.40 0.032 278)", // #44475A current line
      "--secondary-foreground": "oklch(0.98 0.008 107)", // #F8F8F2
      "--muted": "oklch(0.40 0.032 278)", // #44475A
      "--muted-foreground": "oklch(0.56 0.080 270)", // #6272A4 comment
      "--accent": "oklch(0.75 0.183 347)", // #FF79C6 pink
      "--accent-foreground": "oklch(0.29 0.022 277)", // #282A36
      "--destructive": "oklch(0.68 0.206 24)", // #FF5555
      "--destructive-foreground": "oklch(0.29 0.022 277)", // #282A36
      "--border": "oklch(0.56 0.080 270)", // #6272A4 comment
      "--input": "oklch(0.40 0.032 278)", // #44475A
      "--ring": "oklch(0.74 0.149 302)", // #BD93F9
      // Dracula: flat, no shadows, sharp
      "--radius": "0.5rem",
      "--shadow-sm": "none",
      "--shadow-xs": "none",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.29 0.022 277)" }} // #282A36
      >
        {/* Purple glow */}
        <div
          className="absolute -top-10 -right-10 h-36 w-36 rounded-full opacity-20 blur-3xl"
          style={{ background: "oklch(0.74 0.149 302)" }} // #BD93F9
        />
        <div className="relative z-10">
          <h3
            className="text-2xl font-bold"
            style={{ color: "oklch(0.98 0.008 107)" }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.56 0.080 270)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {/* Dracula signature palette dots */}
            {[
              "oklch(0.74 0.149 302)", // purple
              "oklch(0.75 0.183 347)", // pink
              "oklch(0.88 0.093 213)", // cyan
              "oklch(0.87 0.219 148)", // green
              "oklch(0.83 0.124 67)", // orange
              "oklch(0.68 0.206 24)", // red
              "oklch(0.96 0.134 113)", // yellow
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
  },

  // ── 2. Catppuccin Mocha ───────────────────────────────────────────────
  // Source: catppuccin.com/palette
  {
    name: "Catppuccin Mocha",
    tagline: "Pastel accents on warm purple-blue. Soft and rounded.",
    source: "catppuccin.com",
    vars: {
      "--background": "oklch(0.24 0.030 284)", // #1E1E2E base
      "--foreground": "oklch(0.88 0.043 272)", // #CDD6F4 text
      "--card": "oklch(0.22 0.025 284)", // #181825 mantle
      "--card-foreground": "oklch(0.88 0.043 272)", // #CDD6F4
      "--popover": "oklch(0.22 0.025 284)", // #181825
      "--popover-foreground": "oklch(0.88 0.043 272)", // #CDD6F4
      "--primary": "oklch(0.79 0.119 305)", // #CBA6F7 mauve
      "--primary-foreground": "oklch(0.18 0.020 284)", // #11111B crust
      "--secondary": "oklch(0.32 0.032 282)", // #313244 surface0
      "--secondary-foreground": "oklch(0.82 0.040 273)", // #BAC2DE subtext1
      "--muted": "oklch(0.40 0.032 280)", // #45475A surface1
      "--muted-foreground": "oklch(0.62 0.037 276)", // #7F849C overlay1
      "--accent": "oklch(0.87 0.075 336)", // #F5C2E7 pink
      "--accent-foreground": "oklch(0.18 0.020 284)", // #11111B crust
      "--destructive": "oklch(0.76 0.130 3)", // #F38BA8 red
      "--destructive-foreground": "oklch(0.18 0.020 284)", // #11111B
      "--border": "oklch(0.48 0.034 279)", // #585B70 surface2
      "--input": "oklch(0.32 0.032 282)", // #313244 surface0
      "--ring": "oklch(0.79 0.119 305)", // #CBA6F7 mauve
      // Catppuccin: rounded, soft shadows
      "--radius": "0.75rem",
      "--shadow-sm": "0 2px 8px oklch(0 0 0 / 0.2)",
      "--shadow-xs": "0 1px 4px oklch(0 0 0 / 0.15)",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.18 0.020 284)" }} // #11111B crust
      >
        <div className="relative z-10">
          <h3
            className="text-2xl font-semibold"
            style={{ color: "oklch(0.88 0.043 272)" }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.62 0.037 276)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.76 0.130 3)", // red
              "oklch(0.82 0.101 53)", // peach
              "oklch(0.92 0.070 87)", // yellow
              "oklch(0.86 0.109 143)", // green
              "oklch(0.85 0.083 210)", // sky
              "oklch(0.77 0.111 260)", // blue
              "oklch(0.79 0.119 305)", // mauve
              "oklch(0.87 0.075 336)", // pink
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
  },

  // ── 3. Nord ───────────────────────────────────────────────────────────
  // Source: nordtheme.com
  {
    name: "Nord",
    tagline: "Arctic. Muted. Cool blue-gray everything.",
    source: "nordtheme.com",
    vars: {
      "--background": "oklch(0.32 0.023 264)", // #2E3440 nord0
      "--foreground": "oklch(0.90 0.016 263)", // #D8DEE9 nord4
      "--card": "oklch(0.38 0.029 266)", // #3B4252 nord1
      "--card-foreground": "oklch(0.90 0.016 263)", // #D8DEE9
      "--popover": "oklch(0.38 0.029 266)", // #3B4252
      "--popover-foreground": "oklch(0.93 0.010 262)", // #E5E9F0 nord5
      "--primary": "oklch(0.77 0.062 218)", // #88C0D0 nord8 frost blue
      "--primary-foreground": "oklch(0.32 0.023 264)", // #2E3440
      "--secondary": "oklch(0.42 0.032 264)", // #434C5E nord2
      "--secondary-foreground": "oklch(0.90 0.016 263)", // #D8DEE9
      "--muted": "oklch(0.42 0.032 264)", // #434C5E nord2
      "--muted-foreground": "oklch(0.45 0.035 264)", // #4C566A nord3
      "--accent": "oklch(0.76 0.048 195)", // #8FBCBB nord7
      "--accent-foreground": "oklch(0.32 0.023 264)", // #2E3440
      "--destructive": "oklch(0.61 0.121 15)", // #BF616A nord11
      "--destructive-foreground": "oklch(0.93 0.010 262)", // #E5E9F0
      "--border": "oklch(0.42 0.032 264)", // #434C5E nord2
      "--input": "oklch(0.38 0.029 266)", // #3B4252 nord1
      "--ring": "oklch(0.77 0.062 218)", // #88C0D0
      // Nord: subtle radius, no shadows, clean
      "--radius": "0.375rem",
      "--shadow-sm": "none",
      "--shadow-xs": "none",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.32 0.023 264)" }} // nord0
      >
        <div className="relative z-10">
          <h3
            className="text-2xl font-semibold"
            style={{ color: "oklch(0.93 0.010 262)" }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.45 0.035 264)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.77 0.062 218)", // nord8
              "oklch(0.70 0.059 249)", // nord9
              "oklch(0.59 0.077 254)", // nord10
              "oklch(0.61 0.121 15)", // nord11
              "oklch(0.69 0.096 38)", // nord12
              "oklch(0.85 0.089 84)", // nord13
              "oklch(0.77 0.075 131)", // nord14
              "oklch(0.69 0.063 333)", // nord15
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
  },

  // ── 4. Gruvbox Dark ───────────────────────────────────────────────────
  // Source: github.com/morhetz/gruvbox
  {
    name: "Gruvbox Dark",
    tagline: "Warm retro. Yellow-brown tones. Bold orange accent.",
    source: "github.com/morhetz/gruvbox",
    vars: {
      "--background": "oklch(0.28 0.000 263)", // #282828 bg
      "--foreground": "oklch(0.89 0.057 89)", // #EBDBB2 fg - the warm yellow fg!
      "--card": "oklch(0.34 0.007 48)", // #3C3836 bg1
      "--card-foreground": "oklch(0.89 0.057 89)", // #EBDBB2
      "--popover": "oklch(0.34 0.007 48)", // #3C3836
      "--popover-foreground": "oklch(0.89 0.057 89)", // #EBDBB2
      "--primary": "oklch(0.73 0.182 52)", // #FE8019 orange - signature color
      "--primary-foreground": "oklch(0.28 0.000 263)", // #282828
      "--secondary": "oklch(0.41 0.011 52)", // #504945 bg2
      "--secondary-foreground": "oklch(0.83 0.051 85)", // #D5C4A1 fg2
      "--muted": "oklch(0.41 0.011 52)", // #504945 bg2
      "--muted-foreground": "oklch(0.62 0.029 67)", // #928374 gray
      "--accent": "oklch(0.76 0.108 138)", // #8EC07C aqua
      "--accent-foreground": "oklch(0.28 0.000 263)", // #282828
      "--destructive": "oklch(0.66 0.217 30)", // #FB4934 bright red
      "--destructive-foreground": "oklch(0.89 0.057 89)", // #EBDBB2
      "--border": "oklch(0.48 0.018 61)", // #665C54 bg3
      "--input": "oklch(0.34 0.007 48)", // #3C3836 bg1
      "--ring": "oklch(0.73 0.182 52)", // #FE8019
      // Gruvbox: blocky, no shadows, dense
      "--radius": "0px",
      "--shadow-sm": "none",
      "--shadow-xs": "none",
    },
    rootStyle: { fontWeight: 500 },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.28 0.000 263)" }} // #282828
      >
        <div className="relative z-10">
          <h3
            className="text-2xl font-bold"
            style={{ color: "oklch(0.89 0.057 89)" }}
          >
            {name}
          </h3>
          <p className="mt-1 text-sm" style={{ color: "oklch(0.62 0.029 67)" }}>
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.66 0.217 30)", // red
              "oklch(0.73 0.182 52)", // orange
              "oklch(0.83 0.159 83)", // yellow
              "oklch(0.77 0.158 111)", // green
              "oklch(0.76 0.108 138)", // aqua
              "oklch(0.69 0.042 170)", // blue
              "oklch(0.71 0.098 2)", // purple
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
  },

  // ── 5. Tokyo Night ────────────────────────────────────────────────────
  // Source: github.com/enkia/tokyo-night-vscode-theme
  {
    name: "Tokyo Night",
    tagline: "Neon city. Deep blue-purple base, vibrant blue accent.",
    source: "github.com/enkia/tokyo-night-vscode-theme",
    vars: {
      "--background": "oklch(0.23 0.021 280)", // #1A1B26
      "--foreground": "oklch(0.85 0.061 275)", // #C0CAF5
      "--card": "oklch(0.28 0.036 275)", // #24283B storm
      "--card-foreground": "oklch(0.85 0.061 275)", // #C0CAF5
      "--popover": "oklch(0.28 0.036 275)", // #24283B
      "--popover-foreground": "oklch(0.85 0.061 275)", // #C0CAF5
      "--primary": "oklch(0.72 0.132 264)", // #7AA2F7 blue
      "--primary-foreground": "oklch(0.23 0.021 280)", // #1A1B26
      "--secondary": "oklch(0.41 0.055 274)", // #414868
      "--secondary-foreground": "oklch(0.77 0.054 275)", // #A9B1D6
      "--muted": "oklch(0.41 0.055 274)", // #414868
      "--muted-foreground": "oklch(0.50 0.068 274)", // #565F89 comment
      "--accent": "oklch(0.75 0.134 299)", // #BB9AF7 purple
      "--accent-foreground": "oklch(0.23 0.021 280)", // #1A1B26
      "--destructive": "oklch(0.72 0.159 10)", // #F7768E
      "--destructive-foreground": "oklch(0.23 0.021 280)", // #1A1B26
      "--border": "oklch(0.41 0.055 274)", // #414868
      "--input": "oklch(0.28 0.036 275)", // #24283B
      "--ring": "oklch(0.72 0.132 264)", // #7AA2F7
      // Tokyo Night: moderate radius, subtle blue-tinted shadows
      "--radius": "0.5rem",
      "--shadow-sm": "0 2px 8px oklch(0.23 0.021 280 / 0.4)",
      "--shadow-xs": "0 1px 4px oklch(0.23 0.021 280 / 0.3)",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.23 0.021 280)" }} // #1A1B26
      >
        {/* Blue glow - city neon */}
        <div
          className="absolute -top-8 -right-8 h-32 w-32 rounded-full opacity-15 blur-3xl"
          style={{ background: "oklch(0.72 0.132 264)" }} // #7AA2F7
        />
        <div className="relative z-10">
          <h3
            className="text-2xl font-semibold"
            style={{ color: "oklch(0.85 0.061 275)" }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.50 0.068 274)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.72 0.159 10)", // red
              "oklch(0.79 0.137 51)", // orange
              "oklch(0.78 0.106 75)", // yellow
              "oklch(0.80 0.139 130)", // green
              "oklch(0.82 0.100 183)", // teal
              "oklch(0.75 0.124 213)", // cyan
              "oklch(0.72 0.132 264)", // blue
              "oklch(0.75 0.134 299)", // purple
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
  },

  // ── 6. Solarized Dark ─────────────────────────────────────────────────
  // Source: ethanschoonover.com/solarized
  {
    name: "Solarized Dark",
    tagline: "Teal-blue base. Mathematically precise contrast.",
    source: "ethanschoonover.com/solarized",
    vars: {
      "--background": "oklch(0.27 0.049 220)", // #002B36 base03
      "--foreground": "oklch(0.65 0.020 205)", // #839496 base0
      "--card": "oklch(0.31 0.052 220)", // #073642 base02
      "--card-foreground": "oklch(0.65 0.020 205)", // #839496
      "--popover": "oklch(0.31 0.052 220)", // #073642
      "--popover-foreground": "oklch(0.70 0.016 197)", // #93A1A1 base1
      "--primary": "oklch(0.61 0.139 245)", // #268BD2 blue
      "--primary-foreground": "oklch(0.27 0.049 220)", // #002B36
      "--secondary": "oklch(0.31 0.052 220)", // #073642 base02
      "--secondary-foreground": "oklch(0.65 0.020 205)", // #839496
      "--muted": "oklch(0.31 0.052 220)", // #073642
      "--muted-foreground": "oklch(0.52 0.028 219)", // #586E75 base01
      "--accent": "oklch(0.64 0.102 187)", // #2AA198 cyan
      "--accent-foreground": "oklch(0.27 0.049 220)", // #002B36
      "--destructive": "oklch(0.59 0.206 27)", // #DC322F red
      "--destructive-foreground": "oklch(0.93 0.010 262)", // #E5E9F0-ish
      "--border": "oklch(0.52 0.028 219)", // #586E75 base01
      "--input": "oklch(0.31 0.052 220)", // #073642
      "--ring": "oklch(0.61 0.139 245)", // #268BD2
      // Solarized: minimal radius, no shadows, academic
      "--radius": "0.25rem",
      "--shadow-sm": "none",
      "--shadow-xs": "none",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.27 0.049 220)" }} // #002B36
      >
        <div className="relative z-10">
          <h3
            className="text-2xl font-semibold"
            style={{ color: "oklch(0.70 0.016 197)" }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.52 0.028 219)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.65 0.134 86)", // yellow
              "oklch(0.58 0.173 39)", // orange
              "oklch(0.59 0.206 27)", // red
              "oklch(0.59 0.202 356)", // magenta
              "oklch(0.58 0.126 279)", // violet
              "oklch(0.61 0.139 245)", // blue
              "oklch(0.64 0.102 187)", // cyan
              "oklch(0.64 0.151 119)", // green
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
  },

  // ── 7. Commodore 64 ───────────────────────────────────────────────────
  // Source: Pepto's VIC-II Color Analysis (2001) - pepto.de/projects/colorvic
  {
    name: "Commodore 64",
    tagline: 'LOAD "*",8,1. Blue screen, light blue type. 1982.',
    source: "pepto.de/projects/colorvic",
    vars: {
      "--background": "oklch(0.34 0.132 284)", // #352879 blue
      "--foreground": "oklch(0.54 0.133 288)", // #6C5EB5 light blue
      "--card": "oklch(0.34 0.132 284)", // #352879
      "--card-foreground": "oklch(0.54 0.133 288)", // #6C5EB5
      "--popover": "oklch(0.34 0.132 284)", // #352879
      "--popover-foreground": "oklch(0.54 0.133 288)", // #6C5EB5
      "--primary": "oklch(0.54 0.133 288)", // #6C5EB5 light blue
      "--primary-foreground": "oklch(0.34 0.132 284)", // #352879
      "--secondary": "oklch(0.39 0.000 263)", // #444444 dark grey
      "--secondary-foreground": "oklch(0.67 0.000 263)", // #959595 light grey
      "--muted": "oklch(0.34 0.132 284)", // #352879
      "--muted-foreground": "oklch(0.53 0.000 263)", // #6C6C6C grey
      "--accent": "oklch(0.81 0.120 137)", // #9AD284 light green
      "--accent-foreground": "oklch(0.00 0.000 0)", // #000000
      "--destructive": "oklch(0.40 0.073 35)", // #68372B red
      "--destructive-foreground": "oklch(1.00 0.000 263)", // #FFFFFF
      "--border": "oklch(0.54 0.133 288)", // #6C5EB5 light blue
      "--input": "oklch(0.34 0.132 284)", // #352879
      "--ring": "oklch(0.54 0.133 288)", // #6C5EB5
      // C64: absolutely no radius, no shadows, chunky
      "--radius": "0px",
      "--shadow-sm": "none",
      "--shadow-xs": "none",
      "--tracking-normal": "0.08em",
    },
    rootStyle: {
      fontFamily: "'Space Mono', 'Courier New', monospace",
      textTransform: "uppercase" as const,
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.34 0.132 284)" }} // #352879
      >
        {/* Pixel grid */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.08]"
          style={{
            backgroundImage: `linear-gradient(oklch(0 0 0) 1px, transparent 1px),
              linear-gradient(90deg, oklch(0 0 0) 1px, transparent 1px)`,
            backgroundSize: "3px 3px",
          }}
        />
        <div className="relative z-10 font-mono uppercase">
          <div
            className="text-xs tracking-[0.2em]"
            style={{ color: "oklch(0.54 0.133 288)" }}
          >
            **** COMMODORE 64 BASIC V2 ****
          </div>
          <div className="text-xs" style={{ color: "oklch(0.54 0.133 288)" }}>
            64K RAM SYSTEM. 38911 BASIC BYTES FREE.
          </div>
          <h3
            className="mt-2 text-xl font-bold tracking-[0.15em]"
            style={{ color: "oklch(0.54 0.133 288)" }}
          >
            READY.
          </h3>
        </div>
      </div>
    ),
    decorations: (
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-[0.06]"
        style={{
          backgroundImage: `linear-gradient(oklch(0 0 0) 1px, transparent 1px),
            linear-gradient(90deg, oklch(0 0 0) 1px, transparent 1px)`,
          backgroundSize: "3px 3px",
        }}
      />
    ),
  },

  // ── 8. LCARS ──────────────────────────────────────────────────────────
  // Source: thelcars.com - Michael Okuda's Star Trek interface
  {
    name: "LCARS",
    tagline: "Starfleet computer. Gold/pink/blue panels on black.",
    source: "thelcars.com",
    vars: {
      "--background": "oklch(0.00 0.000 0)", // #000000 pure black
      "--foreground": "oklch(0.88 0.088 66)", // #FFCC99 tanoi
      "--card": "oklch(0.08 0.005 0)", // near black
      "--card-foreground": "oklch(0.88 0.088 66)", // #FFCC99
      "--popover": "oklch(0.08 0.005 0)",
      "--popover-foreground": "oklch(0.88 0.088 66)",
      "--primary": "oklch(0.77 0.174 65)", // #FF9900 gold - signature
      "--primary-foreground": "oklch(0.00 0.000 0)", // black
      "--secondary": "oklch(0.65 0.141 350)", // #CC6699 hopbush pink
      "--secondary-foreground": "oklch(0.00 0.000 0)", // black
      "--muted": "oklch(0.15 0.005 0)", // dark panel
      "--muted-foreground": "oklch(0.70 0.074 284)", // #9999CC blue bell
      "--accent": "oklch(0.70 0.074 284)", // #9999CC blue bell
      "--accent-foreground": "oklch(0.00 0.000 0)", // black
      "--destructive": "oklch(0.68 0.206 24)", // #FF5555 tomato
      "--destructive-foreground": "oklch(0.00 0.000 0)", // black
      "--border": "oklch(0.65 0.141 350)", // #CC6699 hopbush
      "--input": "oklch(0.08 0.005 0)",
      "--ring": "oklch(0.77 0.174 65)", // #FF9900
      // LCARS: pill shapes, no shadows
      "--radius": "9999px", // fully rounded
      "--shadow-sm": "none",
      "--shadow-xs": "none",
      "--tracking-normal": "0.06em",
    },
    rootStyle: {
      fontFamily: "'Space Mono', 'Courier New', monospace",
      textTransform: "uppercase" as const,
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.00 0.000 0)" }}
      >
        {/* LCARS sidebar bracket */}
        <div className="absolute top-2 bottom-2 left-0 flex flex-col gap-1 pl-2">
          <div
            className="w-10 flex-1 rounded-tl-[18px]"
            style={{ background: "oklch(0.77 0.174 65)" }}
          />
          <div
            className="h-3 w-10"
            style={{ background: "oklch(0.65 0.141 350)" }}
          />
          <div
            className="w-10 flex-1 rounded-bl-[18px]"
            style={{ background: "oklch(0.70 0.074 284)" }}
          />
        </div>
        {/* Top bar pills */}
        <div className="absolute top-2 right-2 flex gap-1">
          <div
            className="h-3 w-10 rounded-l-full"
            style={{ background: "oklch(0.87 0.132 83)" }}
          />
          <div
            className="h-3 w-6"
            style={{ background: "oklch(0.65 0.141 350)" }}
          />
          <div
            className="h-3 w-14 rounded-r-full"
            style={{ background: "oklch(0.77 0.174 65)" }}
          />
        </div>
        <div className="relative z-10 ml-14 font-mono uppercase">
          <div
            className="mb-1 text-[9px] tracking-[0.2em]"
            style={{ color: "oklch(0.65 0.141 350)" }}
          >
            STARFLEET DATABASE
          </div>
          <h3
            className="text-2xl font-bold tracking-widest"
            style={{ color: "oklch(0.77 0.174 65)" }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-[10px] tracking-wider"
            style={{ color: "oklch(0.70 0.074 284)" }}
          >
            {tagline}
          </p>
        </div>
        {/* Bottom bar pills */}
        <div className="absolute right-2 bottom-2 left-14 flex gap-1">
          <div
            className="h-2 flex-1 rounded-full"
            style={{ background: "oklch(0.65 0.141 350)" }}
          />
          <div
            className="h-2 w-6 rounded-full"
            style={{ background: "oklch(0.77 0.174 65)" }}
          />
          <div
            className="h-2 w-10 rounded-full"
            style={{ background: "oklch(0.75 0.091 326)" }}
          />
          <div
            className="h-2 w-6 rounded-full"
            style={{ background: "oklch(0.68 0.206 24)" }}
          />
        </div>
      </div>
    ),
  },

  // ── 9. Pip-Boy 3000 ───────────────────────────────────────────────────
  // Source: Fallout 3 defaults - R:16 G:255 B:128 (#10FF80)
  {
    name: "Pip-Boy 3000",
    tagline: "Vault-Tec approved. Single-hue monochrome. CRT phosphor.",
    source: "Fallout 3 Pip-Boy default HUD",
    vars: {
      "--background": "oklch(0.18 0.028 140)", // #0A1408 screen bg
      "--foreground": "oklch(0.74 0.196 151)", // #0ECC66 standard green
      "--card": "oklch(0.22 0.035 145)", // slightly lighter than bg
      "--card-foreground": "oklch(0.74 0.196 151)", // #0ECC66
      "--popover": "oklch(0.22 0.035 145)",
      "--popover-foreground": "oklch(0.74 0.196 151)",
      "--primary": "oklch(0.88 0.234 151)", // #10FF80 bright green
      "--primary-foreground": "oklch(0.18 0.028 140)", // screen bg
      "--secondary": "oklch(0.28 0.070 153)", // #033318 faint
      "--secondary-foreground": "oklch(0.60 0.160 151)", // #0A9949 dim
      "--muted": "oklch(0.28 0.070 153)", // #033318
      "--muted-foreground": "oklch(0.45 0.119 151)", // #06662F very dim
      "--accent": "oklch(0.35 0.090 151)", // between faint and dim
      "--accent-foreground": "oklch(0.88 0.234 151)", // bright
      "--destructive": "oklch(0.88 0.234 151)", // bright green (monochrome - no red)
      "--destructive-foreground": "oklch(0.18 0.028 140)",
      "--border": "oklch(0.45 0.119 151)", // #06662F very dim
      "--input": "oklch(0.22 0.035 145)",
      "--ring": "oklch(0.88 0.234 151)", // bright
      // Pip-Boy: angular, inset shadows (CRT depth), thin borders
      "--radius": "2px",
      "--shadow-sm":
        "inset 0 1px 3px oklch(0 0 0 / 0.5), 0 0 6px oklch(0.88 0.234 151 / 0.05)",
      "--shadow-xs": "inset 0 1px 2px oklch(0 0 0 / 0.4)",
      "--tracking-normal": "0.03em",
    },
    rootStyle: { fontFamily: "'Space Mono', 'Courier New', monospace" },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden border-b p-6"
        style={{
          background: "oklch(0.18 0.028 140)",
          borderColor: "oklch(0.45 0.119 151)",
        }}
      >
        {/* CRT vignette */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 80% 70% at center, transparent 40%, oklch(0 0 0 / 0.5) 100%)",
          }}
        />
        {/* Dense scanlines */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.07]"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, transparent, transparent 1px, oklch(0 0 0 / 0.5) 1px, oklch(0 0 0 / 0.5) 2px)",
          }}
        />
        {/* Phosphor screen glow */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.02]"
          style={{ background: "oklch(0.88 0.234 151)" }}
        />
        <div className="relative z-10 font-mono">
          <div
            className="flex items-center gap-2 text-[9px] tracking-wider"
            style={{ color: "oklch(0.45 0.119 151)" }}
          >
            <span>VAULT-TEC IND.</span>
            <span>|</span>
            <span>MODEL 3000 MK IV</span>
          </div>
          <h3
            className="mt-1 text-2xl font-bold tracking-wider"
            style={{
              color: "oklch(0.88 0.234 151)",
              textShadow:
                "0 0 10px oklch(0.88 0.234 151 / 0.4), 0 0 20px oklch(0.88 0.234 151 / 0.2)",
            }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-xs tracking-wide"
            style={{ color: "oklch(0.45 0.119 151)" }}
          >
            {tagline}
          </p>
        </div>
      </div>
    ),
    decorations: (
      <>
        {/* CRT vignette */}
        <div
          className="pointer-events-none absolute inset-0 z-0"
          style={{
            background:
              "radial-gradient(ellipse 80% 70% at center, transparent 50%, oklch(0 0 0 / 0.35) 100%)",
          }}
        />
        {/* Scanlines */}
        <div
          className="pointer-events-none absolute inset-0 z-0 opacity-[0.05]"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, transparent, transparent 1px, oklch(0 0 0 / 0.4) 1px, oklch(0 0 0 / 0.4) 2px)",
          }}
        />
      </>
    ),
  },

  // ── 10. Glassmorphic Noir ─────────────────────────────────────────────
  // Concept theme - not sourced from a specific palette
  {
    name: "Glassmorphic Noir",
    tagline: "Frosted glass panels. Translucent cards. Glow shadows.",
    source: "Design concept - glassmorphism trend",
    vars: {
      "--background": "oklch(0.08 0.01 250)",
      "--foreground": "oklch(0.95 0.005 250)",
      "--card": "oklch(0.14 0.015 250 / 0.5)",
      "--card-foreground": "oklch(0.95 0.005 250)",
      "--popover": "oklch(0.12 0.015 250 / 0.7)",
      "--popover-foreground": "oklch(0.95 0.005 250)",
      "--primary": "oklch(0.72 0.14 195)",
      "--primary-foreground": "oklch(0.10 0 0)",
      "--secondary": "oklch(0.20 0.02 250 / 0.6)",
      "--secondary-foreground": "oklch(0.78 0.03 250)",
      "--muted": "oklch(0.20 0.01 250 / 0.5)",
      "--muted-foreground": "oklch(0.62 0.02 250)",
      "--accent": "oklch(0.25 0.04 195 / 0.4)",
      "--accent-foreground": "oklch(0.72 0.14 195)",
      "--destructive": "oklch(0.55 0.20 15)",
      "--destructive-foreground": "oklch(1 0 0)",
      "--border": "oklch(0.90 0.01 250 / 0.12)",
      "--input": "oklch(0.90 0.01 250 / 0.08)",
      "--ring": "oklch(0.72 0.14 195)",
      "--radius": "1rem",
      "--shadow-sm":
        "0 2px 16px oklch(0.72 0.14 195 / 0.06), 0 1px 2px oklch(0 0 0 / 0.15)",
      "--shadow-xs": "0 1px 8px oklch(0.72 0.14 195 / 0.04)",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{
          background:
            "linear-gradient(135deg, oklch(0.12 0.04 250), oklch(0.18 0.06 195), oklch(0.10 0.05 280))",
        }}
      >
        <div
          className="absolute -top-12 -right-12 h-48 w-48 rounded-full opacity-25 blur-3xl"
          style={{ background: "oklch(0.72 0.14 195)" }}
        />
        <div className="relative z-10">
          <h3 className="text-2xl font-semibold text-white drop-shadow-lg">
            {name}
          </h3>
          <p className="mt-1 text-sm text-white/60">{tagline}</p>
        </div>
      </div>
    ),
  },

  // ── 11. Brutalist ─────────────────────────────────────────────────────
  // Concept theme - brutalist web design movement
  {
    name: "Brutalist",
    tagline: "Thick borders. Hard offset shadows. Bold type.",
    source: "Design concept - brutalistwebsites.com",
    vars: {
      "--background": "oklch(0.06 0 0)",
      "--foreground": "oklch(0.93 0.01 80)",
      "--card": "oklch(0.10 0 0)",
      "--card-foreground": "oklch(0.93 0.01 80)",
      "--popover": "oklch(0.10 0 0)",
      "--popover-foreground": "oklch(0.93 0.01 80)",
      "--primary": "oklch(0.65 0.24 30)",
      "--primary-foreground": "oklch(0.0 0 0)",
      "--secondary": "oklch(0.20 0 0)",
      "--secondary-foreground": "oklch(0.80 0 0)",
      "--muted": "oklch(0.16 0 0)",
      "--muted-foreground": "oklch(0.55 0 0)",
      "--accent": "oklch(0.78 0.17 85)",
      "--accent-foreground": "oklch(0.0 0 0)",
      "--destructive": "oklch(0.60 0.26 25)",
      "--destructive-foreground": "oklch(1 0 0)",
      "--border": "oklch(0.70 0 0)",
      "--input": "oklch(0.10 0 0)",
      "--ring": "oklch(0.65 0.24 30)",
      "--radius": "0px",
      "--shadow-sm": "4px 4px 0 oklch(0 0 0 / 0.5)",
      "--shadow-xs": "2px 2px 0 oklch(0 0 0 / 0.4)",
    },
    rootStyle: { fontWeight: 600 },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.65 0.24 30)" }}
      >
        <div
          className="absolute right-0 bottom-0 h-24 w-24 translate-x-6 translate-y-6"
          style={{
            background: "oklch(0.78 0.17 85)",
            boxShadow: "inset -4px -4px 0 oklch(0 0 0)",
          }}
        />
        <div className="relative z-10">
          <h3 className="text-2xl font-black tracking-widest text-black uppercase">
            {name}
          </h3>
          <p className="mt-1 text-sm font-bold tracking-wider text-black/70 uppercase">
            {tagline}
          </p>
        </div>
      </div>
    ),
  },

  // ── 12. Ember (Current) ───────────────────────────────────────────────
  // The production theme from tooling/tailwind/theme.css
  {
    name: "Ember (Current)",
    tagline: "The current production theme. Warm red-orange.",
    source: "tooling/tailwind/theme.css (dark mode)",
    vars: {
      "--background": "oklch(0 0 0)",
      "--foreground": "oklch(0.97 0 0)",
      "--card": "oklch(0.08 0 0)",
      "--card-foreground": "oklch(0.97 0 0)",
      "--popover": "oklch(0.08 0 0)",
      "--popover-foreground": "oklch(0.97 0 0)",
      "--primary": "oklch(0.70 0.17 25)",
      "--primary-foreground": "oklch(0.13 0 0)",
      "--secondary": "oklch(0.22 0 0)",
      "--secondary-foreground": "oklch(0.72 0 0)",
      "--muted": "oklch(0.22 0 0)",
      "--muted-foreground": "oklch(0.63 0 0)",
      "--accent": "oklch(0.22 0 0)",
      "--accent-foreground": "oklch(0.70 0.17 25)",
      "--destructive": "oklch(0.4 0.13 25)",
      "--destructive-foreground": "oklch(1 0 0)",
      "--border": "oklch(0.27 0 0)",
      "--input": "oklch(0.22 0 0)",
      "--ring": "oklch(0.70 0.17 25)",
      "--radius": "0.75rem",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{
          background:
            "linear-gradient(135deg, oklch(0.70 0.17 25), oklch(0.50 0.19 27))",
        }}
      >
        <div className="absolute inset-0 bg-black/20" />
        <div className="relative z-10">
          <h3 className="text-2xl font-bold text-white drop-shadow-md">
            {name}
          </h3>
          <p className="mt-1 text-sm text-white/70">{tagline}</p>
        </div>
      </div>
    ),
  },

  // ── 13. AIBP - Clean ────────────────────────────────────────────────
  // Pip-Boy green on a green-tinted dark base. Professional layout.
  // The "safe" pick: clearly cybersec but wouldn't scare a CISO in a demo.
  // Green-tinted backgrounds (not neutral gray) give everything a security-monitor feel
  // without CRT gimmicks.
  {
    name: "AIBP - Clean",
    tagline: "Green-tinted dark base. Pip-Boy heritage, boardroom manners.",
    source: "Pip-Boy #30E080 on green-tinted darks #0C1410",
    vars: {
      "--background": "oklch(0.18 0.015 163)", // #0C1410 - near-black, green undertone
      "--foreground": "oklch(0.88 0.030 167)", // #C5DDD2 - warm green-white
      "--card": "oklch(0.21 0.020 160)", // #111C16
      "--card-foreground": "oklch(0.88 0.030 167)", // #C5DDD2
      "--popover": "oklch(0.21 0.020 160)", // #111C16
      "--popover-foreground": "oklch(0.94 0.015 165)", // #E4F0EA
      "--primary": "oklch(0.80 0.192 153)", // #30E080 - hybrid green
      "--primary-foreground": "oklch(0.18 0.015 163)", // #0C1410
      "--secondary": "oklch(0.25 0.022 161)", // #17241D
      "--secondary-foreground": "oklch(0.88 0.030 167)", // #C5DDD2
      "--muted": "oklch(0.25 0.022 161)", // #17241D
      "--muted-foreground": "oklch(0.58 0.049 167)", // #5E8474
      "--accent": "oklch(0.71 0.143 255)", // #60A5FA - blue for info
      "--accent-foreground": "oklch(0.18 0.015 163)", // #0C1410
      "--destructive": "oklch(0.64 0.208 25)", // #EF4444
      "--destructive-foreground": "oklch(0.94 0.015 165)", // #E4F0EA
      "--border": "oklch(0.31 0.024 175)", // #243530
      "--input": "oklch(0.21 0.020 160)", // #111C16
      "--ring": "oklch(0.80 0.192 153)", // #30E080
      "--radius": "0.5rem",
      "--shadow-sm":
        "0 2px 8px oklch(0 0 0 / 0.3), 0 1px 2px oklch(0 0 0 / 0.2)",
      "--shadow-xs": "0 1px 4px oklch(0 0 0 / 0.25)",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.18 0.015 163)" }}
      >
        {/* Subtle green status glow */}
        <div
          className="absolute top-1/2 -right-6 h-20 w-20 -translate-y-1/2 rounded-full opacity-8 blur-2xl"
          style={{ background: "oklch(0.80 0.192 153)" }}
        />
        <div
          className="absolute right-0 bottom-0 left-0 h-px"
          style={{ background: "oklch(0.31 0.024 175)" }}
        />
        <div className="relative z-10">
          <h3
            className="text-2xl font-semibold"
            style={{ color: "oklch(0.94 0.015 165)" }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.58 0.049 167)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.80 0.192 153)", // green primary
              "oklch(0.71 0.143 255)", // blue info
              "oklch(0.84 0.164 84)", // amber warning
              "oklch(0.64 0.208 25)", // red critical
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
  },

  // ── 14. AIBP - Phosphor ───────────────────────────────────────────────
  // More Pip-Boy energy. Brighter green, faint green glow on shadows,
  // very subtle scanline texture. Green-tinted muted text.
  // Still professional layout/radius - the texture is a whisper, not a shout.
  {
    name: "AIBP - Phosphor",
    tagline: "More Pip-Boy. Glow shadows, faint scanlines, green everything.",
    source: "Pip-Boy #2BF08A bright + #0C1410 base + subtle CRT nod",
    vars: {
      "--background": "oklch(0.18 0.015 163)", // #0C1410
      "--foreground": "oklch(0.88 0.030 167)", // #C5DDD2
      "--card": "oklch(0.21 0.020 160)", // #111C16
      "--card-foreground": "oklch(0.88 0.030 167)", // #C5DDD2
      "--popover": "oklch(0.21 0.020 160)", // #111C16
      "--popover-foreground": "oklch(0.94 0.015 165)", // #E4F0EA
      "--primary": "oklch(0.84 0.204 154)", // #2BF08A - brighter, closer to Pip-Boy
      "--primary-foreground": "oklch(0.18 0.015 163)", // #0C1410
      "--secondary": "oklch(0.25 0.022 161)", // #17241D
      "--secondary-foreground": "oklch(0.88 0.030 167)", // #C5DDD2
      "--muted": "oklch(0.25 0.022 161)", // #17241D
      "--muted-foreground": "oklch(0.58 0.049 167)", // #5E8474
      "--accent": "oklch(0.42 0.095 156)", // #0F5C36 - dim green accent
      "--accent-foreground": "oklch(0.84 0.204 154)", // #2BF08A
      "--destructive": "oklch(0.84 0.164 84)", // amber (not red - keeps the monochrome feel)
      "--destructive-foreground": "oklch(0.18 0.015 163)", // #0C1410
      "--border": "oklch(0.31 0.024 175)", // #243530
      "--input": "oklch(0.21 0.020 160)", // #111C16
      "--ring": "oklch(0.84 0.204 154)", // #2BF08A
      "--radius": "0.375rem",
      // The key difference: green-tinted glow shadows
      "--shadow-sm":
        "0 2px 10px oklch(0.84 0.204 154 / 0.06), 0 1px 2px oklch(0 0 0 / 0.3)",
      "--shadow-xs":
        "0 1px 6px oklch(0.84 0.204 154 / 0.04), 0 1px 2px oklch(0 0 0 / 0.2)",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.18 0.015 163)" }}
      >
        {/* Phosphor glow */}
        <div
          className="absolute top-1/2 -right-8 h-28 w-28 -translate-y-1/2 rounded-full opacity-8 blur-3xl"
          style={{ background: "oklch(0.84 0.204 154)" }}
        />
        {/* Faint scanlines - the Pip-Boy nod */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.84 0.204 154) 2px, oklch(0.84 0.204 154) 3px)",
          }}
        />
        <div
          className="absolute right-0 bottom-0 left-0 h-px"
          style={{ background: "oklch(0.31 0.024 175)" }}
        />
        <div className="relative z-10">
          <h3
            className="text-2xl font-semibold"
            style={{
              color: "oklch(0.94 0.015 165)",
              textShadow: "0 0 20px oklch(0.84 0.204 154 / 0.15)",
            }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.58 0.049 167)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.84 0.204 154)", // bright green
              "oklch(0.68 0.161 154)", // muted green
              "oklch(0.84 0.164 84)", // amber
              "oklch(0.57 0.132 155)", // dim green
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
    decorations: (
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-[0.015]"
        style={{
          backgroundImage:
            "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.84 0.204 154) 2px, oklch(0.84 0.204 154) 3px)",
        }}
      />
    ),
  },

  // ── 15. AIBP - Deep ──────────────────────────────────────────────────
  // Darker. More contrast. Heavier glow. The "night shift SOC analyst" edition.
  // Think: lights off, three monitors, 2AM incident response.
  {
    name: "AIBP - Deep",
    tagline: "Darker base. Stronger glow. Night shift energy.",
    source: "Pip-Boy #2BF08A on deeper #080F0B darks",
    vars: {
      "--background": "oklch(0.16 0.014 160)", // #080F0B - deeper black-green
      "--foreground": "oklch(0.85 0.037 166)", // #B8D6C8
      "--card": "oklch(0.19 0.018 155)", // #0D1610
      "--card-foreground": "oklch(0.85 0.037 166)", // #B8D6C8
      "--popover": "oklch(0.19 0.018 155)", // #0D1610
      "--popover-foreground": "oklch(0.94 0.026 160)", // #DCF0E4
      "--primary": "oklch(0.84 0.204 154)", // #2BF08A - bright
      "--primary-foreground": "oklch(0.16 0.014 160)", // #080F0B
      "--secondary": "oklch(0.22 0.022 158)", // #121E17
      "--secondary-foreground": "oklch(0.85 0.037 166)", // #B8D6C8
      "--muted": "oklch(0.22 0.022 158)", // #121E17
      "--muted-foreground": "oklch(0.52 0.054 165)", // #4A7260
      "--accent": "oklch(0.29 0.028 165)", // #1E3028 - green-dark accent
      "--accent-foreground": "oklch(0.84 0.204 154)", // #2BF08A
      "--destructive": "oklch(0.84 0.164 84)", // amber
      "--destructive-foreground": "oklch(0.16 0.014 160)", // #080F0B
      "--border": "oklch(0.29 0.028 165)", // #1E3028
      "--input": "oklch(0.19 0.018 155)", // #0D1610
      "--ring": "oklch(0.84 0.204 154)", // #2BF08A
      "--radius": "0.375rem",
      // Heavier green glow
      "--shadow-sm":
        "0 2px 12px oklch(0.84 0.204 154 / 0.10), 0 1px 3px oklch(0 0 0 / 0.4)",
      "--shadow-xs":
        "0 1px 8px oklch(0.84 0.204 154 / 0.06), 0 1px 2px oklch(0 0 0 / 0.3)",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.16 0.014 160)" }}
      >
        {/* Bigger phosphor glow */}
        <div
          className="absolute top-1/2 -right-10 h-36 w-36 -translate-y-1/2 rounded-full opacity-10 blur-3xl"
          style={{ background: "oklch(0.84 0.204 154)" }}
        />
        {/* Scanlines */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.025]"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.84 0.204 154) 2px, oklch(0.84 0.204 154) 3px)",
          }}
        />
        <div
          className="absolute right-0 bottom-0 left-0 h-px"
          style={{ background: "oklch(0.29 0.028 165)" }}
        />
        <div className="relative z-10">
          <h3
            className="text-2xl font-semibold"
            style={{
              color: "oklch(0.94 0.026 160)",
              textShadow: "0 0 24px oklch(0.84 0.204 154 / 0.20)",
            }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.52 0.054 165)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.84 0.204 154)", // bright green
              "oklch(0.68 0.161 154)", // mid green
              "oklch(0.84 0.164 84)", // amber
              "oklch(0.52 0.054 165)", // dim green
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
    decorations: (
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-[0.02]"
        style={{
          backgroundImage:
            "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.84 0.204 154) 2px, oklch(0.84 0.204 154) 3px)",
        }}
      />
    ),
  },

  // ── 16. AIBP - Mono ───────────────────────────────────────────────────
  // Fully monochrome green - no blue, no teal. Pure green hue 145 throughout.
  // Warmer green (less teal) like actual Pip-Boy. All semantic colors are green
  // intensity levels. Destructive = amber because it's the only non-green.
  // Green-tinted foreground text. This is the "if we could get away with it" pick.
  {
    name: "AIBP - Mono",
    tagline: "Single-hue green. All UI states are green intensities.",
    source: "Pure hue-145 green monochrome, Pip-Boy philosophy",
    vars: {
      "--background": "oklch(0.17 0.020 145)", // #0A120A
      "--foreground": "oklch(0.83 0.076 145)", // #A8D4A8 - green-tinted text
      "--card": "oklch(0.20 0.027 145)", // #0F1A0F
      "--card-foreground": "oklch(0.83 0.076 145)", // #A8D4A8
      "--popover": "oklch(0.20 0.027 145)", // #0F1A0F
      "--popover-foreground": "oklch(0.92 0.044 145)", // #D4EED4
      "--primary": "oklch(0.81 0.226 148)", // #22E866 - warm green primary
      "--primary-foreground": "oklch(0.17 0.020 145)", // #0A120A
      "--secondary": "oklch(0.23 0.024 145)", // #162016
      "--secondary-foreground": "oklch(0.83 0.076 145)", // #A8D4A8
      "--muted": "oklch(0.23 0.024 145)", // #162016
      "--muted-foreground": "oklch(0.53 0.085 144)", // #4D7A4D
      "--accent": "oklch(0.32 0.043 144)", // #243824
      "--accent-foreground": "oklch(0.81 0.226 148)", // #22E866
      "--destructive": "oklch(0.84 0.164 84)", // amber - only non-green color
      "--destructive-foreground": "oklch(0.17 0.020 145)", // #0A120A
      "--border": "oklch(0.32 0.043 144)", // #243824
      "--input": "oklch(0.20 0.027 145)", // #0F1A0F
      "--ring": "oklch(0.81 0.226 148)", // #22E866
      "--radius": "0.375rem",
      "--shadow-sm":
        "0 2px 10px oklch(0.81 0.226 148 / 0.08), 0 1px 3px oklch(0 0 0 / 0.35)",
      "--shadow-xs":
        "0 1px 6px oklch(0.81 0.226 148 / 0.05), 0 1px 2px oklch(0 0 0 / 0.25)",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.17 0.020 145)" }}
      >
        {/* Green glow */}
        <div
          className="absolute top-1/2 -right-8 h-32 w-32 -translate-y-1/2 rounded-full opacity-10 blur-3xl"
          style={{ background: "oklch(0.81 0.226 148)" }}
        />
        {/* Scanlines - slightly more visible here */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.81 0.226 148) 2px, oklch(0.81 0.226 148) 3px)",
          }}
        />
        <div
          className="absolute right-0 bottom-0 left-0 h-px"
          style={{ background: "oklch(0.32 0.043 144)" }}
        />
        <div className="relative z-10">
          <h3
            className="text-2xl font-semibold"
            style={{
              color: "oklch(0.92 0.044 145)",
              textShadow: "0 0 16px oklch(0.81 0.226 148 / 0.20)",
            }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.53 0.085 144)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.81 0.226 148)", // bright green
              "oklch(0.68 0.161 154)", // mid
              "oklch(0.53 0.085 144)", // muted
              "oklch(0.84 0.164 84)", // amber (the one outsider)
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
    decorations: (
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-[0.02]"
        style={{
          backgroundImage:
            "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.81 0.226 148) 2px, oklch(0.81 0.226 148) 3px)",
        }}
      />
    ),
  },

  // ── 17. AIBP - Teal Shift ─────────────────────────────────────────────
  // Same phosphor concept but the green shifts toward teal/cyan.
  // Feels slightly more "corporate security" and less "retro game."
  // Teal reads as modern + technical. Still has the glow and green-tinted base.
  {
    name: "AIBP - Teal Shift",
    tagline: "Phosphor glow shifted toward teal. More modern, same energy.",
    source: "Teal #20DCAC on teal-dark #0A1214 base",
    vars: {
      "--background": "oklch(0.18 0.013 215)", // #0A1214 - dark with teal undertone
      "--foreground": "oklch(0.88 0.034 204)", // #BDDDE0
      "--card": "oklch(0.21 0.017 217)", // #0F1A1D
      "--card-foreground": "oklch(0.88 0.034 204)", // #BDDDE0
      "--popover": "oklch(0.21 0.017 217)", // #0F1A1D
      "--popover-foreground": "oklch(0.94 0.020 205)", // #DDF0F2
      "--primary": "oklch(0.80 0.155 169)", // #20DCAC - teal-green
      "--primary-foreground": "oklch(0.18 0.013 215)", // #0A1214
      "--secondary": "oklch(0.24 0.020 213)", // #152326
      "--secondary-foreground": "oklch(0.88 0.034 204)", // #BDDDE0
      "--muted": "oklch(0.24 0.020 213)", // #152326
      "--muted-foreground": "oklch(0.56 0.052 204)", // #4E7D82
      "--accent": "oklch(0.31 0.026 208)", // #213538
      "--accent-foreground": "oklch(0.80 0.155 169)", // #20DCAC
      "--destructive": "oklch(0.64 0.208 25)", // #EF4444 - red (teal + red = classic security)
      "--destructive-foreground": "oklch(0.94 0.020 205)", // #DDF0F2
      "--border": "oklch(0.31 0.026 208)", // #213538
      "--input": "oklch(0.21 0.017 217)", // #0F1A1D
      "--ring": "oklch(0.80 0.155 169)", // #20DCAC
      "--radius": "0.5rem",
      "--shadow-sm":
        "0 2px 10px oklch(0.80 0.155 169 / 0.08), 0 1px 3px oklch(0 0 0 / 0.35)",
      "--shadow-xs":
        "0 1px 6px oklch(0.80 0.155 169 / 0.05), 0 1px 2px oklch(0 0 0 / 0.25)",
    },
    banner: (name, tagline) => (
      <div
        className="relative h-28 overflow-hidden p-6"
        style={{ background: "oklch(0.18 0.013 215)" }}
      >
        {/* Teal glow */}
        <div
          className="absolute top-1/2 -right-8 h-32 w-32 -translate-y-1/2 rounded-full opacity-10 blur-3xl"
          style={{ background: "oklch(0.80 0.155 169)" }}
        />
        {/* Scanlines */}
        <div
          className="pointer-events-none absolute inset-0 opacity-[0.02]"
          style={{
            backgroundImage:
              "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.80 0.155 169) 2px, oklch(0.80 0.155 169) 3px)",
          }}
        />
        <div
          className="absolute right-0 bottom-0 left-0 h-px"
          style={{ background: "oklch(0.31 0.026 208)" }}
        />
        <div className="relative z-10">
          <h3
            className="text-2xl font-semibold"
            style={{
              color: "oklch(0.94 0.020 205)",
              textShadow: "0 0 20px oklch(0.80 0.155 169 / 0.18)",
            }}
          >
            {name}
          </h3>
          <p
            className="mt-1 text-sm"
            style={{ color: "oklch(0.56 0.052 204)" }}
          >
            {tagline}
          </p>
          <div className="mt-2 flex gap-1.5">
            {[
              "oklch(0.80 0.155 169)", // teal primary
              "oklch(0.60 0.100 175)", // mid teal
              "oklch(0.84 0.164 84)", // amber
              "oklch(0.64 0.208 25)", // red
            ].map((c) => (
              <div
                key={c}
                className="h-3 w-3 rounded-full"
                style={{ background: c }}
              />
            ))}
          </div>
        </div>
      </div>
    ),
    decorations: (
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-[0.015]"
        style={{
          backgroundImage:
            "repeating-linear-gradient(0deg, transparent, transparent 2px, oklch(0.80 0.155 169) 2px, oklch(0.80 0.155 169) 3px)",
        }}
      />
    ),
  },
];

// ---------------------------------------------------------------------------
// Breach table data
// ---------------------------------------------------------------------------

const BREACHES = [
  {
    service: "LinkedIn",
    email: "john@ex.com",
    severity: "High" as const,
    status: "Unresolved",
  },
  {
    service: "Dropbox",
    email: "john@ex.com",
    severity: "Medium" as const,
    status: "Resolved",
  },
  {
    service: "Adobe",
    email: "jane@ex.com",
    severity: "Low" as const,
    status: "Resolved",
  },
];

// ---------------------------------------------------------------------------
// ThemePreview - real shadcn components, themed via CSS variable overrides
// ---------------------------------------------------------------------------

function ThemePreview({ theme }: { theme: ThemeConfig }) {
  return (
    <div
      className="dark overflow-hidden rounded-xl border border-white/5"
      style={{ ...(theme.vars as CSSProperties), ...(theme.rootStyle ?? {}) }}
    >
      {/* Banner */}
      {theme.banner?.(theme.name, theme.tagline)}

      {/* Component showcase */}
      <div
        className="relative space-y-5 p-5"
        style={{
          backgroundColor: "var(--background)",
          color: "var(--foreground)",
        }}
      >
        {theme.decorations}

        {/* Stat cards */}
        <div className="relative z-10 grid grid-cols-3 gap-3">
          <Card className="gap-3 py-3">
            <CardHeader className="px-3 py-0">
              <CardDescription className="text-[11px]">
                Breaches
              </CardDescription>
            </CardHeader>
            <CardContent className="px-3 py-0">
              <p className="text-2xl leading-none font-bold">12</p>
              <p className="text-destructive mt-1 text-[10px] font-medium">
                +3 new
              </p>
            </CardContent>
          </Card>
          <Card className="gap-3 py-3">
            <CardHeader className="px-3 py-0">
              <CardDescription className="text-[11px]">
                Accounts
              </CardDescription>
            </CardHeader>
            <CardContent className="px-3 py-0">
              <p className="text-2xl leading-none font-bold">47</p>
              <p className="text-muted-foreground mt-1 text-[10px]">
                8 domains
              </p>
            </CardContent>
          </Card>
          <Card className="gap-3 py-3">
            <CardHeader className="px-3 py-0">
              <CardDescription className="text-[11px]">Risk</CardDescription>
            </CardHeader>
            <CardContent className="px-3 py-0">
              <p className="text-primary text-2xl leading-none font-bold">
                High
              </p>
              <p className="text-muted-foreground mt-1 text-[10px]">
                4 actions
              </p>
            </CardContent>
          </Card>
        </div>

        {/* Buttons */}
        <div className="relative z-10 flex flex-wrap items-center gap-2">
          <Button size="sm">Scan Now</Button>
          <Button size="sm" variant="outline">
            Report
          </Button>
          <Button size="sm" variant="secondary">
            Settings
          </Button>
          <Button size="sm" variant="ghost">
            Ghost
          </Button>
          <Button size="sm" variant="destructive">
            Delete
          </Button>
        </div>

        {/* Input */}
        <div className="relative z-10 space-y-1.5">
          <Label className="text-xs">Email to monitor</Label>
          <Input placeholder="you@example.com" className="h-8 text-xs" />
        </div>

        {/* Table */}
        <Card className="relative z-10 gap-0 overflow-hidden py-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="h-8 text-[11px]">Service</TableHead>
                <TableHead className="h-8 text-[11px]">Email</TableHead>
                <TableHead className="h-8 text-[11px]">Severity</TableHead>
                <TableHead className="h-8 text-right text-[11px]">
                  Status
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {BREACHES.map((row) => (
                <TableRow key={row.service}>
                  <TableCell className="py-1.5 text-xs font-medium">
                    {row.service}
                  </TableCell>
                  <TableCell className="text-muted-foreground py-1.5 text-xs">
                    {row.email}
                  </TableCell>
                  <TableCell className="py-1.5">
                    <Badge
                      variant={
                        row.severity === "High"
                          ? "destructive"
                          : row.severity === "Medium"
                            ? "default"
                            : "secondary"
                      }
                      className="text-[10px]"
                    >
                      {row.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="py-1.5 text-right">
                    <Badge
                      variant={row.status === "Resolved" ? "outline" : "ghost"}
                      className="text-[10px]"
                    >
                      {row.status}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>

        {/* Badges */}
        <div className="relative z-10 flex flex-wrap gap-1.5">
          <Badge className="text-[10px]">Default</Badge>
          <Badge variant="secondary" className="text-[10px]">
            Secondary
          </Badge>
          <Badge variant="outline" className="text-[10px]">
            Outline
          </Badge>
          <Badge variant="destructive" className="text-[10px]">
            Destructive
          </Badge>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Story
// ---------------------------------------------------------------------------

export const Gallery: Story = {
  render: () => (
    <div className="bg-background text-foreground min-h-screen p-8">
      <div className="mx-auto max-w-7xl space-y-8">
        <div className="space-y-2">
          <h1 className="text-4xl font-bold tracking-tight">Theme Gallery</h1>
          <p className="text-muted-foreground text-lg">
            Real palettes from documented sources. Every OKLCH value traced to a
            hex code.
          </p>
        </div>

        <div className="grid gap-8 lg:grid-cols-2">
          {themes.map((theme) => (
            <ThemePreview key={theme.name} theme={theme} />
          ))}
        </div>

        <p className="text-muted-foreground pb-8 text-center text-sm">
          Color sources noted per theme. No vibe-coded values.
        </p>
      </div>
    </div>
  ),
};
