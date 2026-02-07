import type { Meta, StoryObj } from "@storybook/react";
import type { CSSProperties } from "react";

import { Badge } from "../badge";
import { Button } from "../button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../dropdown-menu";
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSeparator,
  FieldSet,
} from "../field";
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

// ---------------------------------------------------------------------------
// AIBP - Deep theme vars
// Darker base. Stronger glow. Night shift energy.
// Source: Pip-Boy #2BF08A on deeper #080F0B darks
// ---------------------------------------------------------------------------

const GREEN = "oklch(0.84 0.204 154)";
const GREEN_MID = "oklch(0.68 0.161 154)";
const GREEN_DIM = "oklch(0.52 0.054 165)";
const GREEN_FAINT = "oklch(0.35 0.040 160)";
const AMBER = "oklch(0.84 0.164 84)";
const RED = "oklch(0.64 0.208 25)";

const deepVars: Record<string, string> = {
  "--background": "oklch(0.16 0.014 160)", // #080F0B
  "--foreground": "oklch(0.85 0.037 166)", // #B8D6C8
  "--card": "oklch(0.19 0.018 155)", // #0D1610
  "--card-foreground": "oklch(0.85 0.037 166)", // #B8D6C8
  "--popover": "oklch(0.19 0.018 155)", // #0D1610
  "--popover-foreground": "oklch(0.94 0.026 160)", // #DCF0E4
  "--primary": GREEN, // #2BF08A
  "--primary-foreground": "oklch(0.16 0.014 160)", // #080F0B
  "--secondary": "oklch(0.22 0.022 158)", // #121E17
  "--secondary-foreground": "oklch(0.85 0.037 166)", // #B8D6C8
  "--muted": "oklch(0.22 0.022 158)", // #121E17
  "--muted-foreground": GREEN_DIM, // #4A7260
  "--accent": "oklch(0.29 0.028 165)", // #1E3028
  "--accent-foreground": GREEN, // #2BF08A
  "--destructive": AMBER, // amber
  "--destructive-foreground": "oklch(0.16 0.014 160)", // #080F0B
  "--border": "oklch(0.29 0.028 165)", // #1E3028
  "--input": "oklch(0.19 0.018 155)", // #0D1610
  "--ring": GREEN, // #2BF08A
  "--radius": "0.375rem",
  "--shadow-sm": `0 2px 12px oklch(0.84 0.204 154 / 0.10), 0 1px 3px oklch(0 0 0 / 0.4)`,
  "--shadow-xs": `0 1px 8px oklch(0.84 0.204 154 / 0.06), 0 1px 2px oklch(0 0 0 / 0.3)`,
};

// Glow helper
const glow = (color: string, amount = 0.5) =>
  `0 0 6px ${color.replace(")", ` / ${amount})`)}`;

// ---------------------------------------------------------------------------
// Storybook meta
// ---------------------------------------------------------------------------

const meta = {
  title: "AIBP Deep",
  parameters: { layout: "fullscreen" },
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

// ---------------------------------------------------------------------------
// Reusable sub-sections
// ---------------------------------------------------------------------------

function StatusDot({ color, pulse }: { color: string; pulse?: boolean }) {
  return (
    <div
      className={`h-2 w-2 rounded-full ${pulse ? "animate-pulse" : ""}`}
      style={{ background: color, boxShadow: glow(color) }}
    />
  );
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2
      className="text-2xl font-semibold"
      style={{ textShadow: `0 0 20px oklch(0.84 0.204 154 / 0.08)` }}
    >
      {children}
    </h2>
  );
}

// ---------------------------------------------------------------------------
// Main story
// ---------------------------------------------------------------------------

export const Moodboard: Story = {
  render: () => (
    <div
      className="dark min-h-screen"
      style={{ ...(deepVars as CSSProperties) }}
    >
      {/* Scanline overlay */}
      <div
        className="pointer-events-none fixed inset-0 z-50 opacity-[0.018]"
        style={{
          backgroundImage: `repeating-linear-gradient(0deg, transparent, transparent 2px, ${GREEN} 2px, ${GREEN} 3px)`,
        }}
      />
      {/* CRT vignette */}
      <div
        className="pointer-events-none fixed inset-0 z-40"
        style={{
          background:
            "radial-gradient(ellipse 80% 70% at center, transparent 50%, oklch(0 0 0 / 0.25) 100%)",
        }}
      />

      <div
        className="relative min-h-screen"
        style={{
          backgroundColor: "var(--background)",
          color: "var(--foreground)",
        }}
      >
        {/* ================================================================ */}
        {/* TOP NAV BAR                                                      */}
        {/* ================================================================ */}
        <nav
          className="sticky top-0 z-30 border-b px-6 py-3"
          style={{
            backgroundColor: "var(--card)",
            borderColor: "var(--border)",
          }}
        >
          <div className="mx-auto flex max-w-7xl items-center justify-between">
            <div className="flex items-center gap-3">
              <StatusDot color={GREEN} />
              <span
                className="text-sm font-bold tracking-wide"
                style={{ textShadow: `0 0 12px oklch(0.84 0.204 154 / 0.15)` }}
              >
                Am I Being Pwned?
              </span>
              <Badge variant="outline" className="text-[10px]">
                v2.4.1
              </Badge>
            </div>
            <div className="flex items-center gap-2">
              <Input
                placeholder="Search breaches, domains..."
                className="h-7 w-56 text-xs"
              />
              <Button size="sm" variant="ghost">
                Docs
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button size="sm" variant="outline">
                    Account
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuLabel>acorn@example.com</DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem>Settings</DropdownMenuItem>
                  <DropdownMenuItem>API Keys</DropdownMenuItem>
                  <DropdownMenuItem>Billing</DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem variant="destructive">
                    Sign Out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </nav>

        <div className="relative z-10 mx-auto max-w-7xl space-y-14 p-8">
          {/* ================================================================ */}
          {/* HERO / HEADER                                                    */}
          {/* ================================================================ */}
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <StatusDot color={GREEN} />
              <span
                className="text-xs font-medium tracking-widest uppercase"
                style={{ color: GREEN_DIM }}
              >
                System Online &mdash; All monitors active
              </span>
            </div>
            <h1
              className="text-5xl font-bold tracking-tight"
              style={{ textShadow: `0 0 40px oklch(0.84 0.204 154 / 0.12)` }}
            >
              Security Dashboard
            </h1>
            <p className="text-muted-foreground max-w-2xl text-lg">
              Real-time breach monitoring, credential exposure tracking, and
              threat intelligence for your organization. AIBP Deep theme - night
              shift edition.
            </p>
            <div className="flex items-center gap-3 pt-2">
              <Button>Run Full Scan</Button>
              <Button variant="outline">View Reports</Button>
              <Button variant="secondary">Configure Monitors</Button>
              <Button variant="ghost">API Docs</Button>
            </div>
          </div>

          <Separator />

          {/* ================================================================ */}
          {/* KPI STAT CARDS (4-wide)                                          */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Key Metrics</SectionTitle>
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {[
                {
                  title: "Total Breaches",
                  value: "12",
                  delta: "+3",
                  deltaColor: AMBER,
                  desc: "Last 30 days",
                },
                {
                  title: "Accounts Monitored",
                  value: "47",
                  delta: "+5",
                  deltaColor: GREEN,
                  desc: "Across 8 domains",
                },
                {
                  title: "Credentials Exposed",
                  value: "2,841",
                  delta: "-12%",
                  deltaColor: GREEN,
                  desc: "vs. last month",
                },
                {
                  title: "Risk Score",
                  value: "73",
                  delta: "High",
                  deltaColor: AMBER,
                  desc: "4 actions needed",
                },
              ].map((kpi) => (
                <Card key={kpi.title}>
                  <CardHeader className="pb-0">
                    <CardDescription className="text-xs">
                      {kpi.title}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <p
                      className="text-3xl font-bold"
                      style={{
                        textShadow: `0 0 16px oklch(0.84 0.204 154 / 0.12)`,
                      }}
                    >
                      {kpi.value}
                    </p>
                    <div className="mt-1 flex items-center gap-2">
                      <Badge
                        variant="outline"
                        className="text-[10px]"
                        style={{ color: kpi.deltaColor }}
                      >
                        {kpi.delta}
                      </Badge>
                      <span className="text-muted-foreground text-[10px]">
                        {kpi.desc}
                      </span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </section>

          {/* ================================================================ */}
          {/* ALERT BANNER ROW                                                 */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Active Alerts</SectionTitle>
            <div className="space-y-3">
              <Card className="border-l-4" style={{ borderLeftColor: RED }}>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <StatusDot color={RED} pulse />
                    <CardTitle className="text-sm font-semibold">
                      Critical - New Credential Dump Detected
                    </CardTitle>
                    <Badge
                      variant="destructive"
                      className="ml-auto text-[10px]"
                    >
                      Critical
                    </Badge>
                  </div>
                  <CardDescription>
                    5 monitored accounts found in paste
                    &quot;combo_2026_feb.txt&quot; - discovered 23 minutes ago.
                    Immediate action required.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex gap-2">
                    <Button size="sm">Investigate</Button>
                    <Button size="sm" variant="outline">
                      Notify Users
                    </Button>
                    <Button size="sm" variant="ghost">
                      Snooze 1h
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <Card className="border-l-4" style={{ borderLeftColor: AMBER }}>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <StatusDot color={AMBER} pulse />
                    <CardTitle className="text-sm font-semibold">
                      Warning - Domain Certificate Expiring
                    </CardTitle>
                    <Badge variant="outline" className="ml-auto text-[10px]">
                      Warning
                    </Badge>
                  </div>
                  <CardDescription>
                    TLS certificate for api.example.com expires in 14 days.
                  </CardDescription>
                </CardHeader>
              </Card>

              <Card className="border-l-4" style={{ borderLeftColor: GREEN }}>
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <StatusDot color={GREEN} />
                    <CardTitle className="text-sm font-semibold">
                      Resolved - LinkedIn Breach Accounts Rotated
                    </CardTitle>
                    <Badge variant="secondary" className="ml-auto text-[10px]">
                      Resolved
                    </Badge>
                  </div>
                  <CardDescription>
                    All 18 affected credentials have been rotated. Closed by
                    admin@example.com.
                  </CardDescription>
                </CardHeader>
              </Card>
            </div>
          </section>

          {/* ================================================================ */}
          {/* DATA VISUALIZATION (charts mockup)                               */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Analytics</SectionTitle>
            <div className="grid gap-4 lg:grid-cols-3">
              {/* Bar chart */}
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Breach Discovery Timeline</CardTitle>
                  <CardDescription>
                    Monthly breach detections - last 12 months
                  </CardDescription>
                  <CardAction>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button size="sm" variant="ghost">
                          12M
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem>7 Days</DropdownMenuItem>
                        <DropdownMenuItem>30 Days</DropdownMenuItem>
                        <DropdownMenuItem>12 Months</DropdownMenuItem>
                        <DropdownMenuItem>All Time</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </CardAction>
                </CardHeader>
                <CardContent>
                  <div
                    className="flex items-end gap-1.5"
                    style={{ height: 140 }}
                  >
                    {[18, 12, 32, 8, 45, 22, 38, 15, 52, 28, 35, 65].map(
                      (v, i) => (
                        <div
                          key={i}
                          className="flex flex-1 flex-col items-center gap-1"
                        >
                          <span className="text-muted-foreground text-[9px]">
                            {v}
                          </span>
                          <div
                            className="w-full rounded-t transition-all"
                            style={{
                              height: `${(v / 65) * 100}%`,
                              background: v > 40 ? AMBER : GREEN,
                              boxShadow: `0 0 ${v > 40 ? 10 : 6}px ${v > 40 ? AMBER.replace(")", " / 0.3)") : GREEN.replace(")", " / 0.2)")}`,
                              opacity: 0.7 + (v / 65) * 0.3,
                            }}
                          />
                        </div>
                      ),
                    )}
                  </div>
                  <div className="mt-2 flex justify-between">
                    {[
                      "Mar",
                      "Apr",
                      "May",
                      "Jun",
                      "Jul",
                      "Aug",
                      "Sep",
                      "Oct",
                      "Nov",
                      "Dec",
                      "Jan",
                      "Feb",
                    ].map((m) => (
                      <span
                        key={m}
                        className="text-muted-foreground flex-1 text-center text-[9px]"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Donut / ring chart mockup */}
              <Card>
                <CardHeader>
                  <CardTitle>Severity Distribution</CardTitle>
                  <CardDescription>All-time breach severity</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-center py-2">
                    <div className="relative">
                      <svg width={130} height={130} viewBox="0 0 130 130">
                        {/* Background ring */}
                        <circle
                          cx={65}
                          cy={65}
                          r={52}
                          fill="none"
                          stroke="var(--muted)"
                          strokeWidth={14}
                        />
                        {/* Segments - drawn as stroke-dasharray arcs */}
                        <circle
                          cx={65}
                          cy={65}
                          r={52}
                          fill="none"
                          stroke={RED}
                          strokeWidth={14}
                          strokeDasharray={`${0.35 * 327} ${327}`}
                          strokeDashoffset={0}
                          transform="rotate(-90 65 65)"
                          style={{
                            filter: `drop-shadow(0 0 4px ${RED.replace(")", " / 0.5)")})`,
                          }}
                        />
                        <circle
                          cx={65}
                          cy={65}
                          r={52}
                          fill="none"
                          stroke={AMBER}
                          strokeWidth={14}
                          strokeDasharray={`${0.4 * 327} ${327}`}
                          strokeDashoffset={`${-0.35 * 327}`}
                          transform="rotate(-90 65 65)"
                          style={{
                            filter: `drop-shadow(0 0 4px ${AMBER.replace(")", " / 0.4)")})`,
                          }}
                        />
                        <circle
                          cx={65}
                          cy={65}
                          r={52}
                          fill="none"
                          stroke={GREEN}
                          strokeWidth={14}
                          strokeDasharray={`${0.25 * 327} ${327}`}
                          strokeDashoffset={`${-0.75 * 327}`}
                          transform="rotate(-90 65 65)"
                          style={{
                            filter: `drop-shadow(0 0 4px ${GREEN.replace(")", " / 0.3)")})`,
                          }}
                        />
                      </svg>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-2xl font-bold">142</span>
                        <span className="text-muted-foreground text-[10px]">
                          Total
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 space-y-1.5">
                    {[
                      {
                        label: "Critical / High",
                        pct: 35,
                        color: RED,
                        count: 50,
                      },
                      { label: "Medium", pct: 40, color: AMBER, count: 57 },
                      { label: "Low", pct: 25, color: GREEN, count: 35 },
                    ].map((s) => (
                      <div
                        key={s.label}
                        className="flex items-center justify-between text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <div
                            className="h-2 w-2 rounded-full"
                            style={{ background: s.color }}
                          />
                          <span>{s.label}</span>
                        </div>
                        <span className="text-muted-foreground">
                          {s.count} ({s.pct}%)
                        </span>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Progress bars row */}
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Top Exposed Services</CardTitle>
                  <CardDescription>
                    By compromised account count
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {[
                    { name: "LinkedIn", count: 18, pct: 100 },
                    { name: "Adobe", count: 12, pct: 67 },
                    { name: "Dropbox", count: 8, pct: 44 },
                    { name: "Canva", count: 5, pct: 28 },
                    { name: "Twitter/X", count: 3, pct: 17 },
                  ].map((svc) => (
                    <div key={svc.name} className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span className="font-medium">{svc.name}</span>
                        <span className="text-muted-foreground">
                          {svc.count}
                        </span>
                      </div>
                      <div
                        className="h-1.5 overflow-hidden rounded-full"
                        style={{ background: "var(--muted)" }}
                      >
                        <div
                          className="h-full rounded-full transition-all"
                          style={{
                            width: `${svc.pct}%`,
                            background: svc.pct > 80 ? AMBER : GREEN,
                            boxShadow: `0 0 8px ${svc.pct > 80 ? AMBER.replace(")", " / 0.4)") : GREEN.replace(")", " / 0.3)")}`,
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Data Type Exposure</CardTitle>
                  <CardDescription>What was leaked</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  {[
                    { name: "Email Addresses", count: 47, pct: 100 },
                    { name: "Passwords (hashed)", count: 31, pct: 66 },
                    { name: "Passwords (plaintext)", count: 8, pct: 17 },
                    { name: "Phone Numbers", count: 12, pct: 26 },
                    { name: "Physical Addresses", count: 3, pct: 6 },
                  ].map((dt) => (
                    <div key={dt.name} className="space-y-1">
                      <div className="flex justify-between text-sm">
                        <span className="font-medium">{dt.name}</span>
                        <span className="text-muted-foreground">
                          {dt.count}
                        </span>
                      </div>
                      <div
                        className="h-1.5 overflow-hidden rounded-full"
                        style={{ background: "var(--muted)" }}
                      >
                        <div
                          className="h-full rounded-full transition-all"
                          style={{
                            width: `${dt.pct}%`,
                            background: dt.name.includes("plaintext")
                              ? RED
                              : dt.pct > 50
                                ? AMBER
                                : GREEN,
                            boxShadow: `0 0 6px ${dt.name.includes("plaintext") ? RED.replace(")", " / 0.4)") : GREEN.replace(")", " / 0.2)")}`,
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </section>

          {/* ================================================================ */}
          {/* MAIN DATA TABLE                                                  */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Breach Log</SectionTitle>
            <Card>
              <CardHeader>
                <CardTitle>Recent Breaches</CardTitle>
                <CardDescription>
                  All compromised accounts detected across monitored domains.
                </CardDescription>
                <CardAction>
                  <div className="flex gap-2">
                    <Input
                      placeholder="Filter..."
                      className="h-7 w-40 text-xs"
                    />
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button size="sm" variant="outline">
                          Severity
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem>All</DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem>Critical</DropdownMenuItem>
                        <DropdownMenuItem>High</DropdownMenuItem>
                        <DropdownMenuItem>Medium</DropdownMenuItem>
                        <DropdownMenuItem>Low</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                    <Button size="sm" variant="secondary">
                      Export CSV
                    </Button>
                  </div>
                </CardAction>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-8">#</TableHead>
                      <TableHead>Service</TableHead>
                      <TableHead>Email</TableHead>
                      <TableHead>Date</TableHead>
                      <TableHead>Data Leaked</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead className="text-right">Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {[
                      {
                        id: 1,
                        service: "LinkedIn",
                        email: "john@example.com",
                        date: "2026-02-14",
                        data: "Email, Password hash, Phone",
                        severity: "Critical" as const,
                        status: "Unresolved",
                      },
                      {
                        id: 2,
                        service: "Dropbox",
                        email: "john@example.com",
                        date: "2026-01-22",
                        data: "Email, Password hash",
                        severity: "High" as const,
                        status: "Investigating",
                      },
                      {
                        id: 3,
                        service: "Adobe",
                        email: "jane@example.com",
                        date: "2025-12-18",
                        data: "Email, Encrypted password",
                        severity: "Medium" as const,
                        status: "Resolved",
                      },
                      {
                        id: 4,
                        service: "Canva",
                        email: "jane@example.com",
                        date: "2025-11-30",
                        data: "Email, Name, Location",
                        severity: "High" as const,
                        status: "Unresolved",
                      },
                      {
                        id: 5,
                        service: "Twitter/X",
                        email: "john@example.com",
                        date: "2025-11-02",
                        data: "Email, Phone",
                        severity: "Medium" as const,
                        status: "Resolved",
                      },
                      {
                        id: 6,
                        service: "Notion",
                        email: "admin@example.com",
                        date: "2025-10-15",
                        data: "Email, API tokens",
                        severity: "Critical" as const,
                        status: "Resolved",
                      },
                      {
                        id: 7,
                        service: "Slack",
                        email: "dev@example.com",
                        date: "2025-09-08",
                        data: "Email, OAuth tokens",
                        severity: "High" as const,
                        status: "Resolved",
                      },
                      {
                        id: 8,
                        service: "npm",
                        email: "dev@example.com",
                        date: "2025-08-22",
                        data: "Email, Password hash",
                        severity: "Low" as const,
                        status: "Resolved",
                      },
                    ].map((row) => (
                      <TableRow key={row.id}>
                        <TableCell className="text-muted-foreground text-xs">
                          {row.id}
                        </TableCell>
                        <TableCell className="font-medium">
                          {row.service}
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {row.email}
                        </TableCell>
                        <TableCell className="text-sm">{row.date}</TableCell>
                        <TableCell className="text-muted-foreground max-w-48 truncate text-xs">
                          {row.data}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              row.severity === "Critical" ||
                              row.severity === "High"
                                ? "destructive"
                                : row.severity === "Medium"
                                  ? "default"
                                  : "secondary"
                            }
                            className="text-[10px]"
                            style={
                              row.severity === "Critical"
                                ? { background: RED, boxShadow: glow(RED, 0.3) }
                                : undefined
                            }
                          >
                            {row.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Badge
                            variant={
                              row.status === "Resolved"
                                ? "outline"
                                : row.status === "Investigating"
                                  ? "secondary"
                                  : "ghost"
                            }
                            className="text-[10px]"
                          >
                            {row.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-6 px-2 text-xs"
                              >
                                ...
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem>View Details</DropdownMenuItem>
                              <DropdownMenuItem>Notify User</DropdownMenuItem>
                              <DropdownMenuItem>Mark Resolved</DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem variant="destructive">
                                Dismiss
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
              <CardFooter>
                <div className="text-muted-foreground flex w-full items-center justify-between text-xs">
                  <span>Showing 8 of 142 breaches</span>
                  <div className="flex gap-1">
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-6 px-2 text-xs"
                      disabled
                    >
                      Prev
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-6 px-2 text-xs"
                    >
                      Next
                    </Button>
                  </div>
                </div>
              </CardFooter>
            </Card>
          </section>

          {/* ================================================================ */}
          {/* ACTIVITY FEED / TIMELINE                                         */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Activity Feed</SectionTitle>
            <Card>
              <CardContent>
                <div className="space-y-0">
                  {[
                    {
                      time: "2 min ago",
                      action: "New breach detected",
                      detail: "LinkedIn - john@example.com found in paste",
                      color: RED,
                      badge: "Critical",
                    },
                    {
                      time: "23 min ago",
                      action: "Scan completed",
                      detail:
                        "Full domain scan of example.com - 0 new exposures",
                      color: GREEN,
                      badge: "Info",
                    },
                    {
                      time: "1 hour ago",
                      action: "User notified",
                      detail:
                        "Password rotation email sent to jane@example.com",
                      color: GREEN_MID,
                      badge: "Action",
                    },
                    {
                      time: "3 hours ago",
                      action: "Breach resolved",
                      detail: "Adobe breach - all affected credentials rotated",
                      color: GREEN,
                      badge: "Resolved",
                    },
                    {
                      time: "6 hours ago",
                      action: "Monitor added",
                      detail: "New domain monitor: staging.example.com",
                      color: GREEN_DIM,
                      badge: "Config",
                    },
                    {
                      time: "1 day ago",
                      action: "API key rotated",
                      detail:
                        "Production API key regenerated by admin@example.com",
                      color: GREEN_MID,
                      badge: "Security",
                    },
                    {
                      time: "2 days ago",
                      action: "Report exported",
                      detail:
                        "Monthly breach report generated for January 2026",
                      color: GREEN_DIM,
                      badge: "Report",
                    },
                  ].map((event, i) => (
                    <div key={i} className="flex gap-4 py-3">
                      {/* Timeline rail */}
                      <div className="flex flex-col items-center">
                        <StatusDot color={event.color} />
                        {i < 6 && (
                          <div
                            className="mt-1 h-full w-px"
                            style={{ background: "var(--border)" }}
                          />
                        )}
                      </div>
                      {/* Content */}
                      <div className="flex-1 space-y-1 pb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">
                            {event.action}
                          </span>
                          <Badge variant="outline" className="text-[9px]">
                            {event.badge}
                          </Badge>
                          <span className="text-muted-foreground ml-auto text-[10px]">
                            {event.time}
                          </span>
                        </div>
                        <p className="text-muted-foreground text-xs">
                          {event.detail}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
              <CardFooter>
                <Button variant="ghost" size="sm" className="w-full text-xs">
                  View all activity
                </Button>
              </CardFooter>
            </Card>
          </section>

          {/* ================================================================ */}
          {/* COLOR PALETTE                                                    */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Color Palette</SectionTitle>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 md:grid-cols-6">
              {[
                {
                  name: "Background",
                  bg: "bg-background",
                  fg: "text-foreground",
                },
                {
                  name: "Primary",
                  bg: "bg-primary",
                  fg: "text-primary-foreground",
                },
                {
                  name: "Secondary",
                  bg: "bg-secondary",
                  fg: "text-secondary-foreground",
                },
                {
                  name: "Accent",
                  bg: "bg-accent",
                  fg: "text-accent-foreground",
                },
                { name: "Muted", bg: "bg-muted", fg: "text-muted-foreground" },
                {
                  name: "Destructive",
                  bg: "bg-destructive",
                  fg: "text-destructive-foreground",
                },
                { name: "Card", bg: "bg-card", fg: "text-card-foreground" },
                {
                  name: "Popover",
                  bg: "bg-popover",
                  fg: "text-popover-foreground",
                },
                { name: "Border", custom: "var(--border)" },
                { name: "Input", custom: "var(--input)" },
                { name: "Ring", custom: "var(--ring)" },
                { name: "Foreground", custom: "var(--foreground)" },
              ].map((c) => (
                <div key={c.name} className="space-y-1.5">
                  {"custom" in c && c.custom ? (
                    <div
                      className="flex h-20 items-center justify-center rounded-lg border text-[10px] font-medium"
                      style={{
                        background: c.custom,
                        color:
                          c.name === "Foreground" || c.name === "Ring"
                            ? "var(--background)"
                            : "var(--foreground)",
                      }}
                    >
                      {c.name}
                    </div>
                  ) : (
                    <div
                      className={`${"bg" in c ? c.bg : ""} ${"fg" in c ? c.fg : ""} flex h-20 items-center justify-center rounded-lg border text-[10px] font-medium`}
                    >
                      {c.name}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Signal spectrum */}
            <div className="space-y-2">
              <p className="text-muted-foreground text-sm">Signal Spectrum</p>
              <div className="flex gap-2">
                {[
                  { label: "Bright", color: GREEN },
                  { label: "Active", color: "oklch(0.72 0.180 154)" },
                  { label: "Mid", color: GREEN_MID },
                  { label: "Dim", color: GREEN_DIM },
                  { label: "Faint", color: GREEN_FAINT },
                  { label: "Amber", color: AMBER },
                  { label: "Warn", color: "oklch(0.70 0.140 60)" },
                  { label: "Red", color: RED },
                ].map((s) => (
                  <div
                    key={s.label}
                    className="flex flex-1 flex-col items-center gap-1.5"
                  >
                    <div
                      className="h-10 w-full rounded border"
                      style={{
                        background: s.color,
                        borderColor: "var(--border)",
                        boxShadow: `0 0 12px ${s.color.replace(")", " / 0.15)")}`,
                      }}
                    />
                    <span className="text-muted-foreground text-[10px]">
                      {s.label}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* ================================================================ */}
          {/* TYPOGRAPHY                                                       */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Typography</SectionTitle>
            <Card>
              <CardContent className="space-y-4">
                <p
                  className="text-5xl font-bold tracking-tight"
                  style={{
                    textShadow: `0 0 30px oklch(0.84 0.204 154 / 0.10)`,
                  }}
                >
                  Display
                </p>
                <p className="text-4xl font-bold tracking-tight">Heading 1</p>
                <p className="text-3xl font-semibold tracking-tight">
                  Heading 2
                </p>
                <p className="text-2xl font-semibold">Heading 3</p>
                <p className="text-xl font-medium">Heading 4</p>
                <p className="text-lg">
                  Lead paragraph - introductory text that sets the context for
                  the content below.
                </p>
                <p className="text-base">
                  Body text - The quick brown fox jumps over the lazy dog.
                  Standard readable paragraph text for main content areas.
                </p>
                <p className="text-muted-foreground text-sm">
                  Muted text - Secondary information, descriptions, and
                  supporting context that doesn't need primary emphasis.
                </p>
                <p className="text-muted-foreground text-xs">
                  Caption - Fine print, metadata, timestamps, and supplementary
                  details.
                </p>
                <Separator />
                <div className="flex gap-8">
                  <div className="space-y-1">
                    <p className="text-muted-foreground text-[10px] tracking-widest uppercase">
                      Monospace
                    </p>
                    <p className="font-mono text-sm">
                      const breach = await scan(domain);
                    </p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-muted-foreground text-[10px] tracking-widest uppercase">
                      Tabular
                    </p>
                    <p className="text-sm tabular-nums">1,234,567.89</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </section>

          {/* ================================================================ */}
          {/* BUTTONS - EXHAUSTIVE                                             */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Buttons</SectionTitle>
            <Card>
              <CardContent className="space-y-6">
                <div>
                  <Label className="text-muted-foreground mb-2 text-xs">
                    Variants
                  </Label>
                  <div className="flex flex-wrap items-center gap-3">
                    <Button>Primary</Button>
                    <Button variant="secondary">Secondary</Button>
                    <Button variant="outline">Outline</Button>
                    <Button variant="ghost">Ghost</Button>
                    <Button variant="link">Link</Button>
                    <Button variant="destructive">Destructive</Button>
                  </div>
                </div>
                <Separator />
                <div>
                  <Label className="text-muted-foreground mb-2 text-xs">
                    Sizes
                  </Label>
                  <div className="flex flex-wrap items-center gap-3">
                    <Button size="sm">Small</Button>
                    <Button size="default">Default</Button>
                    <Button size="lg">Large</Button>
                    <Button size="icon">+</Button>
                  </div>
                </div>
                <Separator />
                <div>
                  <Label className="text-muted-foreground mb-2 text-xs">
                    States
                  </Label>
                  <div className="flex flex-wrap items-center gap-3">
                    <Button>Enabled</Button>
                    <Button disabled>Disabled</Button>
                    <Button variant="outline" disabled>
                      Disabled Outline
                    </Button>
                    <Button variant="secondary" disabled>
                      Disabled Secondary
                    </Button>
                  </div>
                </div>
                <Separator />
                <div>
                  <Label className="text-muted-foreground mb-2 text-xs">
                    Common Patterns
                  </Label>
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="flex gap-1">
                      <Button>Save Changes</Button>
                      <Button variant="ghost">Cancel</Button>
                    </div>
                    <Separator orientation="vertical" className="h-8" />
                    <div className="flex gap-1">
                      <Button variant="outline">Back</Button>
                      <Button>Continue</Button>
                    </div>
                    <Separator orientation="vertical" className="h-8" />
                    <div className="flex gap-1">
                      <Button variant="destructive">Delete Account</Button>
                      <Button variant="ghost">Cancel</Button>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </section>

          {/* ================================================================ */}
          {/* BADGES - EXHAUSTIVE                                              */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Badges</SectionTitle>
            <Card>
              <CardContent className="space-y-6">
                <div>
                  <Label className="text-muted-foreground mb-2 text-xs">
                    Variants
                  </Label>
                  <div className="flex flex-wrap items-center gap-3">
                    <Badge>Default</Badge>
                    <Badge variant="secondary">Secondary</Badge>
                    <Badge variant="outline">Outline</Badge>
                    <Badge variant="destructive">Destructive</Badge>
                    <Badge variant="ghost">Ghost</Badge>
                    <Badge variant="link">Link</Badge>
                  </div>
                </div>
                <Separator />
                <div>
                  <Label className="text-muted-foreground mb-2 text-xs">
                    Contextual Usage
                  </Label>
                  <div className="flex flex-wrap items-center gap-3">
                    <Badge
                      style={{ background: GREEN, color: "var(--background)" }}
                    >
                      Secure
                    </Badge>
                    <Badge
                      style={{ background: AMBER, color: "var(--background)" }}
                    >
                      Warning
                    </Badge>
                    <Badge style={{ background: RED, color: "#fff" }}>
                      Critical
                    </Badge>
                    <Badge variant="outline">Pending</Badge>
                    <Badge variant="secondary">Archived</Badge>
                    <Badge
                      style={{
                        background: GREEN_DIM,
                        color: "var(--foreground)",
                      }}
                    >
                      Offline
                    </Badge>
                  </div>
                </div>
                <Separator />
                <div>
                  <Label className="text-muted-foreground mb-2 text-xs">
                    With Status Dots
                  </Label>
                  <div className="flex flex-wrap items-center gap-3">
                    {[
                      { label: "Active", color: GREEN },
                      { label: "Degraded", color: AMBER },
                      { label: "Down", color: RED },
                      { label: "Maintenance", color: GREEN_DIM },
                    ].map((s) => (
                      <Badge
                        key={s.label}
                        variant="outline"
                        className="gap-1.5"
                      >
                        <div
                          className="h-1.5 w-1.5 rounded-full"
                          style={{
                            background: s.color,
                            boxShadow: glow(s.color, 0.4),
                          }}
                        />
                        {s.label}
                      </Badge>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </section>

          {/* ================================================================ */}
          {/* FORM ELEMENTS - EXTENSIVE                                        */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Form Elements</SectionTitle>

            {/* Standard form */}
            <Card>
              <CardHeader>
                <CardTitle>Add Monitor</CardTitle>
                <CardDescription>
                  Configure a new breach monitoring target.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <FieldGroup>
                  <div className="grid gap-6 md:grid-cols-2">
                    <Field>
                      <FieldLabel>Email Address</FieldLabel>
                      <FieldContent>
                        <Input type="email" placeholder="you@example.com" />
                        <FieldDescription>
                          We'll check this against known breaches.
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                    <Field>
                      <FieldLabel>Domain</FieldLabel>
                      <FieldContent>
                        <Input placeholder="example.com" />
                        <FieldDescription>
                          Monitor an entire domain for exposures.
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                    <Field>
                      <FieldLabel>Display Name</FieldLabel>
                      <FieldContent>
                        <Input placeholder="Production Domain" />
                        <FieldDescription>
                          A friendly label for this monitor.
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                    <Field>
                      <FieldLabel>Alert Webhook</FieldLabel>
                      <FieldContent>
                        <Input placeholder="https://hooks.slack.com/..." />
                        <FieldDescription>
                          Optional: Send alerts to a webhook URL.
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                  </div>

                  <FieldSeparator>Authentication</FieldSeparator>

                  <div className="grid gap-6 md:grid-cols-2">
                    <Field data-invalid="true">
                      <FieldLabel>API Key</FieldLabel>
                      <FieldContent>
                        <Input placeholder="aibp_..." aria-invalid />
                        <FieldError>
                          Invalid API key format. Keys must start with
                          &quot;aibp_&quot;.
                        </FieldError>
                      </FieldContent>
                    </Field>
                    <Field>
                      <FieldLabel>API Secret</FieldLabel>
                      <FieldContent>
                        <Input type="password" placeholder="••••••••••••" />
                        <FieldDescription>
                          Your API secret from the dashboard.
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                  </div>

                  <FieldSeparator>Notification Preferences</FieldSeparator>

                  <div className="grid gap-6 md:grid-cols-2">
                    <Field>
                      <FieldLabel>Notification Email</FieldLabel>
                      <FieldContent>
                        <Input
                          type="email"
                          placeholder="alerts@example.com"
                          disabled
                        />
                        <FieldDescription>
                          Upgrade to Pro to enable email notifications.
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                    <Field>
                      <FieldLabel>Severity Threshold</FieldLabel>
                      <FieldContent>
                        <Input placeholder="Medium" />
                        <FieldDescription>
                          Only alert for breaches at or above this severity.
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                  </div>
                </FieldGroup>
              </CardContent>
              <CardFooter>
                <div className="flex w-full items-center justify-between">
                  <Button variant="ghost" size="sm">
                    Cancel
                  </Button>
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm">
                      Save Draft
                    </Button>
                    <Button size="sm">Create Monitor</Button>
                  </div>
                </div>
              </CardFooter>
            </Card>

            {/* FieldSet demo */}
            <Card>
              <CardHeader>
                <CardTitle>Account Settings</CardTitle>
                <CardDescription>
                  Manage your account preferences.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <FieldSet>
                  <FieldLegend>Profile</FieldLegend>
                  <FieldGroup>
                    <Field orientation="horizontal">
                      <FieldLabel>Full Name</FieldLabel>
                      <FieldContent>
                        <Input defaultValue="John Doe" />
                      </FieldContent>
                    </Field>
                    <Field orientation="horizontal">
                      <FieldLabel>Email</FieldLabel>
                      <FieldContent>
                        <Input defaultValue="john@example.com" type="email" />
                      </FieldContent>
                    </Field>
                    <Field orientation="horizontal">
                      <FieldLabel>Organization</FieldLabel>
                      <FieldContent>
                        <Input defaultValue="Acme Corp" />
                        <FieldDescription>
                          Your organization name for reports.
                        </FieldDescription>
                      </FieldContent>
                    </Field>
                  </FieldGroup>
                </FieldSet>
              </CardContent>
              <CardFooter>
                <Button size="sm">Update Profile</Button>
              </CardFooter>
            </Card>
          </section>

          {/* ================================================================ */}
          {/* DROPDOWN MENUS                                                   */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Dropdown Menus</SectionTitle>
            <Card>
              <CardContent>
                <div className="flex flex-wrap gap-3">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline">Actions</Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuLabel>Breach Actions</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem>View Details</DropdownMenuItem>
                      <DropdownMenuItem>Export Report</DropdownMenuItem>
                      <DropdownMenuItem>Mark as Resolved</DropdownMenuItem>
                      <DropdownMenuItem>Notify Affected Users</DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem variant="destructive">
                        Dismiss Alert
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>

                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="secondary">Filters</Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuLabel>Severity</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem>Critical</DropdownMenuItem>
                      <DropdownMenuItem>High</DropdownMenuItem>
                      <DropdownMenuItem>Medium</DropdownMenuItem>
                      <DropdownMenuItem>Low</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>

                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost">More</Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuLabel>Export Options</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem>CSV</DropdownMenuItem>
                      <DropdownMenuItem>JSON</DropdownMenuItem>
                      <DropdownMenuItem>PDF Report</DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </CardContent>
            </Card>
          </section>

          {/* ================================================================ */}
          {/* CARD PATTERNS                                                    */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Card Patterns</SectionTitle>
            <div className="grid gap-4 md:grid-cols-3">
              {/* Stat card */}
              <Card>
                <CardHeader>
                  <CardTitle>Scan Coverage</CardTitle>
                  <CardDescription>
                    Percentage of assets monitored
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p
                    className="text-primary text-4xl font-bold"
                    style={{
                      textShadow: `0 0 20px oklch(0.84 0.204 154 / 0.15)`,
                    }}
                  >
                    94%
                  </p>
                  <div
                    className="mt-2 h-2 overflow-hidden rounded-full"
                    style={{ background: "var(--muted)" }}
                  >
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: "94%",
                        background: GREEN,
                        boxShadow: glow(GREEN, 0.3),
                      }}
                    />
                  </div>
                </CardContent>
              </Card>

              {/* Action card */}
              <Card>
                <CardHeader>
                  <CardTitle>Quick Scan</CardTitle>
                  <CardDescription>
                    Check a single email address
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <Input placeholder="check@example.com" className="mb-3" />
                  <Button className="w-full" size="sm">
                    Check Now
                  </Button>
                </CardContent>
              </Card>

              {/* Status card */}
              <Card>
                <CardHeader>
                  <CardTitle>System Status</CardTitle>
                  <CardDescription>All services operational</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  {[
                    { name: "API", status: "Operational" },
                    { name: "Scanner", status: "Operational" },
                    { name: "Database", status: "Operational" },
                    { name: "Webhooks", status: "Degraded" },
                  ].map((svc) => (
                    <div
                      key={svc.name}
                      className="flex items-center justify-between text-sm"
                    >
                      <span>{svc.name}</span>
                      <div className="flex items-center gap-1.5">
                        <StatusDot
                          color={svc.status === "Operational" ? GREEN : AMBER}
                        />
                        <span className="text-muted-foreground text-xs">
                          {svc.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              {/* Empty state */}
              <Card>
                <CardContent className="flex flex-col items-center justify-center py-12 text-center">
                  <div
                    className="mb-4 flex h-12 w-12 items-center justify-center rounded-full text-xl"
                    style={{ background: "var(--accent)", color: GREEN }}
                  >
                    ?
                  </div>
                  <CardTitle className="mb-1 text-base">
                    No monitors configured
                  </CardTitle>
                  <CardDescription className="mb-4 max-w-xs">
                    Add your first domain or email to start monitoring for
                    breaches.
                  </CardDescription>
                  <Button size="sm">Add Monitor</Button>
                </CardContent>
              </Card>

              {/* Pricing / upgrade card */}
              <Card className="border-2" style={{ borderColor: GREEN }}>
                <CardHeader>
                  <Badge className="w-fit text-[10px]">Recommended</Badge>
                  <CardTitle>Pro Plan</CardTitle>
                  <CardDescription>
                    For teams that need advanced monitoring.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="mb-4">
                    <span
                      className="text-3xl font-bold"
                      style={{
                        textShadow: `0 0 16px oklch(0.84 0.204 154 / 0.12)`,
                      }}
                    >
                      $29
                    </span>
                    <span className="text-muted-foreground text-sm">
                      /month
                    </span>
                  </p>
                  <ul className="space-y-2 text-sm">
                    {[
                      "Unlimited domain monitors",
                      "Real-time webhook alerts",
                      "API access",
                      "CSV & PDF exports",
                      "Priority support",
                    ].map((f) => (
                      <li key={f} className="flex items-center gap-2">
                        <StatusDot color={GREEN} />
                        {f}
                      </li>
                    ))}
                  </ul>
                </CardContent>
                <CardFooter>
                  <Button className="w-full">Upgrade to Pro</Button>
                </CardFooter>
              </Card>
            </div>
          </section>

          {/* ================================================================ */}
          {/* SECONDARY TABLE - DOMAIN MONITORS                                */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Domain Monitors</SectionTitle>
            <Card>
              <CardHeader>
                <CardTitle>Active Monitors</CardTitle>
                <CardDescription>
                  Domains and emails being watched for breaches.
                </CardDescription>
                <CardAction>
                  <Button size="sm">Add Monitor</Button>
                </CardAction>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Target</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Last Scanned</TableHead>
                      <TableHead>Breaches</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {[
                      {
                        target: "example.com",
                        type: "Domain",
                        lastScan: "2 min ago",
                        breaches: 12,
                        status: "Active",
                      },
                      {
                        target: "john@example.com",
                        type: "Email",
                        lastScan: "5 min ago",
                        breaches: 4,
                        status: "Active",
                      },
                      {
                        target: "staging.example.com",
                        type: "Domain",
                        lastScan: "1 hour ago",
                        breaches: 0,
                        status: "Active",
                      },
                      {
                        target: "jane@example.com",
                        type: "Email",
                        lastScan: "3 hours ago",
                        breaches: 2,
                        status: "Active",
                      },
                      {
                        target: "legacy.example.com",
                        type: "Domain",
                        lastScan: "3 days ago",
                        breaches: 8,
                        status: "Paused",
                      },
                    ].map((row) => (
                      <TableRow key={row.target}>
                        <TableCell className="font-medium">
                          {row.target}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px]">
                            {row.type}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-muted-foreground text-sm">
                          {row.lastScan}
                        </TableCell>
                        <TableCell>
                          <span
                            className={
                              row.breaches > 0
                                ? "font-medium"
                                : "text-muted-foreground"
                            }
                          >
                            {row.breaches}
                          </span>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              row.status === "Active" ? "outline" : "secondary"
                            }
                            className="gap-1.5 text-[10px]"
                          >
                            <StatusDot
                              color={
                                row.status === "Active" ? GREEN : GREEN_DIM
                              }
                            />
                            {row.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex justify-end gap-1">
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-6 px-2 text-xs"
                            >
                              Scan
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-6 px-2 text-xs"
                            >
                              Edit
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </section>

          {/* ================================================================ */}
          {/* MISC / SEPARATORS / LABELS / STATUS                              */}
          {/* ================================================================ */}
          <section className="space-y-4">
            <SectionTitle>Miscellaneous</SectionTitle>
            <Card>
              <CardContent className="space-y-6">
                <div className="space-y-2">
                  <Label>Labels</Label>
                  <div className="flex items-center gap-4">
                    <Label>Default Label</Label>
                    <Separator orientation="vertical" className="h-4" />
                    <span className="text-muted-foreground text-sm">
                      Muted text
                    </span>
                    <Separator orientation="vertical" className="h-4" />
                    <span className="text-primary text-sm font-medium">
                      Primary text
                    </span>
                  </div>
                </div>
                <Separator />
                <div className="space-y-2">
                  <Label>Separators</Label>
                  <div className="flex items-center gap-4">
                    <span className="text-sm">Item A</span>
                    <Separator orientation="vertical" className="h-4" />
                    <span className="text-sm">Item B</span>
                    <Separator orientation="vertical" className="h-4" />
                    <span className="text-sm">Item C</span>
                    <Separator orientation="vertical" className="h-4" />
                    <span className="text-sm">Item D</span>
                  </div>
                </div>
                <Separator />
                <div className="space-y-2">
                  <Label>Status Indicators</Label>
                  <div className="flex flex-wrap items-center gap-5">
                    {[
                      { label: "Secure", color: GREEN },
                      { label: "Warning", color: AMBER },
                      { label: "Critical", color: RED },
                      { label: "Offline", color: GREEN_DIM },
                      { label: "Scanning", color: GREEN_MID },
                      { label: "Maintenance", color: GREEN_FAINT },
                    ].map((s) => (
                      <div key={s.label} className="flex items-center gap-2">
                        <StatusDot color={s.color} />
                        <span className="text-sm">{s.label}</span>
                      </div>
                    ))}
                  </div>
                </div>
                <Separator />
                <div className="space-y-2">
                  <Label>Keyboard Shortcuts</Label>
                  <div className="flex flex-wrap gap-2">
                    {[
                      { keys: "Ctrl + K", action: "Search" },
                      { keys: "Ctrl + N", action: "New monitor" },
                      { keys: "Ctrl + R", action: "Run scan" },
                      { keys: "Ctrl + E", action: "Export" },
                    ].map((kb) => (
                      <div
                        key={kb.keys}
                        className="flex items-center gap-2 text-sm"
                      >
                        <kbd
                          className="rounded border px-1.5 py-0.5 font-mono text-xs"
                          style={{
                            background: "var(--muted)",
                            borderColor: "var(--border)",
                          }}
                        >
                          {kb.keys}
                        </kbd>
                        <span className="text-muted-foreground text-xs">
                          {kb.action}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          </section>

          {/* ================================================================ */}
          {/* FOOTER                                                           */}
          {/* ================================================================ */}
          <footer
            className="border-t pt-8 pb-8"
            style={{ borderColor: "var(--border)" }}
          >
            <div className="flex flex-col items-center gap-4">
              <div className="flex items-center gap-3">
                <StatusDot color={GREEN} />
                <span
                  className="text-sm font-semibold"
                  style={{ textShadow: `0 0 12px oklch(0.84 0.204 154 / 0.1)` }}
                >
                  Am I Being Pwned?
                </span>
                <StatusDot color={GREEN} />
              </div>
              <div className="text-muted-foreground flex items-center gap-3 text-xs">
                <span>AIBP - Deep Theme</span>
                <Separator orientation="vertical" className="h-3" />
                <span>Night Shift Edition</span>
                <Separator orientation="vertical" className="h-3" />
                <span>All OKLCH values from documented sources</span>
              </div>
              <div className="flex gap-2">
                <Button size="sm" variant="ghost" className="text-xs">
                  Documentation
                </Button>
                <Button size="sm" variant="ghost" className="text-xs">
                  API Reference
                </Button>
                <Button size="sm" variant="ghost" className="text-xs">
                  Status Page
                </Button>
                <Button size="sm" variant="ghost" className="text-xs">
                  Contact
                </Button>
              </div>
            </div>
          </footer>
        </div>
      </div>
    </div>
  ),
};
