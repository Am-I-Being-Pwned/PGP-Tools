import type { Meta, StoryObj } from "@storybook/react";

import { Badge } from "../badge";
import { Button } from "../button";
import {
  Card,
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

const meta = {
  title: "Moodboard",
  parameters: {
    layout: "fullscreen",
  },
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

export const Overview: Story = {
  render: () => (
    <div className="bg-background text-foreground min-h-screen p-8">
      <div className="mx-auto max-w-5xl space-y-12">
        {/* Header */}
        <div className="space-y-2">
          <h1 className="text-4xl font-bold tracking-tight">
            Am I Being Pwned?
          </h1>
          <p className="text-muted-foreground text-lg">UI Theme Moodboard</p>
          <Separator className="mt-4" />
        </div>

        {/* Color Palette */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold">Color Palette</h2>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 md:grid-cols-6">
            {[
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
              { name: "Accent", bg: "bg-accent", fg: "text-accent-foreground" },
              { name: "Muted", bg: "bg-muted", fg: "text-muted-foreground" },
              {
                name: "Destructive",
                bg: "bg-destructive",
                fg: "text-destructive-foreground",
              },
              { name: "Card", bg: "bg-card", fg: "text-card-foreground" },
            ].map((c) => (
              <div key={c.name} className="space-y-1.5">
                <div
                  className={`${c.bg} ${c.fg} flex h-20 items-center justify-center rounded-lg border text-sm font-medium`}
                >
                  {c.name}
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Typography */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold">Typography</h2>
          <Card>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <p className="text-4xl font-bold tracking-tight">Heading 1</p>
                <p className="text-3xl font-semibold tracking-tight">
                  Heading 2
                </p>
                <p className="text-2xl font-semibold">Heading 3</p>
                <p className="text-xl font-medium">Heading 4</p>
                <p className="text-base">
                  Body text - The quick brown fox jumps over the lazy dog.
                </p>
                <p className="text-muted-foreground text-sm">
                  Muted text - Secondary information and descriptions.
                </p>
                <p className="text-muted-foreground text-xs">
                  Caption - Fine print and metadata.
                </p>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Buttons */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold">Buttons</h2>
          <Card>
            <CardContent className="space-y-6">
              <div className="flex flex-wrap items-center gap-3">
                <Button>Primary</Button>
                <Button variant="secondary">Secondary</Button>
                <Button variant="outline">Outline</Button>
                <Button variant="ghost">Ghost</Button>
                <Button variant="link">Link</Button>
                <Button variant="destructive">Destructive</Button>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Button size="sm">Small</Button>
                <Button size="default">Default</Button>
                <Button size="lg">Large</Button>
                <Button disabled>Disabled</Button>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Badges */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold">Badges</h2>
          <Card>
            <CardContent>
              <div className="flex flex-wrap items-center gap-3">
                <Badge>Default</Badge>
                <Badge variant="secondary">Secondary</Badge>
                <Badge variant="outline">Outline</Badge>
                <Badge variant="destructive">Destructive</Badge>
                <Badge variant="ghost">Ghost</Badge>
                <Badge variant="link">Link</Badge>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Cards */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold">Cards</h2>
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <CardHeader>
                <CardTitle>Breaches Found</CardTitle>
                <CardDescription>Last 30 days</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-4xl font-bold">12</p>
                <p className="text-destructive text-sm font-medium">+3 new</p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Accounts Monitored</CardTitle>
                <CardDescription>Active monitoring</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-4xl font-bold">47</p>
                <p className="text-muted-foreground text-sm">
                  Across 8 domains
                </p>
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>Risk Score</CardTitle>
                <CardDescription>Overall assessment</CardDescription>
              </CardHeader>
              <CardContent>
                <p className="text-primary text-4xl font-bold">Medium</p>
                <p className="text-muted-foreground text-sm">
                  2 actions recommended
                </p>
              </CardContent>
              <CardFooter>
                <Button size="sm" variant="outline">
                  View Details
                </Button>
              </CardFooter>
            </Card>
          </div>
        </section>

        {/* Form Elements */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold">Form Elements</h2>
          <Card>
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
                        Monitor an entire domain.
                      </FieldDescription>
                    </FieldContent>
                  </Field>
                  <Field data-invalid="true">
                    <FieldLabel>API Key</FieldLabel>
                    <FieldContent>
                      <Input placeholder="aibp_..." aria-invalid />
                      <FieldError>Invalid API key format.</FieldError>
                    </FieldContent>
                  </Field>
                  <Field>
                    <FieldLabel>Notification Email</FieldLabel>
                    <FieldContent>
                      <Input
                        type="email"
                        placeholder="alerts@example.com"
                        disabled
                      />
                      <FieldDescription>
                        Upgrade to enable notifications.
                      </FieldDescription>
                    </FieldContent>
                  </Field>
                </div>
              </FieldGroup>
            </CardContent>
          </Card>
        </section>

        {/* Dropdown */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold">Dropdown Menu</h2>
          <Card>
            <CardContent>
              <div className="flex gap-3">
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
                    <DropdownMenuSeparator />
                    <DropdownMenuItem variant="destructive">
                      Dismiss
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Table */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold">Data Table</h2>
          <Card>
            <CardHeader>
              <CardTitle>Recent Breaches</CardTitle>
              <CardDescription>
                Compromised accounts detected in monitoring.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Service</TableHead>
                    <TableHead>Email</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead className="text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {[
                    {
                      service: "LinkedIn",
                      email: "john@example.com",
                      date: "2025-12-14",
                      severity: "High",
                      status: "Unresolved",
                    },
                    {
                      service: "Dropbox",
                      email: "john@example.com",
                      date: "2025-11-02",
                      severity: "Medium",
                      status: "Resolved",
                    },
                    {
                      service: "Adobe",
                      email: "jane@example.com",
                      date: "2025-10-18",
                      severity: "Low",
                      status: "Resolved",
                    },
                    {
                      service: "Canva",
                      email: "jane@example.com",
                      date: "2025-09-30",
                      severity: "High",
                      status: "Unresolved",
                    },
                    {
                      service: "Twitter",
                      email: "john@example.com",
                      date: "2025-08-22",
                      severity: "Medium",
                      status: "Resolved",
                    },
                  ].map((row) => (
                    <TableRow key={`${row.service}-${row.email}`}>
                      <TableCell className="font-medium">
                        {row.service}
                      </TableCell>
                      <TableCell>{row.email}</TableCell>
                      <TableCell>{row.date}</TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            row.severity === "High"
                              ? "destructive"
                              : row.severity === "Medium"
                                ? "default"
                                : "secondary"
                          }
                        >
                          {row.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Badge
                          variant={
                            row.status === "Resolved" ? "outline" : "ghost"
                          }
                        >
                          {row.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </section>

        {/* Misc */}
        <section className="space-y-4">
          <h2 className="text-2xl font-semibold">Miscellaneous</h2>
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
                </div>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Footer */}
        <div className="text-muted-foreground pb-8 text-center text-sm">
          Am I Being Pwned? - UI Moodboard
        </div>
      </div>
    </div>
  ),
};
