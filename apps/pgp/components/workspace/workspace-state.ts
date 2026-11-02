import type { PresentedError } from "../../lib/errors/present";
import type { WorkspaceAction } from "../../lib/messages";
import type { MessageEncryption } from "../../lib/pgp/wasm-public";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { FileResult } from "../../lib/utils/download";
import { looksLikeAgeMessage } from "../../lib/armor-blocks";
import { firstMessageHeader } from "../../lib/classify-action";
import { looksLikePrivateKey } from "../../lib/drop-routing";
import { resolveSelfKey } from "../../lib/encrypt-recipients";
import { isPgpRecord, isSshRecord } from "../../lib/storage/key-kind";

/**
 * The workspace's render state, as one reducer.
 *
 * PLAINTEXT NEVER ENTERS IT. The composed message, the result text and a
 * translation live in refs + uncontrolled DOM nodes (SECURITY.md §8.11,
 * T-DRAFT-HEAP-RESIDUE / T-OUTPUT-HEAP-RESIDUE); only facts about them
 * (`TextFacts`) are state. Binary / multi-file results must be state (a
 * row per file), so `wipePlaintext` zeroizes them in place.
 */

export type Mode = WorkspaceAction;

/** Same floor as the vault's `validatePassword`: a message password
 *  guards a file attackable offline forever. */
export const MIN_MESSAGE_PASSWORD_LENGTH = 8;

const PUBLIC_KEY_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

/** What the workspace may know about a text without holding it. */
export interface TextFacts {
  len: number;
  nonBlank: boolean;
  /** The mode the EARLIEST armored message calls for (as `classifyAction`):
   *  a signed message quoting an encrypted one is still something to verify. */
  armor: "decrypt" | "verify" | null;
  /** A key block that is not part of a message. */
  key: "public" | "private" | null;
  age: boolean;
}

export function textFacts(text: string): TextFacts {
  const age = looksLikeAgeMessage(text);
  const armor = firstMessageHeader(text)?.action ?? (age ? "decrypt" : null);
  return {
    len: text.length,
    // `\S`, not trim(): trim() would copy the plaintext.
    nonBlank: /\S/.test(text),
    armor,
    // A private key wins over everything (the draft refuses to seal while
    // it is set); a message is a message whatever key it quotes.
    key: looksLikePrivateKey(text)
      ? "private"
      : !armor && text.includes(PUBLIC_KEY_HEADER)
        ? "public"
        : null,
    age,
  };
}

const NO_TEXT: TextFacts = textFacts("");

export interface Verdict {
  signer: PublicContactKey | ProtectedKeyBlob;
  tone: "success" | "warning";
  /** Said under the signer: when it was signed, co-signers, ... */
  note: string | null;
  /** A good signature with a caveat (retired key, signed for someone
   *  else): amber, but not "unknown signer". */
  caveat: string | null;
}

export interface RunResult {
  status: string | null;
  verdict: Verdict | null;
  binary?: Uint8Array;
  files: FileResult[];
}

export type Run =
  | { kind: "idle" }
  /** `unattended`: a context-menu auto-run; the form stays hidden. */
  | { kind: "running"; unattended: boolean }
  | { kind: "done" }
  | { kind: "error"; error: PresentedError }
  /** An unattended run came out over `AUTO_RUN_MAX_BYTES`. */
  | { kind: "held-back" }
  /** Text to be signed holds characters the box does not draw. */
  | { kind: "hidden-chars"; chars: string[] };

/** Which secret the inline password row asks for. One row, three
 *  questions -- and different code on submit, so never confusable. */
export type PromptKind = "key" | "message" | "crx";

export interface Prompt {
  kind: PromptKind;
  value: string;
  error: string | null;
}

/** What a run came to. Applied in one dispatch (see `finished`). */
export type Outcome =
  | ({
      kind: "done";
      text?: string;
      spentPassword?: boolean;
    } & Partial<RunResult>)
  | { kind: "error"; error: PresentedError }
  | { kind: "prompt"; prompt: PromptKind }
  /** The secret just typed was wrong: said under the prompt, which stays. */
  | { kind: "rejected"; message: string }
  | { kind: "held-back" }
  | { kind: "hidden-chars"; chars: string[] }
  /** Nothing to show: a cancelled ceremony, an unattended run that would
   *  have needed a prompt. */
  | { kind: "none" };

export interface WorkspaceState {
  mode: Mode;
  input: TextFacts & { version: number };
  output: { len: number; publicKey: boolean; version: number };
  files: File[];
  /** Bumped whenever what a run reads changes (text, files, mode). A run
   *  finishing under a newer value is discarded: a verdict must never sit
   *  over input it did not read. */
  staged: number;
  /** How the staged message can be opened; null until scanned. */
  messageEncryption: MessageEncryption | null;
  isExtensionZip: boolean;
  zipFiles: boolean;
  recipientIds: string[];
  /** Explicit picks. What is in effect is derived: the pick while it is
   *  still valid, else the default (see `resolveKeyId`). */
  keyPick: string | null;
  crxKeyPick: string | null;
  signKindPick: "pgp" | "crx" | null;
  run: Run;
  result: RunResult;
  prompt: Prompt | null;
  /** A context-menu selection waiting to run by itself. */
  autoRun: "decrypt" | "verify" | null;
  /** The message password; never persisted, wiped at master lock. */
  encryptPassword: string;
  passwordDialogOpen: boolean;
  clearUndo: boolean;
}

const EMPTY_RESULT: RunResult = { status: null, verdict: null, files: [] };

export const initialWorkspaceState: WorkspaceState = {
  mode: "encrypt",
  input: { ...NO_TEXT, version: 0 },
  output: { len: 0, publicKey: false, version: 0 },
  files: [],
  staged: 0,
  messageEncryption: null,
  isExtensionZip: false,
  zipFiles: true,
  recipientIds: [],
  keyPick: null,
  crxKeyPick: null,
  signKindPick: null,
  run: { kind: "idle" },
  result: EMPTY_RESULT,
  prompt: null,
  autoRun: null,
  encryptPassword: "",
  passwordDialogOpen: false,
  clearUndo: false,
};

export type WorkspaceEvent =
  /** The box's own onChange (or a paste): armor arriving nudges the mode. */
  | { type: "edited"; text: TextFacts }
  | { type: "mode-picked"; mode: Mode }
  /** Escape back to the start: nothing is staged, so nothing to reset. */
  | { type: "mode-reset" }
  /** A context-menu or keyboard op. `text` absent: switch mode only. */
  | {
      type: "opened";
      mode: Mode;
      text?: TextFacts;
      autoRun: "decrypt" | "verify" | null;
    }
  | {
      type: "restored";
      mode: Mode;
      text: TextFacts;
      recipientIds: string[];
      keyPick: string | null;
    }
  | {
      type: "undo-restored";
      text: TextFacts;
      files: File[];
      recipientIds: string[];
    }
  | { type: "encrypt-to"; keyId: string }
  | {
      type: "dropped";
      files: File[];
      /** Ciphertext arrived: flips encrypt to decrypt. */
      encrypted: boolean;
      oversized: string | null;
    }
  | { type: "file-removed"; index: number }
  | { type: "files-cleared" }
  | { type: "recipients"; ids: string[] }
  | { type: "key-picked"; keyId: string | null }
  | { type: "crx-key-picked"; id: string }
  | { type: "sign-kind"; kind: "pgp" | "crx" }
  | { type: "zip-files"; on: boolean }
  | { type: "password-set"; password: string }
  | { type: "password-dialog"; open: boolean }
  | { type: "prompt-typed"; value: string }
  | { type: "prompted"; kind: PromptKind }
  | { type: "reset-results" }
  | { type: "reset-all" }
  /** A fresh run: the last results go. */
  | { type: "started"; unattended?: boolean }
  /** A prompt's secret was submitted; results stay. */
  | { type: "submitted" }
  | { type: "finished"; outcome: Outcome; staged: number }
  | { type: "status"; text: string | null }
  | { type: "output"; len: number; publicKey: boolean }
  | { type: "message-encryption"; value: MessageEncryption | null }
  | { type: "extension-zip"; value: boolean; nudge: boolean }
  | { type: "auto-run-dropped" }
  | { type: "clear-undo"; available: boolean }
  | { type: "wiped" };

function withText(s: WorkspaceState, text: TextFacts): WorkspaceState {
  return {
    ...s,
    input: { ...text, version: s.input.version + 1 },
    staged: s.staged + 1,
    // Stale the moment the text changes.
    messageEncryption: null,
  };
}

function withFiles(s: WorkspaceState, files: File[]): WorkspaceState {
  return {
    ...s,
    files,
    staged: s.staged + 1,
    messageEncryption: null,
    signKindPick: null,
  };
}

function withMode(s: WorkspaceState, mode: Mode): WorkspaceState {
  return mode === s.mode ? s : { ...s, mode, staged: s.staged + 1 };
}

/** The one "results go" rule. A run in flight keeps running: its own
 *  finish is discarded by the `staged` guard if the input moved. */
function resetResults(s: WorkspaceState): WorkspaceState {
  return {
    ...s,
    run: s.run.kind === "running" ? s.run : { kind: "idle" },
    result: EMPTY_RESULT,
    output: { len: 0, publicKey: false, version: s.output.version + 1 },
    prompt: null,
  };
}

function resetAll(s: WorkspaceState): WorkspaceState {
  // A cleared workspace is a fresh message: its recipients go with it.
  return resetResults({
    ...withFiles(withText(s, NO_TEXT), []),
    recipientIds: [],
    autoRun: null,
  });
}

function finish(s: WorkspaceState, outcome: Outcome): WorkspaceState {
  const idle = { ...s, run: { kind: "idle" } as const };
  switch (outcome.kind) {
    case "done":
      return {
        ...s,
        run: { kind: "done" },
        prompt: null,
        encryptPassword: outcome.spentPassword ? "" : s.encryptPassword,
        result: {
          status: outcome.status ?? null,
          verdict: outcome.verdict ?? null,
          binary: outcome.binary,
          files: outcome.files ?? [],
        },
      };
    case "error":
      return { ...s, run: { kind: "error", error: outcome.error } };
    case "prompt":
      return {
        ...idle,
        prompt: { kind: outcome.prompt, value: "", error: null },
      };
    case "rejected":
      return s.prompt
        ? { ...idle, prompt: { ...s.prompt, error: outcome.message } }
        : idle;
    case "held-back":
      return { ...s, run: { kind: "held-back" } };
    case "hidden-chars":
      return { ...s, run: { kind: "hidden-chars", chars: outcome.chars } };
    case "none":
      return idle;
  }
}

export function workspaceReducer(
  s: WorkspaceState,
  e: WorkspaceEvent,
): WorkspaceState {
  switch (e.type) {
    case "edited": {
      // The nudge fires only when the armor ARRIVES: once it has, the mode
      // is the user's choice.
      const nudge =
        e.text.key !== "private" &&
        e.text.armor &&
        e.text.armor !== s.input.armor
          ? e.text.armor
          : null;
      // Encrypt carries the message alongside attachments (as msg.txt);
      // elsewhere text and files are alternatives.
      const next = s.mode === "encrypt" ? s : withFiles(s, []);
      return resetResults({
        ...withMode(withText(next, e.text), nudge ?? s.mode),
        autoRun: null,
      });
    }
    case "mode-picked": {
      const next = withMode(s, e.mode);
      return s.run.kind === "done" ? resetAll(next) : resetResults(next);
    }
    case "mode-reset":
      return withMode(s, "encrypt");
    case "opened": {
      const next = withMode(s, e.mode);
      if (!e.text) return next;
      return resetResults({
        ...withFiles(withText(next, e.text), []),
        autoRun: e.autoRun,
      });
    }
    case "restored":
      return {
        ...withMode(withText(s, e.text), e.mode),
        recipientIds: e.recipientIds,
        keyPick: e.keyPick,
      };
    case "undo-restored": {
      const nudge =
        e.text.key !== "private" && e.text.armor ? e.text.armor : s.mode;
      return {
        ...withMode(withFiles(withText(s, e.text), e.files), nudge),
        recipientIds: e.recipientIds,
        clearUndo: false,
      };
    }
    case "encrypt-to":
      return { ...withMode(s, "encrypt"), recipientIds: [e.keyId] };
    case "dropped": {
      if (e.files.length === 0) {
        // Nothing staged: leave the workspace as it was and say why.
        return e.oversized
          ? { ...s, run: { kind: "error", error: { message: e.oversized } } }
          : s;
      }
      // A file named like one already staged REPLACES it: verifying the
      // old copy of a re-downloaded release.asc would say so in green.
      const incoming = new Map(e.files.map((f) => [f.name, f]));
      const kept = s.files.map((f) => incoming.get(f.name) ?? f);
      const added = [...incoming.values()].filter((f) => !kept.includes(f));
      let next = withFiles(s, [...kept, ...added]);
      if (s.mode !== "encrypt" || e.encrypted) next = withText(next, NO_TEXT);
      if (e.encrypted && s.mode === "encrypt") next = withMode(next, "decrypt");
      next = resetResults(next);
      // After the reset: a partial drop stages what it can AND reports
      // what it skipped.
      return e.oversized
        ? { ...next, run: { kind: "error", error: { message: e.oversized } } }
        : next;
    }
    case "file-removed":
      return resetResults(
        withFiles(
          s,
          s.files.filter((_, i) => i !== e.index),
        ),
      );
    case "files-cleared":
      // The files only: a message written alongside them stays.
      return resetResults(withFiles(s, []));
    case "recipients":
      return resetResults({ ...s, recipientIds: e.ids });
    case "key-picked":
      return resetResults({ ...s, keyPick: e.keyId });
    case "crx-key-picked":
      return { ...s, crxKeyPick: e.id };
    case "sign-kind":
      return { ...s, signKindPick: e.kind };
    case "zip-files":
      return resetResults({ ...s, zipFiles: e.on });
    case "password-set":
      return resetResults({
        ...s,
        encryptPassword: e.password,
        passwordDialogOpen: false,
      });
    case "password-dialog":
      return { ...s, passwordDialogOpen: e.open };
    case "prompt-typed":
      return s.prompt ? { ...s, prompt: { ...s.prompt, value: e.value } } : s;
    case "prompted":
      return finish(s, { kind: "prompt", prompt: e.kind });
    case "reset-results":
      return resetResults(s);
    case "reset-all":
      return resetAll(s);
    case "started":
      return {
        ...resetResults(s),
        run: { kind: "running", unattended: e.unattended ?? false },
      };
    case "submitted":
      return {
        ...s,
        run: { kind: "running", unattended: false },
        prompt: s.prompt && { ...s.prompt, error: null },
      };
    case "finished":
      if (e.staged !== s.staged) {
        // The input moved while it ran: keep nothing it produced.
        return {
          ...resetResults(s),
          run: { kind: "idle" },
          encryptPassword:
            e.outcome.kind === "done" && e.outcome.spentPassword
              ? ""
              : s.encryptPassword,
        };
      }
      return finish(s, e.outcome);
    case "status":
      return { ...s, result: { ...s.result, status: e.text } };
    case "output":
      return {
        ...s,
        output: {
          len: e.len,
          publicKey: e.publicKey,
          version: s.output.version + 1,
        },
      };
    case "message-encryption":
      return { ...s, messageEncryption: e.value };
    case "extension-zip": {
      const next = { ...s, isExtensionZip: e.value };
      // Only from encrypt/decrypt, so an explicit sign/verify is kept.
      return e.nudge && (s.mode === "encrypt" || s.mode === "decrypt")
        ? withMode(next, "sign")
        : next;
    }
    case "auto-run-dropped":
      return { ...s, autoRun: null };
    case "clear-undo":
      return { ...s, clearUndo: e.available };
    case "wiped":
      return { ...s, encryptPassword: "", passwordDialogOpen: false };
  }
}

// ── derived ─────────────────────────────────────────────────────────

export const isRunning = (s: WorkspaceState) => s.run.kind === "running";
export const isDone = (s: WorkspaceState) => s.run.kind === "done";

/** The staged input is age: armored/binary text, or `.age` files. */
export function inputIsAge(s: WorkspaceState): boolean {
  return s.input.age || s.files.some((f) => /\.age$/i.test(f.name));
}

/** A usable message password is set -- the only state in which one is
 *  added. Derived from the password, so no flag can arm it. */
export function encryptPasswordReady(s: WorkspaceState): boolean {
  return s.encryptPassword.length >= MIN_MESSAGE_PASSWORD_LENGTH;
}

/**
 * The private key in effect: the user's pick while it can do the job,
 * else the default. Signing is OpenPGP-only and an age message opens only
 * with an SSH identity, so those modes narrow the pool first.
 */
export function resolveKeyId(
  s: Pick<WorkspaceState, "mode" | "keyPick"> & { age: boolean },
  keys: readonly ProtectedKeyBlob[],
  defaultKeyId: string | null,
): string | null {
  const pool =
    s.mode === "sign"
      ? keys.filter(isPgpRecord)
      : s.mode === "decrypt" && s.age
        ? keys.filter(isSshRecord)
        : keys;
  if (pool.some((k) => k.keyId === s.keyPick)) return s.keyPick;
  return resolveSelfKey(pool, defaultKeyId)?.keyId ?? null;
}

/**
 * Overwrite binary and multi-file result bytes with zeroes, in place.
 *
 * Dropping the reference is NOT enough: these are render state, and at
 * master lock a `setState` is batched with the unmount and never commits,
 * so the previous fiber's `lastRenderedState` keeps the buffer
 * (T-OUTPUT-HEAP-RESIDUE). Detached buffers throw on write and hold
 * nothing readable, so they are skipped.
 */
export function zeroizeResultBytes(
  binary: Uint8Array | undefined,
  results: readonly FileResult[],
): void {
  const wipe = (buf: Uint8Array | undefined) => {
    if (!buf || buf.byteLength === 0) return;
    try {
      buf.fill(0);
    } catch {
      /* detached */
    }
  };
  wipe(binary);
  for (const r of results) wipe(r.data);
}
