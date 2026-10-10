// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest";

import {
  addRecipients,
  bodyHoldsCiphertext,
  clippedLinkFor,
  composeDraftText,
  composeRootOf,
  dropFiles,
  encryptedAttachmentChips,
  findArmor,
  isStandaloneMessageView,
  messageBodies,
  messageText,
  normalizeArmorText,
  parseDownloadUrl,
  readRecipients,
  sampleTheme,
  sendButtonIn,
  writeCiphertext,
} from "./dom";

const MSG = [
  "-----BEGIN PGP MESSAGE-----",
  "",
  "hQEMA2b3c4d5e6f7AQf/abc",
  "=AbCd",
  "-----END PGP MESSAGE-----",
].join("\n");

describe("findArmor", () => {
  it("finds a message block in surrounding prose", () => {
    const found = findArmor(`Hi,\n\n${MSG}\n\nThanks`);
    expect(found).toEqual({ kind: "message", text: MSG, clipped: false });
  });

  it("finds a signed message through to its signature's end", () => {
    const signed = [
      "-----BEGIN PGP SIGNED MESSAGE-----",
      "Hash: SHA256",
      "",
      "hello",
      "-----BEGIN PGP SIGNATURE-----",
      "",
      "iQEz",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    expect(findArmor(signed)).toEqual({
      kind: "signed",
      text: signed,
      clipped: false,
    });
  });

  it("finds a public key", () => {
    const key =
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ\n-----END PGP PUBLIC KEY BLOCK-----";
    expect(findArmor(key)?.kind).toBe("public-key");
  });

  it("takes whichever block comes first", () => {
    const key =
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmDMEZ\n-----END PGP PUBLIC KEY BLOCK-----";
    expect(findArmor(`${MSG}\n${key}`)?.kind).toBe("message");
    expect(findArmor(`${key}\n${MSG}`)?.kind).toBe("public-key");
  });

  it("flags a block Gmail cut off before its END", () => {
    const cut = MSG.split("\n").slice(0, 3).join("\n");
    expect(findArmor(`Hi\n${cut}`)).toEqual({
      kind: "message",
      text: cut,
      clipped: true,
    });
  });

  it("ignores a quoted block and prose that only mentions the marker", () => {
    const quoted = MSG.split("\n")
      .map((l) => `> ${l}`)
      .join("\n");
    expect(findArmor(quoted)).toBeNull();
    expect(
      findArmor("paste the -----BEGIN PGP MESSAGE----- line in"),
    ).toBeNull();
  });

  it("allows an indented block", () => {
    expect(findArmor(MSG.replace("-----BEGIN", "   -----BEGIN"))?.clipped).toBe(
      false,
    );
  });

  it("normalises nbsp, zero-width characters, CRLF and trailing spaces", () => {
    expect(normalizeArmorText("a b​ \r\nc  ")).toBe("a b\nc");
    const mangled = MSG.replaceAll("\n", "  \r\n").replace("hQEMA", "hQ​EMA");
    expect(findArmor(mangled)?.text).toBe(MSG);
  });
});

/** A thread and a compose window, shaped like the Gmail markup the
 *  reference integrations target. */
function gmailFixture(): void {
  document.body.innerHTML = `
    <div class="adn" data-message-id="#msg-1">
      <div class="ii gt"><div class="a3s aiL">Hello</div></div>
      <div class="iX"><a href="?ui=2&amp;view=lg&amp;permmsgid=1">View entire message</a></div>
    </div>
    <div class="M9">
      <div class="I5">
        <form>
          <div class="aoD">
            <span email="alice@example.com" class="vR">Alice</span>
            <input class="agP aFw" aria-label="To recipients" />
            <div data-hovercard-id="Bob@Example.org">Bob</div>
            <span data-hovercard-id="not-an-address"></span>
          </div>
          <input name="cc" value="Carol <carol@example.com>, dave@example.com" />
          <input name="bcc" value="hidden@example.com" />
          <div aria-label="Bcc recipients"><span email="secret@example.com">S</span></div>
        </form>
        <div class="Am Al editable" contenteditable="true" g_editable="true" role="textbox" aria-multiline="true">
          <div>Dear Alice,</div><div><br></div><div>The plan stands.</div>
          <div class="gmail_quote">On Tue, <span email="eve@example.com">Eve</span> wrote:<blockquote>old text</blockquote></div>
        </div>
        <table><tr class="btC"><td class="gU Up"><div class="dC"><div class="T-I J-J5-Ji aoO" role="button">Send</div></div></td></tr></table>
      </div>
    </div>`;
}

describe("Gmail DOM", () => {
  beforeEach(gmailFixture);

  it("finds message bodies but not editors", () => {
    const bodies = messageBodies(document);
    expect(bodies).toHaveLength(1);
    expect(bodies[0].textContent).toBe("Hello");
  });

  it("finds a compose window's root and Send button", () => {
    const body = document.querySelector<HTMLElement>("[g_editable]");
    expect(body).not.toBeNull();
    if (!body) return;
    const root = composeRootOf(body);
    expect(root?.className).toBe("I5");
    expect(root && sendButtonIn(root)?.textContent).toBe("Send");
  });

  it("reads To/Cc from chips and inputs, never Bcc and never the quote", () => {
    const root = document.querySelector(".I5");
    expect(root && readRecipients(root)).toEqual([
      "alice@example.com",
      "bob@example.org",
      "carol@example.com",
      "dave@example.com",
    ]);
  });

  it("reads the draft without Gmail's quoted original", () => {
    const body = document.querySelector("[g_editable]");
    expect(body && composeDraftText(body)).toBe(
      "Dear Alice,\n\nThe plan stands.",
    );
  });

  it("writes ciphertext as one line per div and fires input", () => {
    const body = document.querySelector<HTMLElement>("[g_editable]");
    if (!body) throw new Error("fixture");
    let inputs = 0;
    body.addEventListener("input", () => inputs++);
    writeCiphertext(body, MSG);
    expect(inputs).toBe(1);
    expect(body.children).toHaveLength(MSG.split("\n").length);
    expect(body.querySelector(".gmail_quote")).toBeNull();
    // The blank separator line survives as an empty div with a <br>.
    expect(body.children[1].innerHTML).toBe("<br>");
    expect(composeDraftText(body)).toBe(MSG);
    expect(bodyHoldsCiphertext(body)).toBe(true);
  });

  it("writes text, never markup", () => {
    const body = document.querySelector<HTMLElement>("[g_editable]");
    if (!body) throw new Error("fixture");
    writeCiphertext(body, "<img src=x onerror=alert(1)>");
    expect(body.querySelector("img")).toBeNull();
    expect(body.textContent).toContain("<img");
  });

  it("follows only Gmail's own clipped-message link, rebuilt on its origin", () => {
    const loc = new URL(
      "https://mail.google.com/mail/u/0/#inbox/msg-1",
    ) as unknown as Location;
    const body = document.querySelector("div.a3s");
    if (!body) throw new Error("fixture");
    // The fixture's footer link is relative; it resolves onto Gmail.
    document
      .querySelector(".iX a")
      ?.setAttribute("href", "/mail/u/0?ui=2&view=lg&permmsgid=1");
    expect(clippedLinkFor(body, loc)?.href).toBe(
      "https://mail.google.com/mail/u/0?ui=2&view=lg&permmsgid=1",
    );
  });

  it("refuses a look-alike link from inside the email body", () => {
    const loc = new URL(
      "https://mail.google.com/mail/u/0/",
    ) as unknown as Location;
    const body = document.querySelector("div.a3s");
    if (!body) throw new Error("fixture");
    document.querySelector(".iX")?.remove();
    body.innerHTML =
      '<div class="iX"><a href="https://phish.example/mail/?view=lg">View entire message</a></div>';
    expect(clippedLinkFor(body, loc)).toBeNull();
  });

  it("refuses a footer link to another origin or a javascript: URL", () => {
    const loc = new URL(
      "https://mail.google.com/mail/u/0/",
    ) as unknown as Location;
    const body = document.querySelector("div.a3s");
    const link = document.querySelector(".iX a");
    if (!body || !link) throw new Error("fixture");
    link.setAttribute("href", "https://phish.example/mail/?view=lg");
    expect(clippedLinkFor(body, loc)).toBeNull();
    link.setAttribute("href", "javascript:alert(1)//view=lg");
    expect(clippedLinkFor(body, loc)).toBeNull();
  });

  it("types new recipients into the To box and lets Gmail chip them on blur", () => {
    const root = document.querySelector(".I5");
    const input = document.querySelector<HTMLInputElement>("input.agP");
    if (!root || !input) throw new Error("fixture");
    const events: string[] = [];
    for (const type of ["input", "change", "blur"]) {
      input.addEventListener(type, () => events.push(type));
    }
    // alice is already a chip; only erin is new.
    expect(addRecipients(root, ["alice@example.com", "erin@example.com"])).toBe(
      true,
    );
    expect(input.value).toBe("erin@example.com, ");
    expect(events).toEqual(["input", "change", "blur"]);
  });

  it("does nothing when every address is already there, and fails with no To box", () => {
    const root = document.querySelector(".I5");
    if (!root) throw new Error("fixture");
    expect(addRecipients(root, ["alice@example.com"])).toBe(true);
    expect(document.querySelector<HTMLInputElement>("input.agP")?.value).toBe(
      "",
    );
    document.querySelector("input.agP")?.remove();
    expect(addRecipients(root, ["erin@example.com"])).toBe(false);
  });

  it("knows Gmail's standalone message views", () => {
    const at = (search: string) =>
      isStandaloneMessageView({ search } as Location);
    expect(at("?ui=2&view=lg&permmsgid=1")).toBe(true);
    expect(at("?view=pt")).toBe(true);
    expect(at("")).toBe(false);
    expect(at("?view=om")).toBe(false);
  });
});

describe("messageText", () => {
  it("reads Gmail's one-div-per-line markup back as the lines written", () => {
    document.body.innerHTML = `<div class="a3s">
      <div dir="ltr">Hi,</div><div><br></div>
      <div>-----BEGIN PGP SIGNED MESSAGE-----</div><div>Hash: SHA512</div>
      <div><br></div><div>signed text</div><div><br></div><div><br></div>
      <div>second paragraph</div><div>-----BEGIN PGP SIGNATURE-----</div>
    </div>`;
    const body = document.querySelector<HTMLElement>(".a3s");
    if (!body) throw new Error("no body");
    expect(normalizeArmorText(messageText(body)).trim()).toBe(
      [
        "Hi,",
        "",
        "-----BEGIN PGP SIGNED MESSAGE-----",
        "Hash: SHA512",
        "",
        "signed text",
        "",
        "",
        "second paragraph",
        "-----BEGIN PGP SIGNATURE-----",
      ].join("\n"),
    );
  });

  it("keeps quoted blocks (a received message may be a forward) but drops hidden ones", () => {
    document.body.innerHTML = `<div class="a3s">
      <div>top</div>
      <blockquote><div>quoted</div></blockquote>
      <div style="display:none">hidden</div>
      <pgp-tools-banner data-pgp-tools-ui="">ours</pgp-tools-banner>
    </div>`;
    const body = document.querySelector<HTMLElement>(".a3s");
    if (!body) throw new Error("no body");
    expect(messageText(body).replace(/\s+/g, " ").trim()).toBe("top quoted");
  });
});

describe("attachments", () => {
  const loc = { origin: "https://mail.google.com" };

  // jsdom has File but neither DataTransfer nor DragEvent; the minimum
  // of each that Gmail's drop handler would read.
  beforeEach(() => {
    class FakeDataTransfer {
      files: File[] = [];
      items = { add: (f: File) => void this.files.push(f) };
    }
    class FakeDragEvent extends Event {
      dataTransfer: FakeDataTransfer | null;
      constructor(
        type: string,
        init: EventInit & { dataTransfer?: FakeDataTransfer },
      ) {
        super(type, init);
        this.dataTransfer = init.dataTransfer ?? null;
      }
    }
    Object.assign(window, {
      DataTransfer: FakeDataTransfer,
      DragEvent: FakeDragEvent,
    });
  });
  const url =
    "https://mail.google.com/mail/u/0/?ui=2&ik=abc&attid=0.1&view=att&disp=safe";

  it("parses Gmail's download_url, name with colons included", () => {
    expect(
      parseDownloadUrl(`application/octet-stream:report.pdf.gpg:${url}`, loc),
    ).toEqual({
      name: "report.pdf.gpg",
      url: new URL(url),
    });
    expect(
      parseDownloadUrl(`text/plain:notes: final.asc:${url}`, loc)?.name,
    ).toBe("notes: final.asc");
  });

  it("refuses another origin, a path outside /mail/, and junk", () => {
    expect(
      parseDownloadUrl("a/b:x.gpg:https://evil.example/mail/?attid=1", loc),
    ).toBeNull();
    expect(
      parseDownloadUrl("a/b:x.gpg:https://mail.google.com/other/?attid=1", loc),
    ).toBeNull();
    expect(parseDownloadUrl("a/b:x.gpg:not a url", loc)).toBeNull();
    expect(parseDownloadUrl("", loc)).toBeNull();
    expect(parseDownloadUrl(`a/b::${url}`, loc)).toBeNull();
  });

  it("finds encrypted chips in messages, not in editors or plain files", () => {
    document.body.innerHTML = `
      <div class="aQH">
        <span class="aZo" download_url="application/octet-stream:secret.txt.gpg:${url}"></span>
        <span class="aZo" download_url="application/pdf:plain.pdf:${url}"></span>
        <span class="aZo" download_url="text/plain:key.asc:${url}"></span>
      </div>
      <div contenteditable="true">
        <span download_url="application/octet-stream:draft.gpg:${url}"></span>
      </div>`;
    const chips = encryptedAttachmentChips(document, loc);
    expect(chips.map((c) => c.name)).toEqual(["secret.txt.gpg", "key.asc"]);
  });

  it("drops files on a compose body as one DragEvent carrying them all", () => {
    document.body.innerHTML = `<div contenteditable="true" g_editable="true"></div>`;
    const body = document.querySelector<HTMLElement>("[g_editable]");
    if (!body) throw new Error("no body");
    const seen: string[][] = [];
    body.addEventListener("drop", (e) => {
      seen.push([...(e.dataTransfer?.files ?? [])].map((f) => f.name));
    });
    const ok = dropFiles(
      body,
      [
        { name: "a.gpg", bytes: new Uint8Array([0xc1, 1, 2, 3]) },
        { name: "b.gpg", bytes: new Uint8Array([0xc1, 4, 5, 6]) },
      ],
      () => true,
    );
    expect(ok).toBe(true);
    expect(seen).toEqual([["a.gpg", "b.gpg"]]);
  });

  it("drops nothing when any file fails the check, or the body is gone", () => {
    document.body.innerHTML = `<div contenteditable="true" g_editable="true"></div>`;
    const body = document.querySelector<HTMLElement>("[g_editable]");
    if (!body) throw new Error("no body");
    let drops = 0;
    body.addEventListener("drop", () => drops++);
    expect(
      dropFiles(
        body,
        [
          { name: "a.gpg", bytes: new Uint8Array([0xc1]) },
          { name: "b.txt", bytes: new Uint8Array([0x41]) },
        ],
        (b) => b[0] === 0xc1,
      ),
    ).toBe(false);
    expect(drops).toBe(0);
    body.remove();
    expect(
      dropFiles(
        body,
        [{ name: "a.gpg", bytes: new Uint8Array([0xc1]) }],
        () => true,
      ),
    ).toBe(false);
    expect(dropFiles(document.body, [], () => true)).toBe(false);
  });

  it("samples the message's text colour and nearest opaque background", () => {
    document.body.innerHTML = `
      <div style="background-color: rgb(17, 17, 17)">
        <div style="background-color: transparent">
          <div class="a3s" style="color: rgb(227, 227, 227)"></div>
        </div>
      </div>`;
    const body = document.querySelector<HTMLElement>(".a3s");
    if (!body) throw new Error("no body");
    expect(sampleTheme(body, window)).toEqual({
      color: "rgb(227, 227, 227)",
      background: "rgb(17, 17, 17)",
    });
  });
});
