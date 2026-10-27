import { describe, expect, it, vi } from "vitest";

import { isOwnReaderSender } from "./useReaderTabs";

vi.mock("../lib/pgp/wasm", () => ({}));

const ID = "abcdefghijklmnopabcdefghijklmnop";
const READER = `chrome-extension://${ID}/reader.html`;
const NONCE = "n0nce";

describe("isOwnReaderSender", () => {
  it("accepts the reader tab opened for this nonce", () => {
    expect(
      isOwnReaderSender(
        { id: ID, url: `${READER}#${NONCE}` },
        NONCE,
        ID,
        READER,
      ),
    ).toBe(true);
  });

  it.each([
    ["no sender", undefined],
    ["another extension", { id: "z".repeat(32), url: `${READER}#${NONCE}` }],
    [
      "another extension's reader.html",
      {
        id: ID,
        url: `chrome-extension://${"z".repeat(32)}/reader.html#${NONCE}`,
      },
    ],
    [
      "another page of ours",
      { id: ID, url: `chrome-extension://${ID}/sidepanel.html#${NONCE}` },
    ],
    ["the reader for another nonce", { id: ID, url: `${READER}#other` }],
    ["a reader with a query", { id: ID, url: `${READER}?x=1#${NONCE}` }],
    ["a web page", { id: ID, url: `https://example.com/reader.html#${NONCE}` }],
    ["no URL", { id: ID }],
  ])("refuses %s", (_name, sender) => {
    expect(isOwnReaderSender(sender, NONCE, ID, READER)).toBe(false);
  });
});
