/** Split text into individual armored key blocks (public + private). */

const PUBLIC_BLOCK =
  /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g;
const PRIVATE_BLOCK =
  /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g;

function matchAll(text: string, re: RegExp): string[] {
  // Fresh lastIndex per call -- the module-level regexes are /g/.
  re.lastIndex = 0;
  const blocks: string[] = [];
  let match;
  while ((match = re.exec(text)) !== null) {
    blocks.push(match[0]);
  }
  return blocks;
}

/** Every armored public-key block in `text`, in order. */
export function splitPublicKeyBlocks(text: string): string[] {
  return matchAll(text, PUBLIC_BLOCK);
}

/** Every armored private-key block in `text`, in order. */
export function splitPrivateKeyBlocks(text: string): string[] {
  return matchAll(text, PRIVATE_BLOCK);
}

export interface ArmoredKeyBlocks {
  publicKeys: string[];
  privateKeys: string[];
}

/** Split a (possibly mixed) armored dump into public and private key
 *  blocks -- e.g. a "backup all keys" file with several of each. */
export function splitArmoredKeyBlocks(text: string): ArmoredKeyBlocks {
  return {
    publicKeys: splitPublicKeyBlocks(text),
    privateKeys: splitPrivateKeyBlocks(text),
  };
}
