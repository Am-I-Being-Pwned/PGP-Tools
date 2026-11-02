/** WebAuthn PRF extension: augments the built-in interfaces with `prf`. */

interface AuthenticationExtensionsClientInputsPRF {
  prf?: {
    eval?: {
      first: BufferSource;
      second?: BufferSource;
    };
  };
}

interface AuthenticationExtensionsClientOutputsPRF {
  prf?: {
    enabled?: boolean;
    results?: {
      first?: ArrayBuffer;
      second?: ArrayBuffer;
    };
  };
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type -- augmenting global types requires empty interface extension
  interface AuthenticationExtensionsClientInputs extends AuthenticationExtensionsClientInputsPRF {}
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type -- augmenting global types requires empty interface extension
  interface AuthenticationExtensionsClientOutputs extends AuthenticationExtensionsClientOutputsPRF {}
}

export {};
