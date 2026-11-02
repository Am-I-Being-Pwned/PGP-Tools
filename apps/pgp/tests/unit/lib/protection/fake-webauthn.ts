/** TEST-ONLY stand-in for `webauthn-prf.ts`. Imported exclusively from
 *  `*.test.ts` (load it inside `vi.hoisted` so `vi.mock` can see it). */

import { vi } from "vitest";

export function fakeWebauthnPrf() {
  return {
    registerPasskey: vi.fn(),
    authenticateAndGetPrf: vi.fn(),
    generatePrfSalt: vi.fn(),
    generateStoredSecret: vi.fn(),
    isWebAuthnCancel: vi.fn(() => false),
    checkPrfSupport: vi.fn(() => true),
  };
}
