import { describe, expect, it } from "vitest";

import type { ProtectionChoiceState } from "./protection-choice";
import {
  crxProtectionInput,
  protectionInput,
  validateExportPassphrase,
  validatePassword,
  validateProtection,
} from "./protection-choice";

describe("validateExportPassphrase", () => {
  it("holds an export to the same 8-character, must-match bar", () => {
    expect(validateExportPassphrase("1234567", "1234567")).not.toBeNull();
    expect(validateExportPassphrase("12345678", "12345679")).not.toBeNull();
    expect(validateExportPassphrase("12345678", "12345678")).toBeNull();
  });
});

const salt = new ArrayBuffer(32);
const ctx = { reusePasskeyCredentialId: "cred-1", masterSealSalt: salt };

const password = (pw: string, confirm = pw): ProtectionChoiceState => ({
  method: "password",
  password: pw,
  confirmPassword: confirm,
  reusePasskey: true,
});

const passkey = (reusePasskey: boolean): ProtectionChoiceState => ({
  method: "passkey",
  password: "",
  confirmPassword: "",
  reusePasskey,
});

describe("validateProtection", () => {
  it("rejects a password under 8 characters", () => {
    expect(validateProtection(password("1234567"))).toBe(
      validatePassword("1234567", "1234567"),
    );
    expect(validateProtection(password("1234567"))).not.toBeNull();
  });

  it("rejects a mismatched confirmation", () => {
    expect(
      validateProtection(password("long enough", "long enougH")),
    ).not.toBeNull();
  });

  it("accepts a matching password of 8+", () => {
    expect(validateProtection(password("12345678"))).toBeNull();
  });

  it("never validates a password the passkey path ignores", () => {
    expect(validateProtection({ ...passkey(true), password: "x" })).toBeNull();
  });
});

describe("protectionInput", () => {
  it("password: just the password, plus any cache flag", () => {
    expect(protectionInput(password("hunter22"), ctx)).toEqual({
      method: "password",
      password: "hunter22",
    });
    expect(protectionInput(password("hunter22"), ctx, { cache: true })).toEqual(
      { method: "password", password: "hunter22", cache: true },
    );
  });

  it("reused passkey: the vault credential AND the master seal salt", () => {
    expect(protectionInput(passkey(true), ctx)).toEqual({
      method: "passkey",
      reusePasskeyCredentialId: "cred-1",
      prfSalt: salt,
    });
  });

  it("fresh passkey: neither the credential nor the master salt", () => {
    expect(protectionInput(passkey(false), ctx)).toEqual({
      method: "passkey",
      reusePasskeyCredentialId: undefined,
      prfSalt: undefined,
    });
  });
});

describe("crxProtectionInput", () => {
  it("never carries the master seal salt", () => {
    expect(crxProtectionInput(passkey(true), ctx)).toEqual({
      method: "passkey",
      reusePasskeyCredentialId: "cred-1",
    });
    expect(crxProtectionInput(password("hunter22"), ctx)).toEqual({
      method: "password",
      password: "hunter22",
    });
  });
});
