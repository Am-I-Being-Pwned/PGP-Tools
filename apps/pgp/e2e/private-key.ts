// Throwaway OpenPGP private key + a message encrypted to it, plus a
// distinctive base64 slice of the SECRET material. Test-only, never real.
// Regenerate: see e2e/README.md.

export const PRIVATE_KEY_FIXTURE = {
  name: "Heap Test",
  privateKey:
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlFgEakqSthYJKwYBBAHaRw8BAQdA228hopdMeBCGbKpqraP9LHRaWpCAldBHkvXY\nWsKVC4UAAQCdTxcz+DQHhp2Ttlv8bxGDgAqvxPoZYP3sHw/2zwMuDQ66tBtIZWFw\nIFRlc3QgPGhlYXBAdGVzdC5sb2NhbD6ImQQTFgoAQRYhBL/d7XolEhbRIdxIQZ3s\n0h/ZhwFeBQJqSpK2AhsDBQkB4TOABQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEJ3s0h/ZhwFemE0BAL4a/aHGjafVT7UfgS0EvKVwbcpnmYtt7Qkks9XaegT8\nAP9QVtdqWOTyfLPVHCQCJFjGsT5tPu2uuN6MjcuH+JDfAZxdBGpKkrYSCisGAQQB\nl1UBBQEBB0By+YTBTNrIOQ0WO4NAIOQ6rD1Vd3s+VOWMewAkd0sCRAMBCAcAAP9H\nMtlSvyKIwJDFeCFxwTQWMjsIkxHHydklZdI0LN6FwA+XiHgEGBYKACAWIQS/3e16\nJRIW0SHcSEGd7NIf2YcBXgUCakqStgIbDAAKCRCd7NIf2YcBXnDlAP0SbS2728gd\nuyGYUiml0BA1xqituTrdMvb7FJRPdCF1rwD9Hxzz5xtEFB4PSnMYnWPv+kuQBDZL\nhii42RwELYg2Hwc=\n=ZbZ1\n-----END PGP PRIVATE KEY BLOCK-----\n",
  /** A 44-char base64 slice of the SECRET key material (unique). */
  secretNeedle: "AP9QVtdqWOTyfLPVHCQCJFjGsT5tPu2uuN6MjcuH+JDf",
  /** A message encrypted to this key -- exercises the decrypt path. */
  encryptedMessage:
    "-----BEGIN PGP MESSAGE-----\n\nhF4DnDIELISr3AUSAQdAvT8ts7kTXmgvivPQRngGUECyEWTbf9Er6M6IUGQLWjww\nAWV/u+cVwLoMLi+3Z7NjGscvTEPbtK7ca1g0SBYWOQ4p+i44huNZn/3T9OKh1Jrx\n1GcBCQIQYXzNmy75kB9QLwSscTaCUR8rLHPNxyk4Rahhu6FH/1S70j7wg57gn0yC\nS1PP1koNcX4JWLuz7pwq/RudtH9OccgYxpJ6NkDjf1IphEsDBD8llW0W7ND2p90L\n13QgNEh9KFAy\n=ocyh\n-----END PGP MESSAGE-----\n",
  decryptedPlaintext: "heap-decrypt-plaintext-sentinel-42",
};
