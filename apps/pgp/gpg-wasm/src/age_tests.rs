use super::*;

// Throwaway `ssh-keygen` fixtures, no user key material (SECURITY.md).
// `AGE_CLI_*` were produced by Go `age` v1.2.1 against these keys: the
// cross-tool vectors. At column 0 on purpose: indenting would indent the
// raw-string PEM/armor bodies, which base64 rejects.

const ED25519_PUB: &str = r#"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu/03Nd9eyyrPgxjkFu80Fe1EgN06J8iaY8B+wf6 alice@example.com"#;

const ED25519_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAC8B7v9NzXfXssqz4MY5BbvNBXtRIDdOifImmPAfsH+gAAAJhBxc2tQcXN
rQAAAAtzc2gtZWQyNTUxOQAAACAC8B7v9NzXfXssqz4MY5BbvNBXtRIDdOifImmPAfsH+g
AAAEBA0hh8yBNIqqCUtk4PA5Ii53GhHm7T0f3kb7lSUXGdmwLwHu/03Nd9eyyrPgxjkFu8
0Fe1EgN06J8iaY8B+wf6AAAAEWFsaWNlQGV4YW1wbGUuY29tAQIDBA==
-----END OPENSSH PRIVATE KEY-----
"#;

const ED25519_ENC_PUB: &str = r#"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeO7+ppZ3dvenXFmkPhdLIxEbLSjyhJSqzvIJtkjZkn locked@example.com"#;

const ED25519_ENC_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCtWLauzz
7ngEmNII8YuGr4AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIGeO7+ppZ3dvenXF
mkPhdLIxEbLSjyhJSqzvIJtkjZknAAAAoCGjE3xIijl7N3+0XOzTHatjES/fA8iJhgNIEI
//CFVhY3xEIVh4ISkcXo9cqEnsjCSe0vgKHJlaFkGpvi1MAQtz0cdpMEfGO0/eUoRVO/nE
n/aDJtlfKlQPWSM6SLo96YvenNPECVl/PbFjKrkn3gw8nyobBZpBiFQiGA1l2+19gLsHRC
50mZlrCmTJrYsrAx271bxrLyZbxInFXOmQxmw=
-----END OPENSSH PRIVATE KEY-----
"#;

const RSA2048_PUB: &str = r#"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDnv+3cHn+ucJO/00PQE0tYGhxeW2VTRCPfHpq2sLZov+IckUE/TONFqsHFVYQLGpB3i3YnyhYefy06kOvxuwhSL8B56e//J/xneCQxbbISt+ypQXn8CdWD4MNhkMmQXx10/Ss8L4JfZm3Po1/F50a32W/XTtp/1vXQ+MKbEqFs5R2oX1ahRtiPo3Z369k/V1JA9QoN3IIz5qZg+a00X6IzA6FhxndVxktX+Qps+7oJ65dwqAAV08gADypK+IWKeVvAYZub7Vzd3y0R2Jt8sm2FnqHVh4TonGxTX/Q6XExPfI5F/cer+3VbIrdF6BhQV88xC4M5/EFv8U+ghUSrFBUD rsa2048@example.com"#;

const RSA2048_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA57/t3B5/rnCTv9ND0BNLWBocXltlU0Qj3x6atrC2aL/iHJFBP0zj
RarBxVWECxqQd4t2J8oWHn8tOpDr8bsIUi/Aeenv/yf8Z3gkMW2yErfsqUF5/AnVg+DDYZ
DJkF8ddP0rPC+CX2Ztz6NfxedGt9lv107af9b10PjCmxKhbOUdqF9WoUbYj6N2d+vZP1dS
QPUKDdyCM+amYPmtNF+iMwOhYcZ3VcZLV/kKbPu6CeuXcKgAFdPIAA8qSviFinlbwGGbm+
1c3d8tEdibfLJthZ6h1YeE6JxsU1/0OlxMT3yORf3Hq/t1WyK3RegYUFfPMQuDOfxBb/FP
oIVEqxQVAwAAA9Ck6biwpOm4sAAAAAdzc2gtcnNhAAABAQDnv+3cHn+ucJO/00PQE0tYGh
xeW2VTRCPfHpq2sLZov+IckUE/TONFqsHFVYQLGpB3i3YnyhYefy06kOvxuwhSL8B56e//
J/xneCQxbbISt+ypQXn8CdWD4MNhkMmQXx10/Ss8L4JfZm3Po1/F50a32W/XTtp/1vXQ+M
KbEqFs5R2oX1ahRtiPo3Z369k/V1JA9QoN3IIz5qZg+a00X6IzA6FhxndVxktX+Qps+7oJ
65dwqAAV08gADypK+IWKeVvAYZub7Vzd3y0R2Jt8sm2FnqHVh4TonGxTX/Q6XExPfI5F/c
er+3VbIrdF6BhQV88xC4M5/EFv8U+ghUSrFBUDAAAAAwEAAQAAAQALoH12hbEyN0OyZA8K
6WzmRqkVstAqlUiXcRmiAMumBbp6ZG85lcnxPNfr5pZxWCvXU4/h/ymM7iR+w7aSsieAuB
SYCTyZOJBZQJXQRQiiF8gv1bEhC/1CWIx04Ka8L4lyzSDWLCwGTUVFHZU4gJnzr10FGFeu
AkLi8RgSX6TpqZyVwNRGemBTFM1SvMeXhuopkHtgkgiBd+0i1XajwKe7E9IobhKm3cweW/
yzN5imCBIif13MVmC7wC/C+RZRvVBcR8FEHiU/MUGVNLJV8XCKSAEISkVA+BM0p5ISe0zb
hWwz2E/hCrLkVzjbP0eCQbkq1OB4anOBho1i8v1IgY0BAAAAgQCU+kuDtprnuZ2SDouB23
ppzTlFFhzAq+8h9ihyz9mqS+eurscdUZQNW9s0nnUlBfdogvR05szcSI1PWvvZPUlT8eS6
r+1sNU2MSV3nHLcr+6zQputNCJCtTNz9XgUkGa70Fa50QcnFDaFjovLPC8wMGSX6JUZDke
UFddQYjh7utAAAAIEA/UPPnngid+bLJY8KUPrc+yZBP1OglZNQdLuyLeYF1Rc7a0c2R0CT
hZoQtVk74bMnFKjKcEP2Lm57haV+6UMHW7Jc0wnDjMjg0qAwVTzDSN+3b75X1NgNI2GF+X
UfrB0PtvBXBJj4NhFIhWn1KKtmdhpin2NdRdrU9u6HjiFMdTMAAACBAOpAot7VKNS2JiS4
wZWipc9H90zTWb0ENmFkTF2Ti1wUB/Wd+JcYRxhCkiNPNeO8PVW76f8GfAmFDDToDmBDbN
qO8apfIjtsT+OYaMb6gGPkJdj/QpCrPV0hmK1f6dXbC7HdFfdKP1wD7Rlf/K/96tpKgqNF
Q7z8WNmDPxit/0DxAAAAE3JzYTIwNDhAZXhhbXBsZS5jb20BAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
"#;

const RSA8192_PUB: &str = r#"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAEAQC9Q8nqf3udu4FfIXanMNbEDX1NwEZSYSsAO1ky69uvyIDx4pxptNh14B7bylmP4icgw9+zJBL8QWC0CjclzPD6cM9I+kJfmZwX6zjaftcg3VnUq/E/sMg6PIuKDcAFdv0Qym92THeYyC/lfvIfSun03/k7byJmop/jn1LjjHAyw8L4/pshY61zDY1mNeuJGBoYWljSUg0GdUoFqDwP6x+U8XsWcf0KoueY1VaFgZJUzTofSF09pqoGo1Z8vpSkWLWk5GopTjrSEyCgl0aa8gVUu+Wfzc3i4Z3HIQaEt0s7ihFxMc3gwq876NkYfDR08BYuRKqtEEGO48iqv+ebwFCNxvKHnXHAmQPmPRfTPg7shj4fS/rTu0RXCe9teXqJTBSxRGQLoXqPfzoQyWh6t8yrJTOYccz2n6IhsxyZzjOPetNr5SAiP2NWraGDY/g3x31hprutRFyyyxSYqZ8VlTEFhQDLXR41kMowpC1gN0uRpTkJJqP2FJHOmVzxARscz5vlLo192PHUIyKjqFq2+InEzsMynpm3HsrRlEish+OegVUw+Hf+vEn/cY3Q8ggp59YV8trJhgYzsOQ4Oft/ANikkDcDZ4jSOiickr2c6PuAKcFKOsXw1UrEUGY0NWNBUFunoW65WX2z8OHNZt3H46v8MQDPuZABaLRbJXUbBOMSh6LO1RPWwy6P9VWSjfww+QGPuTaEdHen/ZV+e+bH81Z9KaCRLjEjmDJO9zOdJpYPUG/Z2dDVpFgtmveOKAWyR7PyjpBPGWKBh9lWyGXl8HmeiRY4hZjYJIlz1lYXpQF3uhf/nemUXJj2wtmtWhA5kEW9EDOAV0V9Sgsbl99Aax05MuMhdhyAmZVEVNIpq7xEBChg9SeWzY+nAi6MaHlvpiWvsi35ExU0NhAF0a1EYLeLGBqdBcXuBtvRPhD/LCcaVClW5LhSs/tbE4yUwLQV2RIeGnzfci0KELYz/M99zngFeYKWqsOkeUXSXnvfMWTmDQSiz70v8ABUpq5PRrmUYxFrDj5PHgnl0DSCsq3LZPBBjL1FE/PBTqAQKHzmTpPC78gPGtrpTy50FTEr7Ae7atLWFPxaqb12QRobd1QFEQlSk9wxs7F2/tB4nZitpdUhBwesiQsDKCC0N+ElQ8zGGSPS32AvdjkbzaNOEOB88S4RQDXxw2R2DEOF7KOoIzia5fOPicQ3MKB+Sl1lJxcnWNtb9brBFbWxZ8hRFDm3Z9nF8EbIeboaPYwUCWubJAaBSwZttQ11ihNRuy/BqwUlm1ufysY8J+RUtYRKrPcRLduTfVsj6snXhAlICzuPOD4MYpO2NVAu5j7oAp3AExMD0ZYeuNBrvAcZ0zNwfVCqi+B/ big@example.com"#;

const RSA1024_PUB: &str = r#"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDCOIDWGtVE2bL6yKiVH46XzplUvBSCspML0eLD/kToDNynqvFRrzW6rf19OQiGUMHx4hnMUaZCwDTqjfJXS4fcyuYXIwKDvEFai+eVEd/Na1dKvsgG58MtgXfM8Tdt6Ejj2+FB38M9nyo54cOlFpFfqbBPOo+No2olWUWwYyGWvQ== small@example.com"#;

const ECDSA_PUB: &str = r#"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFRxtTsrSw6vTVnE9RgMN1VMqJzBlbyBWQxPweR0PLRkVzWr9FM+2E22fT7hr7own7h0LasVdFaIdukOlrSjxno= ec@example.com"#;

const ECDSA_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRUcbU7K0sOr01ZxPUYDDdVTKicwZW8
gVkMT8HkdDy0ZFc1q/RTPthNtn0+4a+6MJ+4dC2rFXRWiHbpDpa0o8Z6AAAAqDpL/cc6S/
3HAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFRxtTsrSw6vTVnE
9RgMN1VMqJzBlbyBWQxPweR0PLRkVzWr9FM+2E22fT7hr7own7h0LasVdFaIdukOlrSjxn
oAAAAgLB02fxE9kSi5R8PhdHkDdotN/xtoV0hJwYj256f6ZM0AAAAOZWNAZXhhbXBsZS5j
b20BAg==
-----END OPENSSH PRIVATE KEY-----
"#;

const DSA_PUB: &str = r#"ssh-dss AAAAB3NzaC1kc3MAAACBAMm0XxWiDbnff0Uvw4EXSUyfoNx7WVeE5T6EY/w/J62+WTAm3CU1Q+SYsL8KETpvYnzpB39Gj5Yjg01OKks6EJb9c8d77fWKzFyLgr28AZkJQONKMduGaqFv/NIsOZ1pOsLmWR1GF6sEfm4cLPZWkzHFAtAgubrdh2i2kmDyvdgvAAAAFQCLOxknNGsc6bvIZCjbN6beWdO4HQAAAIBc2xFps/hl8j+D2fcJWeVubgmTwL7dUMGgopt440/vZ5ILTxKYKjyLOO46Hxi+9+p0nCBJE14o8W27OfdT/PElEe/MGAiAIeRczSntletPZoq4A23PvTeZ3OKWrMAVKQ8V5USL5P7/utc1ewf1zUkGBFJiXjFa4nWAaTwjnTXV4QAAAIBwo4s3sJygq4dbbfUGs1Md+Tpfc+IWbnQsmK+tekpcthQYuy1AWWOmoBRcYZotUO4gGf96fNgEhOGmShvTvhi8vvOYV+Or6ThipCcnTNOfIfX+L5g31KNbgWcxPKGuwczwz7SciLDHdk9TbB105mGONoBi7XJ7fN+ztsBOfzPpfw== dsa@example.com"#;

const AGE_CLI_CT_ED25519_BIN_B64: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IGhmQmNYZyBvOTZlVS9jb2JnYmV2ditUbHp1RzBNUzk4ZkxOLzhlc2kxdlB0NE42U0dNCmlqekpLanlSQkdxblVKNXNISzFudFpRNnBaTjBWYnIzbktzRlNCZ1dvemsKLS0tIDZDNXl6MVVsd3BsdmdVWVkvdHR6bUhnNWl2VGdZTjRlMCtubTQ4dE9xNFEKqsusD2Cq0riaThWmqcSVPsqulFMLFOrg090FE3FWyWsxzKFTL6GXZSnbA/uyRoQOU1X08C7DaEcOryIeV9I8IGrMbQczBrebdQ==";

const AGE_CLI_CT_ED25519_ARMOR: &str = r#"-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IGhmQmNYZyBoVy93
ZzNaMWh4YStoNit3anZHNyt4dkJoY0cvT2NSNlpDcCthYnVjc2trCndnOFNtVDB1
M09MU2FRRDhvVzREMHlIYjNIVGRJR3Z0c0pPWllFWkNvcjQKLS0tIGwxck5mREtQ
OXVHajVWekE3THhwUjgxd1JRR1pCWFlmd2pZREpXQjViQ3MK3UU4CERxpbCdDn+S
dqdcLi2MKP22Y91oE1McMZNqqj3wRKAKZfKKFIVw5FFW9hklG0bqp+SLBw9H2tON
ZgPuQPJAPk5hS/wQ1A==
-----END AGE ENCRYPTED FILE-----
"#;

const AGE_CLI_CT_RSA_BIN_B64: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1yc2EgN1RaWFlBCjJqWUVZY3pWeDhWM2ZIUTcvakVISTRMY08vaUR2ZEpHS3dJOWw5Uzd5cWRyR2FQSERpRGd2MWVmN2V3SG5RTDEKcHNxTXVSUEg1T3ZhQWJZUVc1QkE1bTdqNmJLcFVkZVFNRXFKeWJPK2ZOVTBLL3ZZSnZJZHNUYzJFUUprWEU2LwpLRGRnREVENFJ1R2RCZ2hFbDIwb0RhcWE5WjU3RTltQ1BkWDdmTTlkK2pHaDg2aTRtWEdjV2hvTk81ZjMzZnZqCjBadFRCeHdlUFplNll6UW9wUkR1Z3lKNHNQdEVEWEg3TG05Y05MYzgzeWc2bUhpSm0wdGM1VENtM0tnaC9ydUwKWDNHaHpOMG5kY0JUcERvL3hXRFpsbWlZQ1ZabkZtcTJTNkpqak1mUWRRa1I4ck9LOTRDOTl6bHdVVU5yRW0rYwpJV3RhRnBjMUJUN1d1d2lMZXM3N2x3Ci0tLSBNc0RoL1VYN0hkUGNEek5pa1ljMkptdzBKOGdTOWNybEkwWWtpVys0RmZFChettURTnJECyNIDyVvxXrUMMhyUrGR6YjSR0zjAZNTQnxISRLg9/gRehDuNYBEuJ4zt8YssAWN9Ic6Qnzfz4EXDMuTHDDRl/c8=";

const AGE_CLI_CT_RSA_ARMOR: &str = r#"-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1yc2EgN1RaWFlBClB0NXNFU0dz
MDVtNzRwZ0E5Rm1JNnFlMjU1SzBGUHVTMlhMaFRXcmJGaStYMExjdHJTQllPYUpQ
OExpV3l2Y3kKa2R3R2RaLzA0eWNIendab1lwVkRicGxVaFdqTllRM2UyL1hGWFlN
KzBMY2lQMEFlZ3VGWC9UT2YxZHFvODJjVwpVZnIvMWJyU21IWm9hZXBuaXg3c1dX
dFNNWC9KNkNKbHU4bnFqQUhlU3BUcDM3citzYUdQUktaeTg4YUJUQnZtCitzMWRU
VWtuck8rVW5JeEtRYkxCNm4zZTlhZVpzZjlhMDdMeXhMSnNXdlR3bUtVZEJSaHVP
Q0tQV3VPVHI3Rm0KbHE4bmFkQThjZlgvdGlBRUl5Zm11YUtpQ0FjMmFadkp0NlRn
UmgvT0cxdks0WGNpUUxWWklwbkpXcGRnNkgvbAptWWd0Vmdhc3JidjVyVml1MTR3
MnhRCi0tLSAwU1Mra0tUQzViTWxJbERJTTdtM2lvTE5aQkNaOEhpazluZ1MwU0lD
ZUZrCvPvnre8VsB2Zkcbq5QR6o4edRYz+RCsF3FG1UuE/VEvAziYUUVoA/f8FQmj
0zGLdm+nRYnTwmiH8MG7/IT6chudVNBuTiN0dbM=
-----END AGE ENCRYPTED FILE-----
"#;

const ENC_KEY_PASSPHRASE: &[u8] = b"correct horse battery staple";
const PLAINTEXT: &[u8] = b"cross-tool vector: hello from the age CLI";
/// Hand-assembled: a real one needs a hardware token, and the rejection
/// depends only on the type string.
const FIDO_PUB: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAAAABHNzaDo= fido@example.com";

// Weak on purpose: tests the plumbing, not the cost.
const TEST_MEM_KIB: u32 = 64;
const TEST_ITERS: u32 = 1;
const TEST_PAR: u32 = 1;

// Hard-coded `ssh-keygen -lf` output, so a change in how we hash is caught.
const ED25519_FPR: &str = "SHA256:hfBcXl2f8ULI3/KX9lgL1e+zsWQSQc75zL8naYRM1rY";
const ED25519_ENC_FPR: &str = "SHA256:yOrpBFC84MjVC8NpQZB2mAmivzrwfVrRynXtzWzq/s0";
const RSA2048_FPR: &str = "SHA256:7TZXYGCK6AyEBeqIG4ReYtoGyg7fYPbnQIe1icaOsO0";

fn unpack(packed: &[u8]) -> (serde_json::Value, Vec<u8>) {
    let json_len =
        u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
    let meta: serde_json::Value =
        serde_json::from_slice(&packed[4..4 + json_len]).unwrap();
    (meta, packed[4 + json_len..].to_vec())
}

/// Import under a password and unlock again -- the full at-rest path.
fn protect_and_unlock(key_file: &str, source_passphrase: &[u8]) -> (u32, serde_json::Value) {
    let packed = protect_ssh_identity_with_password(
        key_file.as_bytes().to_vec(),
        source_passphrase.to_vec(),
        b"vault password".to_vec(),
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
    .unwrap();
    let (meta, blob) = unpack(&packed);
    let fpr = meta["fingerprint"].as_str().unwrap().to_string();
    let handle = unlock_ssh_identity_with_password(
        &blob[28..],
        &blob[16..28],
        &blob[..16],
        &fpr,
        b"vault password".to_vec(),
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
    .unwrap();
    (handle, meta)
}

fn recipients_json(lines: &[&str]) -> String {
    serde_json::to_string(lines).unwrap()
}

// ── Public parsing ──────────────────────────────────────────────

#[test]
fn parses_an_ed25519_public_key_line() {
    let json: serde_json::Value =
        serde_json::from_str(&parse_ssh_recipient(ED25519_PUB).unwrap()).unwrap();
    assert_eq!(json["algorithm"], "ssh-ed25519");
    assert_eq!(json["fingerprint"], ED25519_FPR);
    assert_eq!(json["comment"], "alice@example.com");
    // Canonical recipient: type + base64, comment stripped.
    assert_eq!(
        json["recipient"].as_str().unwrap(),
        ED25519_PUB.rsplit_once(' ').unwrap().0
    );
}

#[test]
fn parses_an_rsa_public_key_line() {
    let json: serde_json::Value =
        serde_json::from_str(&parse_ssh_recipient(RSA2048_PUB).unwrap()).unwrap();
    assert_eq!(json["algorithm"], "ssh-rsa");
    assert_eq!(json["fingerprint"], RSA2048_FPR);
    assert_eq!(json["comment"], "rsa2048@example.com");
}

#[test]
fn keeps_a_multi_word_comment_intact() {
    let two_token = ED25519_PUB.rsplit_once(' ').unwrap().0;
    let json: serde_json::Value =
        serde_json::from_str(&parse_ssh_recipient(&format!("{two_token} work laptop")).unwrap())
            .unwrap();
    assert_eq!(json["comment"], "work laptop");
}

#[test]
fn a_key_line_with_no_comment_parses() {
    let two_token = ED25519_PUB.rsplit_once(' ').unwrap().0;
    let json: serde_json::Value =
        serde_json::from_str(&parse_ssh_recipient(two_token).unwrap()).unwrap();
    assert_eq!(json["comment"], "");
}

#[test]
fn strips_invisible_and_control_characters_from_a_comment() {
    // Bidi / zero-width / variation selectors would spoof the name.
    let two_token = ED25519_PUB.rsplit_once(' ').unwrap().0;
    for hidden in [
        "\u{202e}", "\u{200b}", "\u{200d}", "\u{2066}", "\u{fe0f}", "\u{feff}", "\u{00ad}",
        "\u{3164}", "\u{e0041}", "\u{0007}", "\u{2800}", "\u{1d159}",
    ] {
        let line = format!("{two_token} alice@corp{hidden}.com");
        let json: serde_json::Value =
            serde_json::from_str(&parse_ssh_recipient(&line).unwrap()).unwrap();
        assert_eq!(json["comment"], "alice@corp.com", "{hidden:?}");
    }
}

#[test]
fn caps_the_length_of_a_comment() {
    let two_token = ED25519_PUB.rsplit_once(' ').unwrap().0;
    let json: serde_json::Value = serde_json::from_str(
        &parse_ssh_recipient(&format!("{two_token} {}", "a".repeat(5000))).unwrap(),
    )
    .unwrap();
    let comment = json["comment"].as_str().unwrap();
    assert_eq!(comment.chars().count(), SSH_COMMENT_MAX + 1);
    assert!(comment.ends_with('…'));
}

#[test]
fn rejects_a_line_whose_label_and_blob_disagree() {
    // The blob is authoritative; disagreement must not be resolved silently.
    let b64 = ED25519_PUB.split(' ').nth(1).unwrap();
    let err = parse_ssh_recipient(&format!("ssh-rsa {b64}")).unwrap_err();
    assert!(err.contains("inconsistent"), "{err}");
}

// ── Rejection paths (exact user-facing messages) ────────────────

#[test]
fn rejects_ecdsa_public_key() {
    assert_eq!(parse_ssh_recipient(ECDSA_PUB).unwrap_err(), MSG_ECDSA);
}

#[test]
fn rejects_ecdsa_private_key_without_asking_for_a_passphrase() {
    let err = protect_ssh_identity_with_password(
        ECDSA_KEY.as_bytes().to_vec(),
        vec![],
        b"pw".to_vec(),
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
    .unwrap_err();
    assert_eq!(err, MSG_ECDSA);
}

#[test]
fn rejects_fido_public_key() {
    assert_eq!(parse_ssh_recipient(FIDO_PUB).unwrap_err(), MSG_FIDO);
    // FIDO has no encryption operation: a retry hint would be a dead end.
    assert!(!MSG_FIDO.to_lowercase().contains("passphrase"));
}

#[test]
fn rejects_dsa_public_key() {
    assert_eq!(parse_ssh_recipient(DSA_PUB).unwrap_err(), MSG_DSA);
}

#[test]
fn rejects_rsa_below_2048_bits_and_names_the_size() {
    assert_eq!(
        parse_ssh_recipient(RSA1024_PUB).unwrap_err(),
        "This RSA key is only 1024 bits. age requires at least 2048 bits."
    );
}

#[test]
fn rejects_rsa_above_4096_bits_and_explains_the_divergence() {
    let err = parse_ssh_recipient(RSA8192_PUB).unwrap_err();
    assert_eq!(
        err,
        "This RSA key is 8192 bits; we support up to 4096. Note the age CLI accepts larger keys, so a file encrypted elsewhere to this key may not decrypt here."
    );
    assert!(!err.contains("invalid"));
}

#[test]
fn rejects_encrypted_legacy_pem() {
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,5C905C47022DDA74BFF7C7EA3D38DD86\n\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n";
    let err = protect_ssh_identity_with_password(
        pem.as_bytes().to_vec(),
        vec![],
        b"pw".to_vec(),
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
    .unwrap_err();
    assert_eq!(err, MSG_LEGACY_PEM);
}

#[test]
fn rejects_pkcs8() {
    for pem in [
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n",
    ] {
        let err = protect_ssh_identity_with_password(
            pem.as_bytes().to_vec(),
            vec![],
            b"pw".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap_err();
        assert_eq!(err, MSG_PKCS8);
    }
}

#[test]
fn rejects_putty_ppk() {
    let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: k\n";
    let err = protect_ssh_identity_with_password(
        ppk.as_bytes().to_vec(),
        vec![],
        b"pw".to_vec(),
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
    .unwrap_err();
    assert_eq!(err, MSG_PPK);
}

/// The import preview names these formats up front, no passphrase asked.
#[test]
fn names_foreign_private_key_formats_without_a_passphrase() {
    for (file, expected) in [
        (
            "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n",
            Some(MSG_PPK),
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n",
            Some(MSG_LEGACY_PEM),
        ),
        (
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
            Some(MSG_PKCS8),
        ),
        (
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n",
            Some(MSG_PKCS8),
        ),
        // Formats owned by other paths must not be claimed here.
        (ED25519_KEY, None),
        ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n", None),
        ("-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n", None),
    ] {
        let json = ssh_private_key_format_rejection(file.as_bytes().to_vec()).unwrap();
        assert_eq!(
            serde_json::from_str::<Option<String>>(&json).unwrap(),
            expected.map(str::to_string),
            "{file}"
        );
    }
}

/// Non-UTF-8 comes back `null`, not an error, so the caller falls through.
#[test]
fn foreign_format_check_tolerates_binary() {
    let json = ssh_private_key_format_rejection(vec![0xff, 0xfe, 0x00]).unwrap();
    assert_eq!(serde_json::from_str::<Option<String>>(&json).unwrap(), None);
}

// ── Identity selection (which key opens this file) ──────────────

fn selected(ciphertext: &[u8], candidates: &[&str]) -> Option<usize> {
    let json = select_age_decryption_key(ciphertext, &recipients_json(candidates)).unwrap();
    serde_json::from_str(&json).unwrap()
}

/// The tag is public: matching needs no identity, even on Go CLI output.
#[test]
fn selects_the_identity_a_file_is_encrypted_to() {
    let candidates = [RSA2048_PUB, ED25519_PUB];
    for (ct, expected) in [
        (
            B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap(),
            Some(1usize),
        ),
        (AGE_CLI_CT_ED25519_ARMOR.as_bytes().to_vec(), Some(1)),
        (B64.decode(AGE_CLI_CT_RSA_BIN_B64).unwrap(), Some(0)),
        (AGE_CLI_CT_RSA_ARMOR.as_bytes().to_vec(), Some(0)),
    ] {
        assert_eq!(selected(&ct, &candidates), expected);
    }
}

/// The index is into the caller's candidate list, not the file's order.
#[test]
fn selects_from_our_own_ciphertext_in_both_forms() {
    for armor in [false, true] {
        let ct = encrypt_age_to_recipients(
            PLAINTEXT,
            &recipients_json(&[ED25519_PUB]),
            armor,
        )
        .unwrap();
        assert_eq!(selected(&ct, &[RSA2048_PUB, ED25519_PUB]), Some(1));
        assert_eq!(selected(&ct, &[ED25519_PUB, RSA2048_PUB]), Some(0));
    }
}

#[test]
fn selects_nothing_when_no_candidate_is_a_recipient() {
    let ct = B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap();
    assert_eq!(selected(&ct, &[RSA2048_PUB]), None);
    assert_eq!(selected(&ct, &[]), None);
    // Candidates this module refuses outright are skipped, not matched.
    assert_eq!(selected(&ct, &[ECDSA_PUB, DSA_PUB, "not a key"]), None);
}

/// The tag is only four bytes, so the stanza type must agree too.
#[test]
fn selection_requires_the_stanza_type_to_agree() {
    let ct = B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap();
    let stanzas = age_header_stanzas(&ct).unwrap();
    assert_eq!(stanzas.len(), 1);
    assert_eq!(stanzas[0].0, "ssh-ed25519");

    // Spliced at the byte level: the payload after the header is not ASCII.
    let needle = b"-> ssh-ed25519 ";
    let at = ct
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("stanza line");
    let mut forged = ct[..at].to_vec();
    forged.extend_from_slice(b"-> ssh-rsa ");
    forged.extend_from_slice(&ct[at + needle.len()..]);
    assert_eq!(selected(&forged, &[ED25519_PUB]), None);
}

/// Not an age file at all: an error, not a wrong answer.
#[test]
fn selection_rejects_non_age_input() {
    assert!(select_age_decryption_key(b"", &recipients_json(&[ED25519_PUB])).is_err());
    assert!(select_age_decryption_key(
        b"-----BEGIN PGP MESSAGE-----\n",
        &recipients_json(&[ED25519_PUB])
    )
    .is_err());
}

/// Pinned so nobody "simplifies" the tag into a fingerprint prefix.
#[test]
fn stanza_tag_is_not_a_fingerprint_prefix() {
    let blob = B64.decode(ED25519_PUB.split(' ').nth(1).unwrap()).unwrap();
    let tag = age_ssh_tag(&blob);
    assert_eq!(tag.len(), 6);
    // The tag the Go CLI wrote into the captured vector.
    assert!(
        String::from_utf8_lossy(&B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap())
            .contains(&format!("-> ssh-ed25519 {tag} ")),
    );
    let fp = fingerprint(&blob);
    assert_ne!(fp[FINGERPRINT_PREFIX.len()..][..6], tag);
}

// ── Round trips ─────────────────────────────────────────────────

#[test]
fn ed25519_round_trip_binary_and_armored() {
    let (handle, meta) = protect_and_unlock(ED25519_KEY, b"");
    assert_eq!(meta["fingerprint"], ED25519_FPR);
    assert_eq!(meta["algorithm"], "ssh-ed25519");
    assert_eq!(meta["comment"], "alice@example.com");

    for armor in [false, true] {
        let ct =
            encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[ED25519_PUB]), armor)
                .unwrap();
        assert!(is_age_message(&ct));
        assert_eq!(
            ct.starts_with(AGE_ARMOR_BEGIN.as_bytes()),
            armor,
            "armor flag not honoured"
        );
        assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
    }
    drop_ssh_identity(handle).unwrap();
}

#[test]
fn rsa_round_trip_binary_and_armored() {
    let (handle, meta) = protect_and_unlock(RSA2048_KEY, b"");
    assert_eq!(meta["fingerprint"], RSA2048_FPR);
    assert_eq!(meta["algorithm"], "ssh-rsa");

    for armor in [false, true] {
        let ct =
            encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[RSA2048_PUB]), armor)
                .unwrap();
        assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
    }
    drop_ssh_identity(handle).unwrap();
}

#[test]
fn encrypts_to_several_recipients_at_once() {
    let ct = encrypt_age_to_recipients(
        PLAINTEXT,
        &recipients_json(&[ED25519_PUB, RSA2048_PUB]),
        false,
    )
    .unwrap();
    for key in [ED25519_KEY, RSA2048_KEY] {
        let (handle, _) = protect_and_unlock(key, b"");
        assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
        drop_ssh_identity(handle).unwrap();
    }
}

#[test]
fn one_bad_recipient_fails_the_whole_call() {
    // Dropping an unusable recipient would yield a file that isn't shareable.
    let err = encrypt_age_to_recipients(
        PLAINTEXT,
        &recipients_json(&[ED25519_PUB, ECDSA_PUB]),
        false,
    )
    .unwrap_err();
    assert_eq!(err, MSG_ECDSA);
}

// ── Passphrase-protected import (normalize-at-import) ───────────

#[test]
fn passphrase_protected_key_is_normalized_sealed_and_usable() {
    let packed = protect_ssh_identity_with_password(
        ED25519_ENC_KEY.as_bytes().to_vec(),
        ENC_KEY_PASSPHRASE.to_vec(),
        b"vault password".to_vec(),
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
    .unwrap();
    let (meta, blob) = unpack(&packed);
    assert_eq!(meta["fingerprint"], ED25519_ENC_FPR);
    assert_eq!(meta["comment"], "locked@example.com");

    let handle = unlock_ssh_identity_with_password(
        &blob[28..],
        &blob[16..28],
        &blob[..16],
        ED25519_ENC_FPR,
        b"vault password".to_vec(),
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
    .unwrap();

    let ct =
        encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[ED25519_ENC_PUB]), false)
            .unwrap();
    assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
    drop_ssh_identity(handle).unwrap();
}

#[test]
fn the_source_passphrase_is_stripped_not_carried() {
    // Sealed form must be unencrypted OpenSSH (usable without callbacks).
    let normalized =
        normalize_openssh_identity(ED25519_ENC_KEY.as_bytes(), ENC_KEY_PASSPHRASE).unwrap();
    let text = std::str::from_utf8(&normalized.plaintext).unwrap();
    assert!(text.starts_with(OPENSSH_BEGIN));
    assert!(matches!(
        ::age::ssh::Identity::from_buffer(normalized.plaintext.as_slice(), None).unwrap(),
        ::age::ssh::Identity::Unencrypted(_)
    ));
    assert_eq!(normalized.public.fingerprint, ED25519_ENC_FPR);
}

#[test]
fn a_wrong_source_passphrase_is_reported_as_such() {
    let err = normalize_openssh_identity(ED25519_ENC_KEY.as_bytes(), b"nope")
        .err()
        .expect("a wrong passphrase must not import");
    assert_eq!(err, "Wrong passphrase for this SSH key.");
}

#[test]
fn an_encrypted_key_with_no_passphrase_asks_for_one() {
    let err = normalize_openssh_identity(ED25519_ENC_KEY.as_bytes(), b"")
        .err()
        .expect("an encrypted key with no passphrase must not import");
    assert!(err.contains("passphrase-protected"), "{err}");
}

// ── PRF (passkey) path ──────────────────────────────────────────

#[test]
fn prf_round_trip() {
    let prf = vec![7u8; 32];
    let stored_secret = vec![9u8; 32];
    let packed = protect_ssh_identity_with_prf(
        ED25519_KEY.as_bytes().to_vec(),
        vec![],
        prf.clone(),
        stored_secret.clone(),
    )
    .unwrap();
    let (meta, blob) = unpack(&packed);
    // PRF blobs carry no Argon2 salt: `[12 iv][ct]`.
    let handle = unlock_ssh_identity_with_prf(
        &blob[12..],
        &blob[..12],
        prf,
        stored_secret,
        meta["fingerprint"].as_str().unwrap(),
    )
    .unwrap();
    let ct = encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[ED25519_PUB]), false)
        .unwrap();
    assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
    drop_ssh_identity(handle).unwrap();
}

#[test]
fn reprotect_with_prf_reseals_the_same_identity_under_new_material() {
    let prf = vec![7u8; 32];
    let stored_secret = vec![9u8; 32];
    let packed = protect_ssh_identity_with_prf(
        ED25519_KEY.as_bytes().to_vec(),
        vec![],
        prf.clone(),
        stored_secret.clone(),
    )
    .unwrap();
    let (meta, blob) = unpack(&packed);
    let fpr = meta["fingerprint"].as_str().unwrap();
    let handle =
        unlock_ssh_identity_with_prf(&blob[12..], &blob[..12], prf, stored_secret, fpr)
            .unwrap();

    // Re-seal under the "master" PRF + a fresh stored secret.
    let master_prf = vec![42u8; 32];
    let fresh_secret = vec![3u8; 32];
    let (meta2, resealed) = unpack(
        &reprotect_ssh_identity_with_prf(handle, master_prf.clone(), fresh_secret.clone())
            .unwrap(),
    );
    assert_eq!(
        meta2["keyId"].as_str().unwrap(),
        fpr,
        "reports the AAD identity"
    );
    // The original handle is untouched by a reprotect.
    let ct =
        encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[ED25519_PUB]), false).unwrap();
    assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);

    // The new blob opens under the new material, and only under it.
    let h2 = unlock_ssh_identity_with_prf(
        &resealed[12..],
        &resealed[..12],
        master_prf.clone(),
        fresh_secret.clone(),
        fpr,
    )
    .unwrap();
    assert_eq!(decrypt_age_with_handle(&ct, h2).unwrap(), PLAINTEXT);
    assert!(
        unlock_ssh_identity_with_prf(
            &resealed[12..],
            &resealed[..12],
            vec![7u8; 32],
            fresh_secret.clone(),
            fpr,
        )
        .is_err(),
        "old PRF must not open the re-sealed blob"
    );
    assert!(
        unlock_ssh_identity_with_prf(
            &resealed[12..],
            &resealed[..12],
            master_prf,
            fresh_secret,
            "SHA256:not-the-fingerprint",
        )
        .is_err(),
        "AAD still binds the re-sealed blob to its fingerprint"
    );
    drop_ssh_identity(handle).unwrap();
    drop_ssh_identity(h2).unwrap();
    assert!(reprotect_ssh_identity_with_prf(handle, vec![1u8; 32], vec![2u8; 32]).is_err());
}

#[test]
fn the_ssh_prf_info_string_is_not_the_pgp_or_crx_one() {
    // Colliding info strings would derive one AES key for two key types.
    assert_ne!(SSH_PRF_HKDF_INFO, b"gpg-tools-prf-v1");
    assert_ne!(SSH_PRF_HKDF_INFO, b"gpg-tools-crx-prf-v1");
    for other in [
        "gpg-tools:password:",
        "gpg-tools:passkey:",
        "gpg-tools:crx-password:",
        "gpg-tools:crx-passkey:",
        "gpg-tools:store:v1:",
    ] {
        for ours in [SSH_PASSWORD_AAD_PREFIX, SSH_PASSKEY_AAD_PREFIX] {
            assert!(!ours.starts_with(other), "{ours} / {other}");
            assert!(!other.starts_with(ours), "{other} / {ours}");
        }
    }
}

// ── Identity validation (`insert_validated`) ────────────────────

/// Seal under an arbitrary fingerprint, as an attacker could.
fn forge_blob(plaintext: &[u8], claimed_fpr: &str) -> Vec<u8> {
    protected::seal_with_password(
        plaintext,
        claimed_fpr,
        SSH_PASSWORD_AAD_PREFIX,
        b"vault password",
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
    .unwrap()
}

fn try_unlock(blob: &[u8], fpr: &str) -> Result<u32, String> {
    unlock_ssh_identity_with_password(
        &blob[28..],
        &blob[16..28],
        &blob[..16],
        fpr,
        b"vault password".to_vec(),
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
}

#[test]
fn rejects_a_blob_whose_key_does_not_match_its_bound_fingerprint() {
    // AAD strings are public, so the tag verifies; only the payload can
    // prove it is the named key.
    let key = normalize_openssh_identity(ED25519_KEY.as_bytes(), b"").unwrap();
    let blob = forge_blob(&key.plaintext, ED25519_ENC_FPR);
    let err = try_unlock(&blob, ED25519_ENC_FPR).unwrap_err();
    assert_eq!(err, "Decrypted key does not match this SSH key's fingerprint");
}

#[test]
fn rejects_a_key_wearing_someone_elses_public_half() {
    // Splice the victim's public blob into the attacker's key so the
    // fingerprint check passes; only the live probe catches this.
    let attacker = normalize_openssh_identity(ED25519_KEY.as_bytes(), b"").unwrap();
    let victim = normalize_openssh_identity(ED25519_ENC_KEY.as_bytes(), ENC_KEY_PASSPHRASE)
        .unwrap();

    let spliced = splice_public_blob(&attacker.plaintext, &victim.plaintext);
    // Precondition: the splice really did move the fingerprint.
    assert_eq!(
        public_key_of_normalized(&spliced).unwrap().fingerprint,
        ED25519_ENC_FPR
    );

    let blob = forge_blob(&spliced, ED25519_ENC_FPR);
    let err = try_unlock(&blob, ED25519_ENC_FPR).unwrap_err();
    assert_eq!(err, "Decrypted key does not match this SSH key's fingerprint");
}

/// Replace `host`'s cleartext public-key string with `donor`'s (both ed25519).
fn splice_public_blob(host: &[u8], donor: &[u8]) -> Zeroizing<Vec<u8>> {
    fn body(pem: &str) -> Vec<u8> {
        let b64: String = pem
            .lines()
            .skip_while(|l| l.trim() != OPENSSH_BEGIN)
            .skip(1)
            .take_while(|l| l.trim() != OPENSSH_END)
            .flat_map(|l| l.trim().chars())
            .collect();
        B64.decode(b64).unwrap()
    }
    let mut raw = body(std::str::from_utf8(host).unwrap());
    let host_blob = openssh_public_blob(std::str::from_utf8(host).unwrap()).unwrap();
    let donor_blob = openssh_public_blob(std::str::from_utf8(donor).unwrap()).unwrap();
    assert_eq!(host_blob.len(), donor_blob.len());
    let at = raw
        .windows(host_blob.len())
        .position(|w| w == host_blob.as_slice())
        .expect("public blob appears in the cleartext section");
    raw[at..at + donor_blob.len()].copy_from_slice(&donor_blob);

    let mut pem = String::from(OPENSSH_BEGIN);
    pem.push('\n');
    for chunk in B64.encode(&raw).as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(OPENSSH_END);
    pem.push('\n');
    Zeroizing::new(pem.into_bytes())
}

#[test]
fn rejects_a_blob_of_junk_that_decrypts_cleanly() {
    let blob = forge_blob(b"not a key at all", ED25519_FPR);
    let err = try_unlock(&blob, ED25519_FPR).unwrap_err();
    assert!(err.contains("not a usable SSH private key"), "{err}");
}

#[test]
fn a_wrong_vault_password_is_opaque() {
    let key = normalize_openssh_identity(ED25519_KEY.as_bytes(), b"").unwrap();
    let blob = forge_blob(&key.plaintext, ED25519_FPR);
    let err = unlock_ssh_identity_with_password(
        &blob[28..],
        &blob[16..28],
        &blob[..16],
        ED25519_FPR,
        b"wrong".to_vec(),
        TEST_MEM_KIB,
        TEST_ITERS,
        TEST_PAR,
    )
    .unwrap_err();
    // Must not distinguish wrong password from tampered blob.
    assert!(!err.contains("fingerprint"), "{err}");
}

// ── Handles ─────────────────────────────────────────────────────

#[test]
fn a_dropped_handle_stops_working() {
    let (handle, _) = protect_and_unlock(ED25519_KEY, b"");
    let ct = encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[ED25519_PUB]), false)
        .unwrap();
    assert!(decrypt_age_with_handle(&ct, handle).is_ok());
    drop_ssh_identity(handle).unwrap();
    assert!(decrypt_age_with_handle(&ct, handle).is_err());
    // Idempotent, like the other stores.
    drop_ssh_identity(handle).unwrap();
}

#[test]
fn decrypting_a_file_addressed_elsewhere_says_so() {
    let (handle, _) = protect_and_unlock(ED25519_KEY, b"");
    let ct = encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[RSA2048_PUB]), false)
        .unwrap();
    let err = decrypt_age_with_handle(&ct, handle).unwrap_err();
    assert!(err.contains("not encrypted to this SSH key"), "{err}");
    drop_ssh_identity(handle).unwrap();
}

// ── Message detection ───────────────────────────────────────────

#[test]
fn detects_age_messages_in_both_forms() {
    assert!(is_age_message(AGE_BINARY_MAGIC));
    assert!(is_age_message(AGE_CLI_CT_ED25519_ARMOR.as_bytes()));
    assert!(is_age_message(
        format!("\n  {AGE_CLI_CT_ED25519_ARMOR}").as_bytes()
    ));
    assert!(is_age_message(&B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap()));

    assert!(!is_age_message(b""));
    assert!(!is_age_message(b"-----BEGIN PGP MESSAGE-----"));
    assert!(!is_age_message(&[0xff, 0xfe, 0xfd]));
}

// ── Cross-tool vectors (Go age <-> Rust age) ────────────────────

#[test]
fn decrypts_ciphertext_from_the_go_age_cli() {
    for (key, vectors) in [
        (
            ED25519_KEY,
            [
                B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap(),
                AGE_CLI_CT_ED25519_ARMOR.as_bytes().to_vec(),
            ],
        ),
        (
            RSA2048_KEY,
            [
                B64.decode(AGE_CLI_CT_RSA_BIN_B64).unwrap(),
                AGE_CLI_CT_RSA_ARMOR.as_bytes().to_vec(),
            ],
        ),
    ] {
        let (handle, _) = protect_and_unlock(key, b"");
        for ct in vectors {
            assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
        }
        drop_ssh_identity(handle).unwrap();
    }
}

/// Rust -> Go: our ciphertext must open in the `age` CLI. Skipped when it
/// is not installed (the captured vectors cover Go -> Rust).
#[test]
fn age_cli_decrypts_our_ciphertext() {
    use std::process::Command;

    if Command::new("age").arg("--version").output().is_err() {
        eprintln!("skipping: the `age` CLI is not installed");
        return;
    }

    let dir = std::env::temp_dir().join(format!("gpg-wasm-age-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    for (name, key, pubkey) in [
        ("ed25519", ED25519_KEY, ED25519_PUB),
        ("rsa", RSA2048_KEY, RSA2048_PUB),
    ] {
        for (ext, armor) in [("bin", false), ("age", true)] {
            let key_path = dir.join(format!("{name}.key"));
            let ct_path = dir.join(format!("{name}.{ext}"));
            std::fs::write(&key_path, key).unwrap();
            std::fs::write(
                &ct_path,
                encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[pubkey]), armor)
                    .unwrap(),
            )
            .unwrap();

            let out = Command::new("age")
                .arg("-d")
                .arg("-i")
                .arg(&key_path)
                .arg(&ct_path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "age CLI failed for {name}/{ext}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(out.stdout, PLAINTEXT, "{name}/{ext}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
