# Chrome Web Store listing

Measured against the live store, not inferred. Method and corpora are in the
Am I Being Pwned repo at `example/findings.md`.

## The two fields that are code

`name` and the 132-character summary come from `public/_locales/*/messages.json`
and ship with the build. The detailed description below is typed into the
Developer Dashboard by hand, per locale.

## `en` is deliberately unchanged

The English name is byte-identical to what shipped before. It holds **#1 for
"pgp tools"** and **#5 for "pgp"**, and the only causal evidence anywhere on
store SEO (381 measured title changes) says a title change moves rankings at
roughly even odds up or down. It reallocates relevance rather than adding it.
There is nothing to gain by gambling a ranking that already works.

Everything new rides on the other 42 locales, which are indexed as separate
strings and provably do not dilute each other.

## What the other locales buy

`PGP`, `GPG`, `OpenPGP` and `GnuPG` are standard names, identical in every
language, so a name that is entirely natural in Polish or Japanese still
carries them. Measured SERP depth for those terms:

| query | total results in the store |
|---|---|
| `gnupg` | 2 |
| `gpg` | 3 |
| `openpgp` | 5 |
| `pgp tools` | 5 |

Nearly uncontested, and our title carried none of them.

`en_GB` and `en_AU` carry the English terms `en` has no room for. They were
aimed at the softest SERPs measured, where the #1 result is held by a listing
with fewer weekly users than we have:

| query | #1 holder's weekly users |
|---|---|
| `secure chat` | 5 |
| `private messaging` | 7 |
| `email security` | 18 |
| `message encryption` | 20 |
| `encrypted messaging` | 21 |

Deliberately **not** targeted: `encrypted email` and `secure email` are both
held by Mailvelope at 100,000 users. Relevance gates the tier and popularity
orders within it, so those are not winnable with a title alone.

## Accuracy, and the line we do not cross

The crypto is `sequoia-openpgp`, a real OpenPGP implementation, so `OpenPGP` is
exact and `GPG` is honest shorthand for the interoperable ecosystem. This is
not GnuPG, so every name that mentions GnuPG says **GnuPG compatible**, which
is true by way of the standard.

What we do not do, though the study shows it works and competitors run it: put
other companies' brand names in localised titles. A 234-user ad blocker sits at
#6 for "ublock origin" on exactly that trick. It is trademark infringement on
top of a metadata-policy breach.

## Names and summaries

| locale | name | summary |
|---|---|---|
| `ar` | PGP Tools - تشفير البريد بـ OpenPGP و GPG وحماية الخصوصية | شفّر وفك تشفير ووقّع وتحقق من البريد والرسائل باستخدام OpenPGP و GPG. |
| `bg` | PGP Tools - OpenPGP и GPG криптиране на имейл и съобщения | Криптирайте, декриптирайте, подписвайте и проверявайте съобщения с OpenPGP и GPG. |
| `cs` | PGP Tools - Šifrování OpenPGP a GPG pro e-mail a zprávy | Šifrujte, dešifrujte, podepisujte a ověřujte zprávy pomocí OpenPGP a GPG. Spravujte klíče. |
| `da` | PGP Tools - OpenPGP- og GPG-kryptering af e-mail og filer | Krypter, dekrypter, signer og verificer e-mail med OpenPGP og GPG. Håndter dine nøgler. |
| `de` | PGP Tools - OpenPGP-, GPG- und GnuPG-E-Mail-Verschlüsselung | E-Mails verschlüsseln, entschlüsseln, signieren und verifizieren mit OpenPGP und GPG. |
| `el` | PGP Tools - Κρυπτογράφηση OpenPGP και GPG για email και μηνύματα | Κρυπτογραφήστε, αποκρυπτογραφήστε, υπογράψτε και επαληθεύστε με OpenPGP και GPG. |
| `en` | PGP Tools - Encrypt, Decrypt & Sign | Encrypt, decrypt, sign, and verify messages with PGP. Drag-and-drop files and manage keys. |
| `en_AU` | PGP Tools - GnuPG Compatible Encrypted Messaging and File Encryption | GnuPG compatible file encryption, private messaging and digital signature verification. |
| `en_GB` | PGP Tools - OpenPGP & GPG Message Encryption and Email Security | OpenPGP and GPG message encryption in your browser: encrypt, decrypt, sign, verify, manage keys. |
| `es` | PGP Tools - Cifrado OpenPGP, GPG y GnuPG de correo y mensajes | Cifra, descifra, firma y verifica correo y mensajes con OpenPGP y GPG. Gestiona tus claves. |
| `es_419` | PGP Tools - Encriptación PGP y GPG de email con firma digital | Encripta y desencripta archivos, firma y verifica mensajes con PGP y GPG. Privacidad real. |
| `et` | PGP Tools - OpenPGP ja GPG e-posti krüpteerimine ja privaatsus | Krüpteeri, dekrüpteeri, allkirjasta ja kontrolli sõnumeid OpenPGP ja GPG abil. |
| `fi` | PGP Tools - OpenPGP- ja GPG-salaus sähköpostille ja viesteille | Salaa, pura, allekirjoita ja vahvista viestejä OpenPGP:llä ja GPG:llä. Hallitse avaimiasi. |
| `fil` | PGP Tools - OpenPGP at GPG Email Encryption at Privacy | I-encrypt, i-decrypt, pirmahan at i-verify ang email at mensahe gamit ang OpenPGP at GPG. |
| `fr` | PGP Tools - Chiffrement OpenPGP, GPG et GnuPG d'e-mails | Chiffrez, déchiffrez, signez et vérifiez vos e-mails avec OpenPGP et GPG. Gérez vos clés. |
| `he` | PGP Tools - הצפנת דוא"ל OpenPGP ו-GPG ופרטיות | הצפן, פענח, חתום ואמת דוא"ל והודעות באמצעות OpenPGP ו-GPG. נהל את המפתחות שלך. |
| `hi` | PGP Tools - OpenPGP और GPG ईमेल एन्क्रिप्शन और निजता | OpenPGP और GPG से ईमेल और संदेश एन्क्रिप्ट, डिक्रिप्ट, साइन और सत्यापित करें। |
| `hr` | PGP Tools - OpenPGP i GPG enkripcija e-pošte i privatnost | Šifrirajte, dešifrirajte, potpišite i provjerite poruke pomoću OpenPGP i GPG. |
| `hu` | PGP Tools - OpenPGP és GPG e-mail titkosítás és adatvédelem | Titkosítson, fejtsen vissza, írjon alá és ellenőrizzen OpenPGP és GPG segítségével. |
| `id` | PGP Tools - Enkripsi email OpenPGP dan GPG serta privasi | Enkripsi, dekripsi, tanda tangani, dan verifikasi email dan pesan dengan OpenPGP dan GPG. |
| `it` | PGP Tools - Crittografia OpenPGP e GPG per email e privacy | Cifra, decifra, firma e verifica email e messaggi con OpenPGP e GPG. Gestisci le tue chiavi. |
| `ja` | PGP Tools - OpenPGP・GPGメール暗号化と鍵管理 | OpenPGPとGPGでメールやメッセージを暗号化、復号、署名、検証。ブラウザ上で鍵を管理。 |
| `ko` | PGP Tools - OpenPGP 및 GPG 이메일 암호화와 개인정보 보호 | OpenPGP와 GPG로 이메일과 메시지를 암호화, 복호화, 서명, 검증하고 키를 관리하세요. |
| `lt` | PGP Tools - OpenPGP ir GPG el. pašto šifravimas ir privatumas | Šifruokite, iššifruokite, pasirašykite ir patikrinkite žinutes su OpenPGP ir GPG. |
| `lv` | PGP Tools - OpenPGP un GPG e-pasta šifrēšana un privātums | Šifrējiet, atšifrējiet, parakstiet un pārbaudiet ziņojumus ar OpenPGP un GPG. |
| `ms` | PGP Tools - Penyulitan e-mel OpenPGP dan GPG serta privasi | Sulitkan, nyahsulit, tandatangan dan sahkan mesej dengan OpenPGP dan GPG. |
| `nl` | PGP Tools - OpenPGP- en GPG-e-mailversleuteling en privacy | Versleutel, ontsleutel, onderteken en verifieer e-mail met OpenPGP en GPG. Beheer je sleutels. |
| `no` | PGP Tools - OpenPGP- og GPG-kryptering av e-post og filer | Krypter, dekrypter, signer og verifiser med OpenPGP og GPG. Håndter nøklene dine. |
| `pl` | PGP Tools - Szyfrowanie OpenPGP i GPG poczty e-mail | Szyfruj, odszyfrowuj, podpisuj i weryfikuj e-mail i wiadomości za pomocą OpenPGP i GPG. |
| `pt_BR` | PGP Tools - Criptografia OpenPGP e GPG de e-mail e mensagens | Criptografe, descriptografe, assine e verifique e-mail e mensagens com OpenPGP e GPG. |
| `pt_PT` | PGP Tools - Encriptação OpenPGP e GPG de e-mail e privacidade | Encripte, desencripte, assine e verifique mensagens com OpenPGP e GPG. Faça a gestão das chaves. |
| `ro` | PGP Tools - Criptare OpenPGP și GPG pentru e-mail și mesaje | Criptează, decriptează, semnează și verifică mesaje cu OpenPGP și GPG. Gestionează cheile. |
| `ru` | PGP Tools - Шифрование OpenPGP и GPG для почты и сообщений | Шифруйте, расшифровывайте, подписывайте и проверяйте сообщения с помощью OpenPGP и GPG. |
| `sk` | PGP Tools - Šifrovanie OpenPGP a GPG pre e-mail a správy | Šifrujte, dešifrujte, podpisujte a overujte správy pomocou OpenPGP a GPG. Spravujte kľúče. |
| `sl` | PGP Tools - Šifriranje OpenPGP in GPG za e-pošto in zasebnost | Šifrirajte, dešifrirajte, podpišite in preverite sporočila z OpenPGP in GPG. |
| `sr` | PGP Tools - OpenPGP и GPG енкрипција е-поште и порука | Шифрујте, дешифрујте, потпишите и проверите поруке помоћу OpenPGP и GPG. |
| `sv` | PGP Tools - OpenPGP- och GPG-kryptering av e-post och filer | Kryptera, dekryptera, signera och verifiera med OpenPGP och GPG. Hantera dina nycklar. |
| `th` | PGP Tools - เข้ารหัสอีเมล OpenPGP และ GPG เพื่อความเป็นส่วนตัว | เข้ารหัส ถอดรหัส ลงลายเซ็น และตรวจสอบอีเมลและข้อความด้วย OpenPGP และ GPG |
| `tr` | PGP Tools - OpenPGP ve GPG e-posta şifreleme ve gizlilik | OpenPGP ve GPG ile e-posta ve mesajları şifreleyin, çözün, imzalayın ve doğrulayın. |
| `uk` | PGP Tools - Шифрування OpenPGP і GPG для пошти та повідомлень | Шифруйте, розшифровуйте, підписуйте та перевіряйте повідомлення за допомогою OpenPGP і GPG. |
| `vi` | PGP Tools - Mã hóa email OpenPGP và GPG, bảo mật riêng tư | Mã hóa, giải mã, ký và xác minh email và tin nhắn bằng OpenPGP và GPG. |
| `zh_CN` | PGP Tools - OpenPGP 与 GPG 邮件加密及隐私保护 | 使用 OpenPGP 和 GPG 加密、解密、签名和验证邮件与消息，并管理密钥。 |
| `zh_TW` | PGP Tools - OpenPGP 與 GPG 郵件加密及隱私保護 | 使用 OpenPGP 和 GPG 加密、解密、簽署與驗證郵件與訊息，並管理金鑰。 |

## Detailed description (English)

Dashboard field, not in the build. Every phrase we target appears 2 to 5 times:
a phrase used once retrieves its own listing about 2% of the time, and the spam
policy flags repetition above five. `scripts/check-listing-mentions.mjs`
enforces the window.

```text
Ever thought PGP is a pain to use? That's why this exists.

PGP Tools is OpenPGP and GPG encryption that lives in your browser side panel. Encrypt and decrypt messages, sign and verify them, encrypt files by dragging them in, and manage your keys and contacts. No terminal, no accounts, nothing to configure.

WHAT IT DOES

Message encryption: encrypt and decrypt any text with OpenPGP. Paste it in, or open the side panel next to whatever you are writing. Message encryption works the same whether the text is headed for email, chat, or a file on disk.

Email security: PGP Tools produces standard OpenPGP armoured output, so anything encrypted here opens in GPG, GnuPG, Mailvelope, Thunderbird, or any other standards-compliant client. Email security should not depend on both sides picking the same vendor.

File encryption: drag a file in and get it back encrypted or decrypted. File encryption uses the same keys as everything else, so there is no second thing to set up.

Digital signatures: sign what you send and verify what you receive. A digital signature tells the reader that a message is yours and that nobody edited it on the way.

Key management: generate keys, import and export them, keep a contact list, and look up public keys from GitHub or a keyserver when you ask it to. Key management stays local: nothing is uploaded, and no key leaves the browser unless you export it.

PRIVACY AND SECURITY

Your private keys never leave the browser. They are protected by a passkey through the WebAuthn PRF extension (Touch ID, Face ID, YubiKey) or by an Argon2id password. No accounts, no servers of ours, nothing to sign up for. The privacy here is structural rather than promised, which is the only kind worth having.

All crypto is sequoia-openpgp compiled to WebAssembly, not a JavaScript reimplementation. Security is checked on every build by two audit scripts that assert the extension can name exactly two remote destinations, both reachable only when you request a key lookup.

Open source, free, no accounts required.

Source: https://github.com/Am-I-Being-Pwned/PGP-Tools
```

## Left alone

- **Developer display name**, currently `J4A Industries`. Indexed with title
  weight and shared across every extension on the account, so changing it is a
  portfolio decision, not a PGP Tools one.
- **Category**, `make_chrome_yours/privacy`. Category does nothing for search
  rank, only for browse placement.

## Measuring it

Store search is deterministic for anonymous queries, so rank tracking is
meaningful. `scripts/cws-rank.mjs` reports where we place. Baseline before this
change: #1 for `pgp tools`, #5 for `pgp`, #7 for `decrypt`, and absent from the
top 10 of the other 42 tracked queries.
