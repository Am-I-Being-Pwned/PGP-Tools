/**
 * Mark the letters that make a word a lookalike.
 *
 * The same rule the engine uses to set `lookalike` (`mixes_scripts` in
 * gpg-wasm/src/lib.rs): a WORD whose letters come from more than one of
 * the scripts that imitate each other. Within such a word, the letters
 * outside its main script are the ones to point at -- the Cyrillic А in
 * "Аlice", the IPA ɑ in "ɑlice". A Cyrillic name with a Latin address is
 * two words in two scripts, which is ordinary, and nothing is marked.
 *
 * Computed from the text itself rather than read off the stored flag, so
 * it also marks names on contacts saved before the flag existed.
 */

export interface TextRun {
  text: string;
  /** A letter from a different alphabet than the rest of its word -- or
   *  an invisible character (see `invisible`). */
  odd: boolean;
  /** Characters that draw nothing at all (see {@link INVISIBLE}). Marked
   *  as `odd` too, but a highlight on nothing is still nothing, so the
   *  renderer shows a placeholder in their place. */
  invisible?: true;
  /** A letter of the address's own alphabet that passes for a different
   *  one (the dotless ı in "alıce@corp.com"; see {@link markWord}).
   *  Marked as `odd` too, with its own hover text: "from a different
   *  alphabet" would be wrong about it. */
  confusable?: true;
}

/**
 * Characters that render as nothing: every Default_Ignorable_Code_Point
 * (zero-width space and joiners, soft hyphen, variation selectors, tag
 * characters, the Hangul fillers, the combining grapheme joiner), every
 * format control (Cf: bidi overrides and isolates, Arabic number signs)
 * and every C0/C1 control; the line and paragraph separators; and the
 * symbols that draw as an empty cell without being ignorable (the
 * Braille blank U+2800, the object replacement character U+FFFC, the
 * musical null notehead U+1D159), which neither property covers. The
 * engine strips these from User IDs and key comments; this is the same
 * set on the TypeScript side (`INVISIBLE_RANGES` in gpg-wasm/src/lib.rs,
 * held to it by `lookalike.test.ts`), for text stored before it did and
 * for anything that reaches the screen another way. Inside a name or an
 * address, any one of them makes two different strings look identical.
 */
export const INVISIBLE =
  /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Cc}\u2028\u2029\u2800\uFFFC\u{1D159}]/u;
const INVISIBLE_ALL = new RegExp(INVISIBLE.source, "gu");

/** `s` with every {@link INVISIBLE} character taken out. */
export function stripInvisible(s: string): string {
  return s.replace(INVISIBLE_ALL, "");
}

/**
 * Letters that render like a Latin letter without being one, mapped to
 * it -- a hand-picked subset of the Unicode confusables data (UTS #39)
 * covering the scripts that imitate Latin names in practice: Cyrillic,
 * Greek, Armenian, Cherokee, Lisu, Coptic, small capitals and IPA, and
 * the Latin letters with a stroke or hook that no decomposition takes
 * apart (ł, ø, đ, ħ, ŧ). Digits and pipes that pass for letters
 * ("Car0l", "|ane") are folded the same way.
 *
 * Every value is lower-case ASCII, except "I": a letter drawn as a
 * capital I, which reads as an "i" or an "l" depending on the face. The
 * skeleton gives it both readings, exactly as it does the real one (see
 * `nameSkeleton` in identity/binding).
 *
 * Entries are looked up AFTER NFKC (`readableForm`), so a character
 * NFKC folds into another is covered by its folded form's entry: the
 * hooked upsilon ϒ is Υ by then, and the lunate sigma ϲ is ς, which is
 * why ς is listed. Small forms are listed beside their capitals: the
 * lookup lower-cases a capital, it never upper-cases a small letter.
 */
export const CONFUSABLE = new Map<string, string>([
  ["\u0030", "o"],
  ["\u0031", "l"],
  ["\u007c", "l"],
  ["\u0131", "i"],
  ["\u01c0", "l"],
  ["\u0251", "a"],
  ["\u0261", "g"],
  ["\u0269", "i"],
  ["\u0391", "a"],
  ["\u0392", "b"],
  ["\u0395", "e"],
  ["\u0396", "z"],
  ["\u0397", "h"],
  ["\u0399", "I"],
  ["\u039a", "k"],
  ["\u039c", "m"],
  ["\u039d", "n"],
  ["\u039f", "o"],
  ["\u03a1", "p"],
  ["\u03a4", "t"],
  ["\u03a5", "y"],
  ["\u03a7", "x"],
  ["\u03b1", "a"],
  ["\u03b9", "i"],
  ["\u03ba", "k"],
  ["\u03bd", "v"],
  ["\u03bf", "o"],
  ["\u03c1", "p"],
  ["\u03c2", "c"],
  ["\u03c4", "t"],
  ["\u03c5", "u"],
  ["\u03c7", "x"],
  ["\u0405", "s"],
  ["\u0406", "I"],
  ["\u0408", "j"],
  ["\u0410", "a"],
  ["\u0412", "b"],
  ["\u0415", "e"],
  ["\u041a", "k"],
  ["\u041c", "m"],
  ["\u041d", "h"],
  ["\u041e", "o"],
  ["\u0420", "p"],
  ["\u0421", "c"],
  ["\u0422", "t"],
  ["\u0423", "y"],
  ["\u0425", "x"],
  ["\u0430", "a"],
  ["\u0432", "b"],
  ["\u0435", "e"],
  ["\u043a", "k"],
  ["\u043c", "m"],
  ["\u043d", "h"],
  ["\u043e", "o"],
  ["\u0440", "p"],
  ["\u0441", "c"],
  ["\u0442", "t"],
  ["\u0443", "y"],
  ["\u0445", "x"],
  ["\u0455", "s"],
  ["\u0456", "i"],
  ["\u0457", "i"],
  ["\u0458", "j"],
  ["\u0491", "r"],
  ["\u04c0", "I"],
  ["\u04cf", "l"],
  ["\u0501", "d"],
  ["\u051b", "q"],
  ["\u051d", "w"],
  ["\u1d00", "a"],
  ["\u0262", "g"],
  ["\u0274", "n"],
  ["\u0280", "r"],
  ["\u028f", "y"],
  ["\u0299", "b"],
  ["\u029c", "h"],
  ["\u029f", "l"],
  ["\u026a", "i"],
  ["\u1d04", "c"],
  ["\u1d05", "d"],
  ["\u1d07", "e"],
  ["\u1d0a", "j"],
  ["\u1d0b", "k"],
  ["\u1d0d", "m"],
  ["\u1d0f", "o"],
  ["\u1d18", "p"],
  ["\u1d1b", "t"],
  ["\u1d1c", "u"],
  ["\u1d20", "v"],
  ["\u1d21", "w"],
  ["\u1d22", "z"],
  ["\ua731", "s"],
  ["\u212a", "k"],
  ["\u212b", "a"],
  // Cherokee: capitals that are Latin capitals in all but code point,
  // and their small forms, which draw as small capitals.
  ["\u13a0", "d"], // Ꭰ CHEROKEE LETTER A
  ["\u13a1", "r"], // Ꭱ CHEROKEE LETTER E
  ["\u13a2", "t"], // Ꭲ CHEROKEE LETTER I
  ["\u13a5", "i"], // Ꭵ CHEROKEE LETTER V
  ["\u13a9", "y"], // Ꭹ CHEROKEE LETTER GI
  ["\u13aa", "a"], // Ꭺ CHEROKEE LETTER GO
  ["\u13ab", "j"], // Ꭻ CHEROKEE LETTER GU
  ["\u13ac", "e"], // Ꭼ CHEROKEE LETTER GV
  ["\u13b3", "w"], // Ꮃ CHEROKEE LETTER LA
  ["\u13b7", "m"], // Ꮇ CHEROKEE LETTER LU
  ["\u13bb", "h"], // Ꮋ CHEROKEE LETTER MI
  ["\u13bd", "y"], // Ꮍ CHEROKEE LETTER MU
  ["\u13c0", "g"], // Ꮐ CHEROKEE LETTER NAH
  ["\u13c2", "h"], // Ꮒ CHEROKEE LETTER NI
  ["\u13c3", "z"], // Ꮓ CHEROKEE LETTER NO
  ["\u13cf", "b"], // Ꮟ CHEROKEE LETTER SI
  ["\u13d2", "r"], // Ꮢ CHEROKEE LETTER SV
  ["\u13d4", "w"], // Ꮤ CHEROKEE LETTER TA
  ["\u13d5", "s"], // Ꮥ CHEROKEE LETTER DE
  ["\u13d9", "v"], // Ꮩ CHEROKEE LETTER DO
  ["\u13da", "s"], // Ꮪ CHEROKEE LETTER DU
  ["\u13dd", "l"], // Ꮭ CHEROKEE LETTER TLA
  ["\u13de", "l"], // Ꮮ CHEROKEE LETTER TLE
  ["\u13df", "c"], // Ꮯ CHEROKEE LETTER TLI
  ["\u13e2", "p"], // Ꮲ CHEROKEE LETTER TLV
  ["\u13e6", "k"], // Ꮶ CHEROKEE LETTER TSO
  ["\u13e7", "d"], // Ꮷ CHEROKEE LETTER TSU
  ["\u13f4", "b"], // Ᏼ CHEROKEE LETTER YV
  ["\u13fc", "b"], // ᏼ CHEROKEE SMALL LETTER YV
  ["\uab70", "d"], // ꭰ CHEROKEE SMALL LETTER A
  ["\uab71", "r"], // ꭱ CHEROKEE SMALL LETTER E
  ["\uab72", "t"], // ꭲ CHEROKEE SMALL LETTER I
  ["\uab75", "i"], // ꭵ CHEROKEE SMALL LETTER V
  ["\uab79", "y"], // ꭹ CHEROKEE SMALL LETTER GI
  ["\uab7a", "a"], // ꭺ CHEROKEE SMALL LETTER GO
  ["\uab7b", "j"], // ꭻ CHEROKEE SMALL LETTER GU
  ["\uab7c", "e"], // ꭼ CHEROKEE SMALL LETTER GV
  ["\uab83", "w"], // ꮃ CHEROKEE SMALL LETTER LA
  ["\uab87", "m"], // ꮇ CHEROKEE SMALL LETTER LU
  ["\uab8b", "h"], // ꮋ CHEROKEE SMALL LETTER MI
  ["\uab8d", "y"], // ꮍ CHEROKEE SMALL LETTER MU
  ["\uab90", "g"], // ꮐ CHEROKEE SMALL LETTER NAH
  ["\uab92", "h"], // ꮒ CHEROKEE SMALL LETTER NI
  ["\uab93", "z"], // ꮓ CHEROKEE SMALL LETTER NO
  ["\uab9f", "b"], // ꮟ CHEROKEE SMALL LETTER SI
  ["\uaba2", "r"], // ꮢ CHEROKEE SMALL LETTER SV
  ["\uaba4", "w"], // ꮤ CHEROKEE SMALL LETTER TA
  ["\uaba5", "s"], // ꮥ CHEROKEE SMALL LETTER DE
  ["\uaba9", "v"], // ꮩ CHEROKEE SMALL LETTER DO
  ["\uabaa", "s"], // ꮪ CHEROKEE SMALL LETTER DU
  ["\uabad", "l"], // ꮭ CHEROKEE SMALL LETTER TLA
  ["\uabae", "l"], // ꮮ CHEROKEE SMALL LETTER TLE
  ["\uabaf", "c"], // ꮯ CHEROKEE SMALL LETTER TLI
  ["\uabb2", "p"], // ꮲ CHEROKEE SMALL LETTER TLV
  ["\uabb6", "k"], // ꮶ CHEROKEE SMALL LETTER TSO
  ["\uabb7", "d"], // ꮷ CHEROKEE SMALL LETTER TSU
  // Lisu: an alphabet built from Latin capitals, upright and turned.
  // Only the upright ones are here.
  ["\ua4d0", "b"], // ꓐ LISU LETTER BA
  ["\ua4d1", "p"], // ꓑ LISU LETTER PA
  ["\ua4d2", "d"], // ꓒ LISU LETTER PHA
  ["\ua4d3", "d"], // ꓓ LISU LETTER DA
  ["\ua4d4", "t"], // ꓔ LISU LETTER TA
  ["\ua4d6", "g"], // ꓖ LISU LETTER GA
  ["\ua4d7", "k"], // ꓗ LISU LETTER KA
  ["\ua4d9", "j"], // ꓙ LISU LETTER JA
  ["\ua4da", "c"], // ꓚ LISU LETTER CA
  ["\ua4dc", "z"], // ꓜ LISU LETTER DZA
  ["\ua4dd", "f"], // ꓝ LISU LETTER TSA
  ["\ua4df", "m"], // ꓟ LISU LETTER MA
  ["\ua4e0", "n"], // ꓠ LISU LETTER NA
  ["\ua4e1", "l"], // ꓡ LISU LETTER LA
  ["\ua4e2", "s"], // ꓢ LISU LETTER SA
  ["\ua4e3", "r"], // ꓣ LISU LETTER ZHA
  ["\ua4e6", "v"], // ꓦ LISU LETTER HA
  ["\ua4e7", "h"], // ꓧ LISU LETTER XA
  ["\ua4ea", "w"], // ꓪ LISU LETTER WA
  ["\ua4eb", "x"], // ꓫ LISU LETTER SHA
  ["\ua4ec", "y"], // ꓬ LISU LETTER YA
  ["\ua4ee", "a"], // ꓮ LISU LETTER A
  ["\ua4f0", "e"], // ꓰ LISU LETTER E
  ["\ua4f2", "I"], // ꓲ LISU LETTER I
  ["\ua4f3", "o"], // ꓳ LISU LETTER O
  ["\ua4f4", "u"], // ꓴ LISU LETTER U
  // Armenian.
  ["\u053c", "l"], // Լ ARMENIAN CAPITAL LETTER LIWN
  ["\u054d", "u"], // Ս ARMENIAN CAPITAL LETTER SEH
  ["\u054f", "s"], // Տ ARMENIAN CAPITAL LETTER TIWN
  ["\u0555", "o"], // Օ ARMENIAN CAPITAL LETTER OH
  ["\u0566", "q"], // զ ARMENIAN SMALL LETTER ZA
  ["\u056c", "l"], // լ ARMENIAN SMALL LETTER LIWN
  ["\u0570", "h"], // հ ARMENIAN SMALL LETTER HO
  ["\u0575", "j"], // յ ARMENIAN SMALL LETTER YI
  ["\u0578", "n"], // ո ARMENIAN SMALL LETTER VO
  ["\u057c", "n"], // ռ ARMENIAN SMALL LETTER RA
  ["\u057d", "u"], // ս ARMENIAN SMALL LETTER SEH
  ["\u0581", "g"], // ց ARMENIAN SMALL LETTER CO
  ["\u0585", "o"], // օ ARMENIAN SMALL LETTER OH
  // Coptic: capitals and their small forms.
  ["\u2c82", "b"], // Ⲃ COPTIC CAPITAL LETTER VIDA
  ["\u2c83", "b"], // ⲃ COPTIC SMALL LETTER VIDA
  ["\u2c8c", "z"], // Ⲍ COPTIC CAPITAL LETTER ZATA
  ["\u2c8d", "z"], // ⲍ COPTIC SMALL LETTER ZATA
  ["\u2c8e", "h"], // Ⲏ COPTIC CAPITAL LETTER HATE
  ["\u2c8f", "h"], // ⲏ COPTIC SMALL LETTER HATE
  ["\u2c92", "I"], // Ⲓ COPTIC CAPITAL LETTER IAUDA
  ["\u2c93", "I"], // ⲓ COPTIC SMALL LETTER IAUDA
  ["\u2c94", "k"], // Ⲕ COPTIC CAPITAL LETTER KAPA
  ["\u2c95", "k"], // ⲕ COPTIC SMALL LETTER KAPA
  ["\u2c98", "m"], // Ⲙ COPTIC CAPITAL LETTER MI
  ["\u2c99", "m"], // ⲙ COPTIC SMALL LETTER MI
  ["\u2c9a", "n"], // Ⲛ COPTIC CAPITAL LETTER NI
  ["\u2c9b", "n"], // ⲛ COPTIC SMALL LETTER NI
  ["\u2c9e", "o"], // Ⲟ COPTIC CAPITAL LETTER O
  ["\u2c9f", "o"], // ⲟ COPTIC SMALL LETTER O
  ["\u2ca2", "p"], // Ⲣ COPTIC CAPITAL LETTER RO
  ["\u2ca3", "p"], // ⲣ COPTIC SMALL LETTER RO
  ["\u2ca4", "c"], // Ⲥ COPTIC CAPITAL LETTER SIMA
  ["\u2ca5", "c"], // ⲥ COPTIC SMALL LETTER SIMA
  ["\u2ca6", "t"], // Ⲧ COPTIC CAPITAL LETTER TAU
  ["\u2ca7", "t"], // ⲧ COPTIC SMALL LETTER TAU
  ["\u2ca8", "y"], // Ⲩ COPTIC CAPITAL LETTER UA
  ["\u2ca9", "y"], // ⲩ COPTIC SMALL LETTER UA
  ["\u2cac", "x"], // Ⲭ COPTIC CAPITAL LETTER KHI
  ["\u2cad", "x"], // ⲭ COPTIC SMALL LETTER KHI
  // Greek, beyond the letters above.
  ["\u037f", "j"], // Ϳ GREEK CAPITAL LETTER YOT
  ["\u03b3", "y"], // γ GREEK SMALL LETTER GAMMA
  ["\u03b7", "n"], // η GREEK SMALL LETTER ETA
  ["\u03c9", "w"], // ω GREEK SMALL LETTER OMEGA
  ["\u03dc", "f"], // Ϝ GREEK LETTER DIGAMMA
  ["\u03f3", "j"], // ϳ GREEK LETTER YOT
  ["\u03fa", "m"], // Ϻ GREEK CAPITAL LETTER SAN
  // Cyrillic, beyond the letters above.
  ["\u0400", "e"], // Ѐ CYRILLIC CAPITAL LETTER IE WITH GRAVE
  ["\u0407", "I"], // Ї CYRILLIC CAPITAL LETTER YI
  ["\u040c", "k"], // Ќ CYRILLIC CAPITAL LETTER KJE
  ["\u0433", "r"], // г CYRILLIC SMALL LETTER GHE
  ["\u043f", "n"], // п CYRILLIC SMALL LETTER PE
  ["\u0450", "e"], // ѐ CYRILLIC SMALL LETTER IE WITH GRAVE
  ["\u0461", "w"], // ѡ CYRILLIC SMALL LETTER OMEGA
  ["\u0474", "v"], // Ѵ CYRILLIC CAPITAL LETTER IZHITSA
  ["\u0475", "v"], // ѵ CYRILLIC SMALL LETTER IZHITSA
  ["\u04ae", "y"], // Ү CYRILLIC CAPITAL LETTER STRAIGHT U
  ["\u04af", "y"], // ү CYRILLIC SMALL LETTER STRAIGHT U
  ["\u04ba", "h"], // Һ CYRILLIC CAPITAL LETTER SHHA
  ["\u04bb", "h"], // һ CYRILLIC SMALL LETTER SHHA
  ["\u04e0", "z"], // Ӡ CYRILLIC CAPITAL LETTER ABKHASIAN DZE
  ["\u0500", "d"], // Ԁ CYRILLIC CAPITAL LETTER KOMI DE
  ["\u050c", "g"], // Ԍ CYRILLIC CAPITAL LETTER KOMI SJE
  ["\u051a", "q"], // Ԛ CYRILLIC CAPITAL LETTER QA
  ["\u051c", "w"], // Ԝ CYRILLIC CAPITAL LETTER WE
  // Latin letters with a stroke, bar or hook. None of them decomposes,
  // so the NFKD pass that drops an accent leaves them whole.
  ["\u00d8", "o"], // Ø LATIN CAPITAL LETTER O WITH STROKE
  ["\u00f8", "o"], // ø LATIN SMALL LETTER O WITH STROKE
  ["\u0110", "d"], // Đ LATIN CAPITAL LETTER D WITH STROKE
  ["\u0111", "d"], // đ LATIN SMALL LETTER D WITH STROKE
  ["\u0126", "h"], // Ħ LATIN CAPITAL LETTER H WITH STROKE
  ["\u0127", "h"], // ħ LATIN SMALL LETTER H WITH STROKE
  ["\u0138", "k"], // ĸ LATIN SMALL LETTER KRA
  ["\u0141", "l"], // Ł LATIN CAPITAL LETTER L WITH STROKE
  ["\u0142", "l"], // ł LATIN SMALL LETTER L WITH STROKE
  ["\u0166", "t"], // Ŧ LATIN CAPITAL LETTER T WITH STROKE
  ["\u0167", "t"], // ŧ LATIN SMALL LETTER T WITH STROKE
  ["\u0180", "b"], // ƀ LATIN SMALL LETTER B WITH STROKE
  ["\u0181", "b"], // Ɓ LATIN CAPITAL LETTER B WITH HOOK
  ["\u0188", "c"], // ƈ LATIN SMALL LETTER C WITH HOOK
  ["\u018a", "d"], // Ɗ LATIN CAPITAL LETTER D WITH HOOK
  ["\u0191", "f"], // Ƒ LATIN CAPITAL LETTER F WITH HOOK
  ["\u0192", "f"], // ƒ LATIN SMALL LETTER F WITH HOOK
  ["\u0197", "I"], // Ɨ LATIN CAPITAL LETTER I WITH STROKE
  ["\u0198", "k"], // Ƙ LATIN CAPITAL LETTER K WITH HOOK
  ["\u0199", "k"], // ƙ LATIN SMALL LETTER K WITH HOOK
  ["\u019a", "l"], // ƚ LATIN SMALL LETTER L WITH BAR
  ["\u019d", "n"], // Ɲ LATIN CAPITAL LETTER N WITH LEFT HOOK
  ["\u01a4", "p"], // Ƥ LATIN CAPITAL LETTER P WITH HOOK
  ["\u01a5", "p"], // ƥ LATIN SMALL LETTER P WITH HOOK
  ["\u01ab", "t"], // ƫ LATIN SMALL LETTER T WITH PALATAL HOOK
  ["\u01ac", "t"], // Ƭ LATIN CAPITAL LETTER T WITH HOOK
  ["\u01ad", "t"], // ƭ LATIN SMALL LETTER T WITH HOOK
  ["\u01ae", "t"], // Ʈ LATIN CAPITAL LETTER T WITH RETROFLEX HOOK
  ["\u01b5", "z"], // Ƶ LATIN CAPITAL LETTER Z WITH STROKE
  ["\u01b6", "z"], // ƶ LATIN SMALL LETTER Z WITH STROKE
  ["\u01e4", "g"], // Ǥ LATIN CAPITAL LETTER G WITH STROKE
  ["\u01e5", "g"], // ǥ LATIN SMALL LETTER G WITH STROKE
  ["\u0224", "z"], // Ȥ LATIN CAPITAL LETTER Z WITH HOOK
  ["\u0225", "z"], // ȥ LATIN SMALL LETTER Z WITH HOOK
  ["\u0237", "j"], // ȷ LATIN SMALL LETTER DOTLESS J
  ["\u023a", "a"], // Ⱥ LATIN CAPITAL LETTER A WITH STROKE
  ["\u023b", "c"], // Ȼ LATIN CAPITAL LETTER C WITH STROKE
  ["\u023c", "c"], // ȼ LATIN SMALL LETTER C WITH STROKE
  ["\u023e", "t"], // Ⱦ LATIN CAPITAL LETTER T WITH DIAGONAL STROKE
  ["\u023f", "s"], // ȿ LATIN SMALL LETTER S WITH SWASH TAIL
  ["\u0240", "z"], // ɀ LATIN SMALL LETTER Z WITH SWASH TAIL
  ["\u0243", "b"], // Ƀ LATIN CAPITAL LETTER B WITH STROKE
  ["\u0246", "e"], // Ɇ LATIN CAPITAL LETTER E WITH STROKE
  ["\u0247", "e"], // ɇ LATIN SMALL LETTER E WITH STROKE
  ["\u0248", "j"], // Ɉ LATIN CAPITAL LETTER J WITH STROKE
  ["\u0249", "j"], // ɉ LATIN SMALL LETTER J WITH STROKE
  ["\u024c", "r"], // Ɍ LATIN CAPITAL LETTER R WITH STROKE
  ["\u024d", "r"], // ɍ LATIN SMALL LETTER R WITH STROKE
  ["\u024e", "y"], // Ɏ LATIN CAPITAL LETTER Y WITH STROKE
  ["\u024f", "y"], // ɏ LATIN SMALL LETTER Y WITH STROKE
  ["\u0253", "b"], // ɓ LATIN SMALL LETTER B WITH HOOK
  ["\u0256", "d"], // ɖ LATIN SMALL LETTER D WITH TAIL
  ["\u0257", "d"], // ɗ LATIN SMALL LETTER D WITH HOOK
  ["\u0260", "g"], // ɠ LATIN SMALL LETTER G WITH HOOK
  ["\u0266", "h"], // ɦ LATIN SMALL LETTER H WITH HOOK
  ["\u0268", "i"], // ɨ LATIN SMALL LETTER I WITH STROKE
  ["\u026b", "l"], // ɫ LATIN SMALL LETTER L WITH MIDDLE TILDE
  ["\u026c", "l"], // ɬ LATIN SMALL LETTER L WITH BELT
  ["\u026d", "l"], // ɭ LATIN SMALL LETTER L WITH RETROFLEX HOOK
  ["\u0271", "m"], // ɱ LATIN SMALL LETTER M WITH HOOK
  ["\u0272", "n"], // ɲ LATIN SMALL LETTER N WITH LEFT HOOK
  ["\u0273", "n"], // ɳ LATIN SMALL LETTER N WITH RETROFLEX HOOK
  ["\u0275", "o"], // ɵ LATIN SMALL LETTER BARRED O
  ["\u027d", "r"], // ɽ LATIN SMALL LETTER R WITH TAIL
  ["\u0282", "s"], // ʂ LATIN SMALL LETTER S WITH HOOK
  ["\u0288", "t"], // ʈ LATIN SMALL LETTER T WITH RETROFLEX HOOK
  ["\u028b", "v"], // ʋ LATIN SMALL LETTER V WITH HOOK
  ["\u0290", "z"], // ʐ LATIN SMALL LETTER Z WITH RETROFLEX HOOK
  ["\u0291", "z"], // ʑ LATIN SMALL LETTER Z WITH CURL
  ["\u02a0", "q"], // ʠ LATIN SMALL LETTER Q WITH HOOK
  ["\u2c60", "l"], // Ⱡ LATIN CAPITAL LETTER L WITH DOUBLE BAR
  ["\u2c61", "l"], // ⱡ LATIN SMALL LETTER L WITH DOUBLE BAR
  ["\u2c62", "l"], // Ɫ LATIN CAPITAL LETTER L WITH MIDDLE TILDE
  ["\u2c63", "p"], // Ᵽ LATIN CAPITAL LETTER P WITH STROKE
  ["\u2c64", "r"], // Ɽ LATIN CAPITAL LETTER R WITH TAIL
  ["\u2c65", "a"], // ⱥ LATIN SMALL LETTER A WITH STROKE
  ["\u2c66", "t"], // ⱦ LATIN SMALL LETTER T WITH DIAGONAL STROKE
  ["\u2c67", "h"], // Ⱨ LATIN CAPITAL LETTER H WITH DESCENDER
  ["\u2c68", "h"], // ⱨ LATIN SMALL LETTER H WITH DESCENDER
  ["\u2c69", "k"], // Ⱪ LATIN CAPITAL LETTER K WITH DESCENDER
  ["\u2c6a", "k"], // ⱪ LATIN SMALL LETTER K WITH DESCENDER
  ["\u2c6b", "z"], // Ⱬ LATIN CAPITAL LETTER Z WITH DESCENDER
  ["\u2c6c", "z"], // ⱬ LATIN SMALL LETTER Z WITH DESCENDER
  ["\u2c6e", "m"], // Ɱ LATIN CAPITAL LETTER M WITH HOOK
  ["\ua740", "k"], // Ꝁ LATIN CAPITAL LETTER K WITH STROKE
  ["\ua741", "k"], // ꝁ LATIN SMALL LETTER K WITH STROKE
  ["\ua748", "l"], // Ꝉ LATIN CAPITAL LETTER L WITH HIGH STROKE
  ["\ua749", "l"], // ꝉ LATIN SMALL LETTER L WITH HIGH STROKE
  ["\ua750", "p"], // Ꝑ LATIN CAPITAL LETTER P WITH STROKE THROUGH DESCENDER
  ["\ua751", "p"], // ꝑ LATIN SMALL LETTER P WITH STROKE THROUGH DESCENDER
  ["\ua756", "q"], // Ꝗ LATIN CAPITAL LETTER Q WITH STROKE THROUGH DESCENDER
  ["\ua757", "q"], // ꝗ LATIN SMALL LETTER Q WITH STROKE THROUGH DESCENDER
  ["\ua75e", "v"], // Ꝟ LATIN CAPITAL LETTER V WITH DIAGONAL STROKE
  ["\ua75f", "v"], // ꝟ LATIN SMALL LETTER V WITH DIAGONAL STROKE
  // Digits and letters of other scripts drawn as a plain round "o" (or a
  // y, a q) in most faces. A word mixing one of these in is marked by
  // its script anyway (see `scriptOf`); listed so the skeleton reads it
  // as the letter it passes for, not as a wildcard.
  ["\u0966", "o"], // ० DEVANAGARI DIGIT ZERO
  ["\u0e50", "o"], // ๐ THAI DIGIT ZERO
  ["\u0d20", "o"], // ഠ MALAYALAM LETTER TTHA
  ["\u0b20", "o"], // ଠ ORIYA LETTER TTHA
  ["\u0c66", "o"], // ౦ TELUGU DIGIT ZERO
  ["\u0ce6", "o"], // ೦ KANNADA DIGIT ZERO
  ["\u10e7", "y"], // ყ GEORGIAN LETTER QAR
  ["\u0563", "q"], // գ ARMENIAN SMALL LETTER GIM
  ["\u056e", "o"], // ծ ARMENIAN SMALL LETTER CA
]);

const enum Script {
  Latin,
  Greek,
  Cyrillic,
  Armenian,
  Fullwidth,
  ExtendedLatin,
  Cherokee,
}

/**
 * Every Unicode script, by its Script property name. `scriptOf` asks
 * the regex engine which one a letter belongs to, rather than keeping a
 * list of the scripts known to imitate Latin: that list missed the
 * Devanagari, Thai, Telugu and Kannada zeros, the Malayalam ttha, a
 * Georgian and two Armenian letters, so "Dan C\u0966le" mixed nothing and
 * nothing was marked. A name the runtime does not know is skipped.
 */
const SCRIPT_NAMES =
  "Adlam Ahom Anatolian_Hieroglyphs Arabic Armenian Avestan Balinese Bamum Bassa_Vah Batak Bengali Bhaiksuki Bopomofo Brahmi Braille Buginese Buhid Canadian_Aboriginal Carian Caucasian_Albanian Chakma Cham Cherokee Chorasmian Coptic Cuneiform Cypriot Cypro_Minoan Cyrillic Deseret Devanagari Dives_Akuru Dogra Duployan Egyptian_Hieroglyphs Elbasan Elymaic Ethiopic Garay Georgian Glagolitic Gothic Grantha Greek Gujarati Gunjala_Gondi Gurmukhi Gurung_Khema Han Hangul Hanifi_Rohingya Hanunoo Hatran Hebrew Hiragana Imperial_Aramaic Inscriptional_Pahlavi Inscriptional_Parthian Javanese Kaithi Kannada Katakana Kawi Kayah_Li Kharoshthi Khitan_Small_Script Khmer Khojki Khudawadi Kirat_Rai Lao Latin Lepcha Limbu Linear_A Linear_B Lisu Lycian Lydian Mahajani Makasar Malayalam Mandaic Manichaean Marchen Masaram_Gondi Medefaidrin Meetei_Mayek Mende_Kikakui Meroitic_Cursive Meroitic_Hieroglyphs Miao Modi Mongolian Mro Multani Myanmar Nabataean Nag_Mundari Nandinagari New_Tai_Lue Newa Nko Nushu Nyiakeng_Puachue_Hmong Ogham Ol_Chiki Ol_Onal Old_Hungarian Old_Italic Old_North_Arabian Old_Permic Old_Persian Old_Sogdian Old_South_Arabian Old_Turkic Old_Uyghur Oriya Osage Osmanya Pahawh_Hmong Palmyrene Pau_Cin_Hau Phags_Pa Phoenician Psalter_Pahlavi Rejang Runic Samaritan Saurashtra Sharada Shavian Siddham SignWriting Sinhala Sogdian Sora_Sompeng Soyombo Sundanese Sunuwar Syloti_Nagri Syriac Tagalog Tagbanwa Tai_Le Tai_Tham Tai_Viet Takri Tamil Tangsa Tangut Telugu Thaana Thai Tibetan Tifinagh Tirhuta Todhri Toto Tulu_Tigalari Ugaritic Vai Vithkuqi Wancho Warang_Citi Yezidi Yi Zanabazar_Square".split(
    " ",
  );

/** Scripts written together in one word: Japanese mixes kanji, hiragana
 *  and katakana, Korean hangul and hanja, Chinese han and bopomofo. */
const CJK = new Set(["Han", "Hiragana", "Katakana", "Hangul", "Bopomofo"]);

let scriptTests: [string, RegExp][] | null = null;
const scriptCache = new Map<string, string | null>();
/** Letters and digits; Common and Inherited ones (ASCII digits, the
 *  fullwidth forms' punctuation, combining marks) belong to no script. */
const LETTER_OR_DIGIT = /^[\p{L}\p{N}]$/u;
const NO_SCRIPT = /^[\p{Script=Common}\p{Script=Inherited}]$/u;

/** The Unicode script of a letter or digit, by its Script property;
 *  null for anything else (see {@link SCRIPT_NAMES}). */
function unicodeScript(c: string): string | null {
  const cached = scriptCache.get(c);
  if (cached !== undefined) return cached;
  let found: string | null = null;
  if (LETTER_OR_DIGIT.test(c) && !NO_SCRIPT.test(c)) {
    scriptTests ??= SCRIPT_NAMES.flatMap((name): [string, RegExp][] => {
      try {
        return [[name, new RegExp(`^\\p{Script=${name}}$`, "u")]];
      } catch {
        return [];
      }
    });
    const hit = scriptTests.find(([, re]) => re.test(c))?.[0] ?? null;
    found = hit !== null && CJK.has(hit) ? "Han" : hit;
  }
  scriptCache.set(c, found);
  return found;
}

/** Which script a letter counts as. The scripts that imitate Latin
 *  first, by range -- with Latin split into its plain letters, its
 *  fullwidth and mathematical forms and its IPA and small capitals,
 *  which do not belong in an ordinary Latin word either. Then any other
 *  letter or digit by its Unicode script (see {@link unicodeScript}). */
function scriptOf(c: string): Script | string | null {
  const known = knownScriptOf(c);
  if (known !== null) return known;
  const script = unicodeScript(c);
  // A letter of a split-out script outside its main ranges (Latin
  // ligatures and Latin Extended-C, say) is not a plain letter of it.
  return script === "Latin"
    ? Script.ExtendedLatin
    : script === "Lisu"
      ? Script.Cherokee
      : script !== null && script in SPLIT_OUT
        ? SPLIT_OUT[script]
        : script;
}

/** The scripts `knownScriptOf` already names, by their property name. */
const SPLIT_OUT: Record<string, Script> = {
  Greek: Script.Greek,
  Cyrillic: Script.Cyrillic,
  Armenian: Script.Armenian,
  Cherokee: Script.Cherokee,
};

function knownScriptOf(c: string): Script | null {
  const cp = c.codePointAt(0) ?? 0;
  if (
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    (cp >= 0xc0 && cp <= 0x24f) ||
    (cp >= 0x1e00 && cp <= 0x1eff)
  )
    return Script.Latin;
  if ((cp >= 0x370 && cp <= 0x3ff) || (cp >= 0x1f00 && cp <= 0x1fff))
    return Script.Greek;
  if (
    (cp >= 0x400 && cp <= 0x52f) ||
    (cp >= 0x1c80 && cp <= 0x1c8f) ||
    (cp >= 0x2de0 && cp <= 0x2dff) ||
    (cp >= 0xa640 && cp <= 0xa69f)
  )
    return Script.Cyrillic;
  if (cp >= 0x530 && cp <= 0x58f) return Script.Armenian;
  if (
    (cp >= 0xff21 && cp <= 0xff3a) ||
    (cp >= 0xff41 && cp <= 0xff5a) ||
    (cp >= 0x2100 && cp <= 0x214f) ||
    (cp >= 0x1d400 && cp <= 0x1d7ff)
  )
    return Script.Fullwidth;
  if (
    (cp >= 0x250 && cp <= 0x2af) ||
    (cp >= 0x1d00 && cp <= 0x1dbf) ||
    (cp >= 0xa720 && cp <= 0xa7ff)
  )
    return Script.ExtendedLatin;
  if (
    (cp >= 0x13a0 && cp <= 0x13ff) ||
    (cp >= 0xab70 && cp <= 0xabbf) ||
    (cp >= 0xa4d0 && cp <= 0xa4ff)
  )
    return Script.Cherokee;
  return null;
}

/** Word separators, as `mixes_scripts` splits on them. An email address
 *  is ONE word, so a domain label in another script next to a Latin one
 *  ("tim@аррӏе.com") counts as mixing. */
const SEPARATOR = /[\s<>()"',;:]/u;

/** Mark one word: the letters outside its main script, if it mixes,
 *  and every invisible character whether it mixes or not.
 *
 *  In an ADDRESS (a word with an "@"), also every non-ASCII letter that
 *  stands in for a Latin one ({@link CONFUSABLE}). Mixing scripts is not
 *  needed for those to deceive: the dotless ı is Latin, so "alıce" is a
 *  one-script word, and it reads as alice. A name may well be written in
 *  such letters (Turkish, Greek, Cyrillic); an address that otherwise
 *  reads as plain ASCII is where one is a disguise -- and it is the
 *  address the conflict check compares on its skeleton (see
 *  `identity/binding`), so it is marked where that check looks. */
function markWord(word: string): TextRun[] {
  const chars = [...word];
  const scripts = chars.map(scriptOf);
  const counts = new Map<Script | string, number>();
  for (const s of scripts) {
    if (s !== null) counts.set(s, (counts.get(s) ?? 0) + 1);
  }

  // The word's own script is the one most of its letters use; a tie goes
  // to plain Latin, which is what a lookalike is usually imitating.
  let main: Script | string = Script.Latin;
  let best = -1;
  for (const [s, n] of counts) {
    if (n > best || (n === best && s === Script.Latin)) {
      main = s;
      best = n;
    }
  }
  // Only an address that otherwise reads as Latin: "иван@почта.рф" is
  // written in Cyrillic, and every one of its а and о is meant.
  const latinAddress = word.includes("@") && main === Script.Latin;
  const special = (c: string): TextRun | null =>
    INVISIBLE.test(c)
      ? { text: c, odd: true, invisible: true }
      : latinAddress && isConfusableLetter(c)
        ? { text: c, odd: true, confusable: true }
        : null;
  if (counts.size < 2) {
    if (!chars.some((c) => special(c) !== null))
      return [{ text: word, odd: false }];
    return chars.map((c) => special(c) ?? { text: c, odd: false });
  }
  return chars.map(
    (c, i) =>
      special(c) ?? {
        text: c,
        odd: scripts[i] !== null && scripts[i] !== main,
      },
  );
}

/** Characters that pass for the dot in an address ("corp・com"):
 *  middle dots, the hyphenation point, the dot operators. A name drops
 *  them with the rest of its punctuation; an address keeps its dots, so
 *  these are read as one (`addressSkeletons`) and marked inside it. */
export const DOT_LOOKALIKES = new Set([
  "\u00b7",
  "\u0387",
  "\u2027",
  "\u2219",
  "\u22c5",
  "\u30fb",
  "\uff65",
  // The ideographic full stop and its halfwidth and fullwidth forms:
  // "corp\u3002com" is how an IME types corp.com.
  "\u3002",
  "\uff0e",
  "\uff61",
]);

/** A non-ASCII letter that stands in for a Latin one. ASCII entries in
 *  {@link CONFUSABLE} (the digits and the pipe) are left alone: "bob1"
 *  is an ordinary address. */
function isConfusableLetter(c: string): boolean {
  if ((c.codePointAt(0) ?? 0) < 0x80) return false;
  return (
    CONFUSABLE.has(c) ||
    CONFUSABLE.has(c.toLowerCase()) ||
    DOT_LOOKALIKES.has(c)
  );
}

/** Split `s` into runs, merging neighbours with the same marking. */
export function markLookalikes(s: string): TextRun[] {
  const runs: TextRun[] = [];
  let word = "";
  const push = (run: TextRun) => {
    const last = runs.at(-1);
    // Invisible characters stay one per run, so each gets its own
    // placeholder and its own code point in the hover text.
    if (
      last?.odd === run.odd &&
      !last.invisible &&
      !run.invisible &&
      last.confusable === run.confusable
    )
      last.text += run.text;
    else runs.push({ ...run });
  };
  const flush = () => {
    if (word) markWord(word).forEach(push);
    word = "";
  };
  for (const c of s) {
    if (SEPARATOR.test(c)) {
      flush();
      push({ text: c, odd: false });
    } else {
      word += c;
    }
  }
  flush();
  return runs;
}

/** "U+0410", for saying which character is marked. */
export function codePointLabel(c: string): string {
  return [...c]
    .map(
      (ch) =>
        `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`,
    )
    .join(" ");
}
