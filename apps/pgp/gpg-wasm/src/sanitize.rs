//! Untrusted-text cleanup and lookalike-script detection for User IDs.

/// A word whose letters mix scripts that imitate each other ("Аlice" with a
/// Cyrillic А). Judged per word, so a Cyrillic name with a Latin address is
/// fine; an email address is one word, so a mixed-script domain counts.
pub(crate) fn mixes_scripts(s: &str) -> bool {
    let script = |c: char| match c as u32 {
        0x41..=0x5a | 0x61..=0x7a | 0xc0..=0x24f | 0x1e00..=0x1eff => Some(0),
        0x370..=0x3ff | 0x1f00..=0x1fff => Some(1),
        0x400..=0x52f | 0x1c80..=0x1c8f | 0x2de0..=0x2dff | 0xa640..=0xa69f => Some(2),
        0x530..=0x58f => Some(3),
        // Letters that pass for Latin ones without being them: fullwidth,
        // letterlike and mathematical forms (Ａ, K Kelvin, 𝐀); IPA, phonetic
        // and extended Latin (ɑ, ᴀ); Cherokee and Lisu (Ꭺ, ꓮ).
        0xff21..=0xff3a | 0xff41..=0xff5a | 0x2100..=0x214f | 0x1d400..=0x1d7ff => Some(4),
        0x250..=0x2af | 0x1d00..=0x1dbf | 0xa720..=0xa7ff => Some(5),
        0x13a0..=0x13ff | 0xab70..=0xabbf | 0xa4d0..=0xa4ff => Some(6),
        _ => None,
    };
    s.split(|c: char| c.is_whitespace() || "<>()\"',;:".contains(c))
        .any(|word| {
            let mut seen = None;
            for k in word.chars().filter_map(script) {
                match seen {
                    None => seen = Some(k),
                    Some(prev) if prev != k => return true,
                    _ => {}
                }
            }
            false
        })
}

/// Characters that change how a string displays without showing
/// themselves (inclusive ranges): every `Default_Ignorable_Code_Point` and
/// `Cf` character (Unicode 16), line/paragraph separators, and the visible
/// characters that draw as blank (BLANK below). Each lets two different
/// User IDs look identical. Spelled out rather than a dependency so it can
/// be audited; `lib/utils/lookalike.ts` mirrors it and `lookalike.test.ts`
/// reads this table to keep them equal. Dropping ZWJ/emoji selectors only
/// unjoins emoji, a cosmetic cost in a User ID.
const INVISIBLE_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),   // soft hyphen
    (0x034F, 0x034F),   // combining grapheme joiner
    (0x0600, 0x0605),   // Arabic number signs (Cf)
    (0x061C, 0x061C),   // Arabic letter mark
    (0x06DD, 0x06DD),   // Arabic end of ayah (Cf)
    (0x070F, 0x070F),   // Syriac abbreviation mark (Cf)
    (0x0890, 0x0891),   // Arabic pound/piastre marks above (Cf)
    (0x08E2, 0x08E2),   // Arabic disputed end of ayah (Cf)
    (0x115F, 0x1160),   // Hangul choseong/jungseong fillers
    (0x17B4, 0x17B5),   // Khmer inherent vowels
    (0x180B, 0x180F),   // Mongolian variation selectors, vowel separator
    (0x200B, 0x200F),   // zero-width space/non-joiner/joiner, LRM, RLM
    (0x2028, 0x202E),   // line/paragraph separators, bidi embeddings and overrides
    (0x2060, 0x206F),   // word joiner, invisible operators, isolates, deprecated controls
    (0x2800, 0x2800),   // BLANK: Braille pattern blank (So)
    (0x3164, 0x3164),   // Hangul filler
    (0xFE00, 0xFE0F),   // variation selectors
    (0xFEFF, 0xFEFF),   // zero-width no-break space (BOM)
    (0xFFA0, 0xFFA0),   // halfwidth Hangul filler
    (0xFFF0, 0xFFFB),   // unassigned ignorables, interlinear annotation controls
    (0xFFFC, 0xFFFC),   // BLANK: object replacement character (So)
    (0x110BD, 0x110BD), // Kaithi number sign (Cf)
    (0x110CD, 0x110CD), // Kaithi number sign above (Cf)
    (0x13430, 0x1343F), // Egyptian hieroglyph format controls (Cf)
    (0x1BCA0, 0x1BCA3), // shorthand format controls
    (0x1D159, 0x1D159), // BLANK: musical symbol null notehead (So)
    (0x1D173, 0x1D17A), // musical symbol format controls
    (0xE0000, 0xE0FFF), // tags, variation selectors supplement, reserved ignorables
];

fn is_invisible(c: char) -> bool {
    let c = c as u32;
    INVISIBLE_RANGES.iter().any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// Clean an attacker-controlled string before it reaches the UI: drop
/// control and `INVISIBLE_RANGES` characters, truncate to `max` chars.
pub(crate) fn sanitize_untrusted(s: &str, max: usize) -> String {
    let mut out = String::new();
    let cleaned = s.chars().filter(|&c| !c.is_control() && !is_invisible(c));
    for (i, c) in cleaned.enumerate() {
        if i == max {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}
