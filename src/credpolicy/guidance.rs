//! Message keys and their Polish and English strings.
//!
//! The assessors return a **key**, never prose ([`crate::credpolicy::Assessment::guidance`]).
//! Five front-ends have to say the same thing — `passwd`, `login`, the
//! `orblogin` greeter, the sudo daemon and `eos-control` — and three of them
//! draw text in a GUI while two write to a TTY. A key lets each render it its
//! own way and lets the strings be translated without touching the policy.
//!
//! ```
//! use userutils::credpolicy::guidance::{text, Lang};
//! let a = userutils::credpolicy::assess_password("eos");
//! assert_eq!(a.guidance, "cred.pw.too_short");
//! assert!(text(a.guidance, Lang::Pl).contains("12"));
//! ```
//!
//! # Adding a key
//!
//! Add it to [`GUIDANCE`] **in byte order** — the table is binary-searched and
//! `guidance_table_is_sorted` fails if it is not — with both languages filled
//! in. `every_emitted_key_resolves` in `lib.rs` fails if an assessor ever
//! returns a key that is not in this table, so a missing translation cannot
//! reach a user as a raw key.

/// Language a message is rendered in.
///
/// Polish is the owner's language and the default for E-OS's own interfaces;
/// English is the fallback and the language of the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// Polish.
    Pl,
    /// English.
    En,
}

/// One message: a stable key and its two renderings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Guidance {
    /// Stable identifier, e.g. `cred.pw.too_short`. Never shown to a user.
    pub key: &'static str,
    /// Polish text.
    pub pl: &'static str,
    /// English text.
    pub en: &'static str,
}

/// Returned by [`text`] when a key is not in [`GUIDANCE`].
///
/// Deliberately not an empty string: a front-end that renders this shows
/// something obviously wrong rather than silently nothing (CLAUDE.md §13, a
/// check that cannot be seen failing is not a check).
pub const MISSING_KEY: &str = "cred.error.missing_key";

/// Every message this crate can emit, sorted by key for binary search.
pub static GUIDANCE: [Guidance; 26] = [
    Guidance {
        key: "cred.advice.length_beats_complexity",
        pl: "Długość liczy się bardziej niż znaki specjalne. Cztery zwykłe słowa są mocniejsze niż jedno słowo z „@” i cyfrą.",
        en: "Length beats complexity. Four ordinary words are stronger than one word with an \"@\" and a digit.",
    },
    Guidance {
        key: "cred.advice.measured_cost",
        pl: "Zmierzone w E-OS: jedno sprawdzenie hasła kosztuje 14,06 ms na jednym rdzeniu, czyli około 71 prób na sekundę. Stąd biorą się podawane czasy.",
        en: "Measured on E-OS: one password check costs 14.06 ms on one core, about 71 guesses per second. That is where the times below come from.",
    },
    Guidance {
        key: "cred.advice.never_reuse",
        pl: "Nie używaj tego hasła nigdzie indziej. Wyciek u kogoś innego staje się wtedy wyciekiem tutaj.",
        en: "Do not reuse this password anywhere else. Someone else's breach then becomes a breach here.",
    },
    Guidance {
        key: "cred.advice.phrase_beats_word",
        pl: "Zdanie jest łatwiejsze do zapamiętania niż hasło i trudniejsze do zgadnięcia.",
        en: "A phrase is easier to remember than a password and harder to guess.",
    },
    Guidance {
        key: "cred.lockout.hard_locked",
        pl: "Konto zablokowane po zbyt wielu nieudanych próbach. Odblokowanie wymaga administratora.",
        en: "Locked after too many failed attempts. An administrator must unlock it.",
    },
    Guidance {
        key: "cred.lockout.locked",
        pl: "Za dużo nieudanych prób. Poczekaj przed kolejną.",
        en: "Too many failed attempts. Wait before trying again.",
    },
    Guidance {
        key: "cred.pin.blocklisted",
        pl: "Ten PIN jest jednym z najczęściej używanych. Wybierz inny.",
        en: "This PIN is one of the most common ones. Choose another.",
    },
    Guidance {
        key: "cred.pin.date_like",
        pl: "Ten PIN wygląda jak data. Daty są zgadywane w pierwszej kolejności.",
        en: "This PIN looks like a date. Dates are guessed first.",
    },
    Guidance {
        key: "cred.pin.low_variety",
        pl: "Ten PIN używa zbyt niewielu różnych cyfr.",
        en: "This PIN uses too few different digits.",
    },
    Guidance {
        key: "cred.pin.not_digits",
        pl: "PIN może zawierać wyłącznie cyfry.",
        en: "A PIN may contain digits only.",
    },
    Guidance {
        key: "cred.pin.ok",
        pl: "PIN przyjęty. Odblokowuje wyłącznie ekran — do hasła, sudo i szyfrowania dysku się nie nadaje.",
        en: "PIN accepted. It unlocks the screen only — never the password, sudo or disk encryption.",
    },
    Guidance {
        key: "cred.pin.repeated",
        pl: "Ten PIN to powtórzenie tej samej cyfry albo tego samego układu.",
        en: "This PIN repeats one digit or one pattern.",
    },
    Guidance {
        key: "cred.pin.sequential",
        pl: "Ten PIN to ciąg kolejnych cyfr.",
        en: "This PIN is a run of consecutive digits.",
    },
    Guidance {
        key: "cred.pin.too_long",
        pl: "PIN może mieć najwyżej 12 cyfr.",
        en: "A PIN may be at most 12 digits.",
    },
    Guidance {
        key: "cred.pin.too_short",
        pl: "PIN musi mieć co najmniej 6 cyfr.",
        en: "A PIN must be at least 6 digits.",
    },
    Guidance {
        key: "cred.pin.unlock_only",
        pl: "PIN odblokowuje tylko ekran. Nie zastępuje hasła i nigdy nie szyfruje dysku — chroni go licznik prób, a nie długość.",
        en: "A PIN unlocks the screen only. It never replaces the password and never encrypts the disk — what protects it is the try counter, not its length.",
    },
    Guidance {
        key: "cred.pw.below_score",
        pl: "To hasło jest za słabe, choć nie łamie żadnej pojedynczej zasady. Dodaj jeszcze jedno lub dwa słowa.",
        en: "This password is too weak, although it breaks no single rule. Add another word or two.",
    },
    Guidance {
        key: "cred.pw.blocklisted",
        // Covers both ways a password reaches the blocklist: being a common
        // password, and being built mostly out of one (`password moje`).
        pl: "To hasło jest jednym z najczęściej używanych albo składa się głównie z takiego hasła. Zostanie zgadnięte od razu.",
        en: "This password is one of the most common ones, or is built mostly from one. It will be guessed immediately.",
    },
    Guidance {
        key: "cred.pw.low_variety",
        pl: "To hasło używa zbyt niewielu różnych znaków.",
        en: "This password uses too few different characters.",
    },
    Guidance {
        key: "cred.pw.ok_fair",
        pl: "Hasło przyjęte. Dłuższe byłoby wyraźnie mocniejsze.",
        en: "Password accepted. A longer one would be markedly stronger.",
    },
    Guidance {
        key: "cred.pw.ok_strong",
        pl: "Mocne hasło.",
        en: "Strong password.",
    },
    Guidance {
        key: "cred.pw.ok_weak",
        pl: "Hasło przyjęte, ale słabe. Dodaj jeszcze kilka słów.",
        en: "Password accepted, but weak. Add a few more words.",
    },
    Guidance {
        key: "cred.pw.repeated",
        pl: "To hasło powtarza ten sam znak albo ten sam fragment.",
        en: "This password repeats one character or one fragment.",
    },
    Guidance {
        key: "cred.pw.sequential",
        pl: "To hasło zawiera ciąg kolejnych znaków, na przykład „abcd” albo „1234”.",
        en: "This password contains a run of consecutive characters, such as \"abcd\" or \"1234\".",
    },
    Guidance {
        key: "cred.pw.too_short",
        pl: "Hasło musi mieć co najmniej 12 znaków.",
        en: "A password must be at least 12 characters.",
    },
    Guidance {
        key: "cred.pw.waived_by_env",
        pl: "Zasady hasła osłabione przez EOS_CREDPOLICY_ALLOW_WEAK. Ten system nie nadaje się do użytku produkcyjnego.",
        en: "Password rules weakened by EOS_CREDPOLICY_ALLOW_WEAK. This system is not fit for production use.",
    },
];

/// The entry for `key`, or `None` if there is none.
pub fn entry(key: &str) -> Option<&'static Guidance> {
    GUIDANCE
        .binary_search_by(|g| g.key.cmp(key))
        .ok()
        .map(|i| &GUIDANCE[i])
}

/// Is `key` a key this crate knows?
pub fn key_exists(key: &str) -> bool {
    entry(key).is_some()
}

/// The text for `key` in `lang`, or [`MISSING_KEY`] if the key is unknown.
pub fn text(key: &str, lang: Lang) -> &'static str {
    match entry(key) {
        Some(g) => match lang {
            Lang::Pl => g.pl,
            Lang::En => g.en,
        },
        None => MISSING_KEY,
    }
}

/// The three standing pieces of advice, in the order a front-end should show
/// them. Not tied to any one assessment — `passwd` and the greeter display
/// these next to the strength meter.
pub const ADVICE_KEYS: [&str; 4] = [
    "cred.advice.length_beats_complexity",
    "cred.advice.phrase_beats_word",
    "cred.advice.never_reuse",
    "cred.advice.measured_cost",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guidance_table_is_sorted() {
        // Unsorted, binary_search stops finding keys and every message becomes
        // MISSING_KEY. Nothing else would notice.
        for pair in GUIDANCE.windows(2) {
            assert!(
                pair[0].key < pair[1].key,
                "guidance out of order at {:?} / {:?}",
                pair[0].key,
                pair[1].key
            );
        }
    }

    #[test]
    fn both_languages_are_filled_in() {
        for g in GUIDANCE.iter() {
            assert!(!g.pl.trim().is_empty(), "{} has no Polish text", g.key);
            assert!(!g.en.trim().is_empty(), "{} has no English text", g.key);
            assert_ne!(g.pl, g.en, "{} is the same string twice", g.key);
        }
    }

    #[test]
    fn keys_share_one_prefix_scheme() {
        for g in GUIDANCE.iter() {
            assert!(
                g.key.starts_with("cred."),
                "{} does not start with cred.",
                g.key
            );
        }
    }

    #[test]
    fn lookup_returns_the_right_language() {
        assert_eq!(text("cred.pw.ok_strong", Lang::En), "Strong password.");
        assert_eq!(text("cred.pw.ok_strong", Lang::Pl), "Mocne hasło.");
    }

    #[test]
    fn unknown_key_is_visible_not_silent() {
        assert_eq!(text("cred.pw.nonexistent", Lang::Pl), MISSING_KEY);
        assert_eq!(text("cred.pw.nonexistent", Lang::En), MISSING_KEY);
        assert!(!key_exists("cred.pw.nonexistent"));
    }

    #[test]
    fn advice_keys_all_resolve() {
        for key in ADVICE_KEYS {
            assert!(key_exists(key), "{key} missing from GUIDANCE");
        }
    }

    #[test]
    fn measured_cost_advice_states_the_measured_number() {
        // If someone re-measures the hash cost, this string and
        // GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE must move together.
        assert!(text("cred.advice.measured_cost", Lang::En).contains("14.06 ms"));
        assert!(text("cred.advice.measured_cost", Lang::Pl).contains("14,06 ms"));
    }
}
