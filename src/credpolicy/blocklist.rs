//! Common-password lookup over two compiled-in tables.
//!
//! # Why the tables are compiled in and not read from a file
//!
//! ROADMAP `R-602b` sketched "a compressed list in the image under
//! `/usr/share/eos/weak-passwords`". A file has a failure mode a table does
//! not: it can be absent, truncated or unreadable, and the natural way to
//! handle that in a login path is to carry on without a blocklist — a security
//! control that disappears quietly is worse than one that costs space
//! (CLAUDE.md §5.5, fail-closed). Compiled in, the only way to lose the
//! blocklist is to edit the source.
//!
//! The price is measured, not waved away: 9916 + 145 entries cost **~300 KiB**
//! of read-only data (65 KiB of strings, 235 KiB of pointer table on a 64-bit
//! target). If that ever matters more than the failure mode above, the fix is a
//! denser encoding — a shared prefix trie or a perfect hash — not a file.
//!
//! # Why normalisation matters more than the table
//!
//! Measured on the corpus in `blocklist_data`: **24 of 9916** entries
//! are twelve characters or longer. The twelve-character floor already refuses
//! the other 9892 before the blocklist is ever consulted. What the blocklist
//! adds is reach through decoration — `P@ssw0rd!2026` is fourteen characters,
//! passes the floor, and is `password`.
//!
//! So every candidate is looked up in several forms:
//!
//! | step | `P@ssw0rd!2026` becomes |
//! |---|---|
//! | lower-case | `p@ssw0rd!2026` |
//! | de-accent (`ł`→`l`, `ó`→`o`, …) | `p@ssw0rd!2026` |
//! | strip leading/trailing non-letters | `p@ssw0rd` |
//! | de-leet (`0`→`o`, `@`→`a`, `3`→`e`, …) | `password` ← hit |
//! | minimal period (`passwordpassword`) | `password` |
//! | words joined (`correct horse battery staple`) | `correcthorsebatterystaple` |
//!
//! Each form is searched in both tables. A hit in any form is a hit.
//!
//! # Separators were the hole in exactly that argument
//!
//! The paragraph above rests the whole justification for shipping 300 KiB of
//! tables on "reach through decoration". Until this was fixed, the one form of
//! decoration **not** handled was the most likely one: a space. `password
//! password`, `password-password`, `qwerty warszawa` and `letmein please` were
//! all accepted, because normalisation only ever looked at the string as a
//! whole and never inside a separator — and the test for a doubled word only
//! tried the separator-free spelling, so nothing went red.
//!
//! [`contains`] therefore also splits a password into words and asks whether
//! common words *dominate* it. "Dominate", not "appear": an ordinary passphrase
//! contains ordinary words, and refusing on one hit would refuse `coffee table
//! green window`. The rule and the measurements behind its two constants are in
//! `is_dominated_by_common_words`.

use crate::credpolicy::blocklist_data::BLOCKLIST;
use crate::credpolicy::blocklist_supplement::SUPPLEMENT;

/// Shortest entry in either table; shorter candidates are not looked up.
///
/// The corpus contains three-character entries, so two-character fragments left
/// over from stripping decoration would only produce noise.
const MIN_CANDIDATE_LEN: usize = 3;

/// Upper bound on generated candidate forms, and therefore on table lookups.
///
/// This bounds **lookups only**. It used to claim it stopped "a pathological
/// input turning one keystroke into unbounded work in the greeter", and that
/// was false: the work was in building each candidate and in the period scan
/// above the lookups, both of which grew with the input, not with this number.
/// What actually bounds the work is [`crate::credpolicy::MAX_PASSWORD_LEN`], applied to
/// this module's input in [`candidates`].
const MAX_CANDIDATES: usize = 12;

/// A blocklisted word must cover at least this share of a password's
/// alphanumeric characters before coverage alone refuses it.
///
/// See [`is_dominated_by_common_words`] for the measurements that chose 60.
const COVERAGE_PERCENT: usize = 60;

/// Coverage only refuses passwords built from at most this many distinct words.
///
/// Three or more distinct words is a passphrase, and a passphrase is refused
/// only when **every** word is common, never on coverage. Without this gate,
/// `coffee table green window` — 77 % covered, four independent words — would
/// be refused, which would push users towards shorter passwords.
const DOMINATED_MAX_TOKENS: usize = 2;

/// Is this password, in any of its normalised forms, a known common password?
///
/// ```
/// assert!(userutils::credpolicy::blocklist::contains("password"));
/// assert!(userutils::credpolicy::blocklist::contains("P@ssw0rd!2026"));
/// assert!(!userutils::credpolicy::blocklist::contains("xkq7wm2ptz9lr4bv6nc8"));
/// ```
pub fn contains(password: &str) -> bool {
    candidates(password).iter().any(|c| in_any_table(c)) || is_dominated_by_common_words(password)
}

/// Is this password, once separators are removed, essentially a common word?
///
/// # The gap this closes
///
/// Normalisation never looked *inside* a separator, so any blocklisted word
/// plus a space or a hyphen walked straight through — and adding a space is the
/// single most likely response to a twelve-character floor. Measured on this
/// crate before the fix, every one of these was `Accept`:
///
/// ```text
/// password password   password-password   password moje
/// qwerty warszawa     letmein please      haslo haslo haslo haslo
/// ```
///
/// # Why coverage, and not "any word is blocklisted"
///
/// Refusing on any single blocklisted token would refuse ordinary passphrases:
/// measured against the shipped tables, `coffee table green window` has three
/// of its four words in the corpus and `the quick brown fox jumps` has one. So
/// a password is refused here only when it is **dominated**:
///
/// 1. every word of at least [`MIN_CANDIDATE_LEN`] characters is common, or
/// 2. it is at most [`DOMINATED_MAX_TOKENS`] distinct words *and* common words
///    cover at least [`COVERAGE_PERCENT`] % of its alphanumeric characters.
///
/// Measured separation, with the shipped tables (`coverage`, `distinct words`):
///
/// | password | coverage | words | verdict |
/// |---|---|---|---|
/// | `password password` | 100 % | 1 | refused, rule 1 |
/// | `password moje` | 66 % | 2 | refused, rule 2 |
/// | `qwerty warszawa` | 100 % | 2 | refused, rule 1 |
/// | `monkey dragon shadow master` | 100 % | 4 | refused, rule 1 |
/// | `coffee table green window` | 77 % | 4 | **accepted** |
/// | `purple monkey dishwasher` | 54 % | 3 | **accepted** |
/// | `burza nad jeziorem w maju` | 0 % | 4 | **accepted** |
/// | `password poziomka` | 50 % | 2 | **accepted** |
///
/// The last row is the boundary and is stated rather than hidden: at 50 %
/// coverage `password poziomka` passes. Lowering the threshold to catch it
/// would start refusing legitimate two-word Polish phrases such as
/// `password zielona` at 53 %, so the line sits where the measurements put it.
///
/// `correct horse battery staple` is *not* caught here — 48 % coverage, four
/// words — but is refused anyway, because [`candidates`] also looks up the
/// concatenation of the words, and `correcthorsebatterystaple` is in the
/// supplement table.
fn is_dominated_by_common_words(password: &str) -> bool {
    // Two token sets, because leet substitutions are themselves separators.
    // `P@ssw0rd P@ssw0rd` splits on `@` into `p` + `ssw0rd`, which matches
    // nothing; de-leeting first gives `password password`, which matches. The
    // reverse case needs the raw form: `password!password` splits on `!` into
    // two words, while de-leeting turns it into one word `passwordipassword`.
    let plain = alnum_tokens(password);
    let deleeted = alnum_tokens(&deleet(password));
    dominated(&plain) || dominated(&deleeted)
}

/// The dominance rule applied to one already-tokenised form.
fn dominated(tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return false;
    }

    // Short tokens are not looked up (they would be noise), but they still
    // count towards the total a common word has to cover.
    let total: usize = tokens.iter().map(|t| t.chars().count()).sum();
    let long: Vec<&String> = tokens
        .iter()
        .filter(|t| t.chars().count() >= MIN_CANDIDATE_LEN)
        .collect();
    if long.is_empty() {
        return false;
    }

    // `in_any_table` and not `contains`: this function is reached *from*
    // `contains`, and a single-token password would recurse forever.
    let blocked: Vec<bool> = long
        .iter()
        .map(|t| in_any_table(t) || in_any_table(&deleet(t)))
        .collect();

    if blocked.iter().all(|b| *b) {
        return true;
    }

    let mut distinct: Vec<&&String> = long.iter().collect();
    distinct.sort();
    distinct.dedup();
    if distinct.len() > DOMINATED_MAX_TOKENS {
        return false;
    }

    let covered: usize = long
        .iter()
        .zip(&blocked)
        .filter(|(_, is_blocked)| **is_blocked)
        .map(|(t, _)| t.chars().count())
        .sum();

    covered * 100 >= COVERAGE_PERCENT * total
}

/// The alphanumeric words of a password, lower-cased and de-accented.
///
/// Splitting on runs of non-alphanumeric characters is what looks *inside* a
/// separator. Input is capped at [`crate::credpolicy::MAX_PASSWORD_LEN`] before any of the
/// allocating work, so this is bounded no matter what is pasted in.
pub fn alnum_tokens(password: &str) -> Vec<String> {
    let capped: String = password.chars().take(crate::credpolicy::MAX_PASSWORD_LEN).collect();
    deaccent(&capped.to_lowercase())
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

/// Rank of the password in the corpus table, 1 being the most common.
///
/// Returns the best (lowest) rank across all normalised forms, or `None` when
/// no form is in the corpus table. A password matched only by the authored E-OS
/// supplement returns `None` even though [`contains`] is `true`: the supplement
/// carries no measured frequency, and inventing one would be a claim this crate
/// cannot support.
pub fn rank(password: &str) -> Option<u16> {
    candidates(password)
        .iter()
        .filter_map(|c| corpus_rank(c))
        .min()
}

/// The normalised forms [`contains`] looks up, in the order they are generated.
///
/// Exposed so a user interface can explain *why* a password was refused
/// ("this is `password` with decoration") instead of only that it was.
pub fn candidates(password: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(MAX_CANDIDATES);

    // Cap first, before `to_lowercase` allocates: this is the bound that makes
    // the module's cost per keystroke constant (see MAX_CANDIDATES).
    let capped: String = password.chars().take(crate::credpolicy::MAX_PASSWORD_LEN).collect();

    let lower = capped.to_lowercase();
    push(&mut out, lower.clone());

    let plain = deaccent(&lower);
    push(&mut out, plain.clone());

    let stripped = strip_decoration(&plain).to_string();
    push(&mut out, stripped.clone());

    push(&mut out, deleet(&stripped));
    push(&mut out, deleet(&plain));

    // `passwordpassword` is `password` twice, and neither the floor nor a
    // dictionary lookup of the whole string catches it.
    let chars: Vec<char> = stripped.chars().collect();
    let period = crate::credpolicy::entropy::minimal_period(&chars);
    if period < chars.len() {
        let block: String = chars[..period].iter().collect();
        push(&mut out, deleet(&block));
        push(&mut out, block);
    }

    // The words with their separators removed. This is what turns
    // `correct horse battery staple` into `correcthorsebatterystaple`, which is
    // in the supplement table under the spelling it was authored for — before
    // this form existed, that entry did not catch the canonical spelling of the
    // password it was written for.
    let joined: String = alnum_tokens(&capped).concat();
    push(&mut out, deleet(&joined));
    push(&mut out, joined);

    out
}

/// Add a candidate if it is long enough, not empty and not already present.
fn push(out: &mut Vec<String>, candidate: String) {
    if out.len() >= MAX_CANDIDATES
        || candidate.chars().count() < MIN_CANDIDATE_LEN
        || out.contains(&candidate)
    {
        return;
    }
    out.push(candidate);
}

/// Look a single already-normalised form up in both tables.
fn in_any_table(candidate: &str) -> bool {
    corpus_rank(candidate).is_some() || SUPPLEMENT.binary_search(&candidate).is_ok()
}

/// Look a single already-normalised form up in the ranked corpus table.
fn corpus_rank(candidate: &str) -> Option<u16> {
    BLOCKLIST
        .binary_search_by(|(word, _)| (*word).cmp(candidate))
        .ok()
        .map(|i| BLOCKLIST[i].1)
}

/// Fold Polish and common Latin-1 diacritics onto ASCII.
///
/// Both tables are ASCII, so `hasło` has to become `haslo` to be found. Only
/// the letters that actually occur in Polish plus the widespread Latin-1 vowels
/// are mapped; anything else is left alone and simply will not match.
fn deaccent(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'ą' => 'a',
            'ć' => 'c',
            'ę' => 'e',
            'ł' => 'l',
            'ń' => 'n',
            'ó' => 'o',
            'ś' => 's',
            'ź' | 'ż' => 'z',
            'á' | 'à' | 'â' | 'ä' | 'å' | 'ã' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' => 'i',
            'ò' | 'ô' | 'ö' | 'õ' => 'o',
            'ú' | 'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            'ñ' => 'n',
            'ý' | 'ÿ' => 'y',
            other => other,
        })
        .collect()
}

/// Undo the common letter-for-symbol substitutions.
///
/// `1` maps to `i` rather than `l` because `adm1n` and `l3tm31n` are the shapes
/// this actually has to catch. Applied *after* decoration is stripped, so a
/// trailing `password1` has already lost its `1` and does not become
/// `passwordi`.
fn deleet(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | '!' | '|' => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' => 't',
            '8' => 'b',
            '+' => 't',
            other => other,
        })
        .collect()
}

/// Trim leading and trailing characters that are not ASCII letters.
///
/// This is what turns `password1234`, `!!password!!` and `2026password` into
/// `password`. Interior punctuation is left alone — removing it would make
/// `correct-horse-battery` collapse into something the tables might contain by
/// accident.
fn strip_decoration(s: &str) -> &str {
    s.trim_matches(|c: char| !c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_table_is_sorted_and_unique() {
        // Binary search silently stops matching on an unsorted table, so this
        // is the gate that keeps the generator honest.
        for pair in BLOCKLIST.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "corpus table out of order at {:?} / {:?}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn supplement_table_is_sorted_and_unique() {
        for pair in SUPPLEMENT.windows(2) {
            assert!(
                pair[0] < pair[1],
                "supplement out of order at {:?} / {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn tables_contain_only_lowercase_ascii() {
        for (word, _) in BLOCKLIST.iter() {
            assert!(
                word.is_ascii() && *word == word.to_lowercase(),
                "corpus entry {word:?} is not lower-case ASCII"
            );
        }
        for word in SUPPLEMENT.iter() {
            assert!(
                word.is_ascii() && *word == word.to_lowercase(),
                "supplement entry {word:?} is not lower-case ASCII"
            );
        }
    }

    #[test]
    fn the_classics_are_blocked() {
        for word in ["password", "qwerty", "1234", "123456", "letmein", "monkey"] {
            assert!(contains(word), "{word:?} should be blocklisted");
        }
    }

    #[test]
    fn eos_harness_password_is_blocked() {
        // ROADMAP R-602e: the install-smoke harness sets PASSWORD = "eos".
        assert!(contains("eos"));
        assert!(contains("EOS"));
    }

    #[test]
    fn case_is_ignored() {
        assert!(contains("PASSWORD"));
        assert!(contains("PaSsWoRd"));
    }

    #[test]
    fn decoration_is_stripped() {
        assert!(contains("password1234"));
        assert!(contains("!!password!!"));
        assert!(contains("2026password2026"));
    }

    #[test]
    fn leet_is_undone() {
        assert!(contains("p@ssw0rd"));
        assert!(contains("P@ssw0rd!2026"));
        assert!(contains("l3tm31n"));
    }

    #[test]
    fn polish_diacritics_are_folded() {
        assert!(contains("hasło"));
        assert!(contains("HASŁO123"));
    }

    #[test]
    fn a_doubled_common_word_is_blocked() {
        // Sixteen characters, passes the floor, and is one dictionary word.
        assert!(contains("passwordpassword"));
        assert!(contains("haslohaslo"));
    }

    #[test]
    fn a_separator_does_not_defeat_the_blocklist() {
        // The gap that made the module doc's justification false: every one of
        // these was Accept before the token rule existed. The separator-free
        // spellings were already refused, which is exactly why the old test
        // could not see the hole.
        for pw in [
            "password password",
            "password-password",
            "password_password",
            "password.password",
            "password moje",
            "qwerty warszawa",
            "letmein please",
            "haslo haslo haslo haslo",
            "P@ssw0rd P@ssw0rd",
        ] {
            assert!(contains(pw), "{pw:?} should be blocklisted");
        }
    }

    #[test]
    fn the_supplement_entry_catches_its_canonical_spelling() {
        // `correcthorsebatterystaple` was authored for this password, and did
        // not catch the way anyone actually writes it. 48 % coverage over four
        // words, so the token rule does NOT fire; the joined form is what does.
        for pw in [
            "correct horse battery staple",
            "correct-horse-battery-staple",
            "Correct Horse Battery Staple",
            "correcthorsebatterystaple",
        ] {
            assert!(contains(pw), "{pw:?} should be blocklisted");
        }
    }

    #[test]
    fn an_ordinary_passphrase_survives_the_token_rule() {
        // The negative side of the same rule, and the reason it is coverage and
        // not "any word is common". Measured against the shipped tables:
        // `coffee table green window` is 77 % covered by three corpus words and
        // must still be accepted; refusing it would push users to shorter
        // passwords. If a future table edit makes one of these refuse, that is
        // a real regression and this test is where it shows.
        for pw in [
            "coffee table green window",
            "purple monkey dishwasher",
            "the quick brown fox jumps",
            "poziomka zielona kot",
            "poziomka zielona kotwica",
            "burza nad jeziorem w maju",
            "rower most kawa lampa",
            "zielona herbata o poranku",
            "xkq7wm2ptz9lr4bv6nc8",
        ] {
            assert!(!contains(pw), "{pw:?} should NOT be blocklisted");
        }
    }

    #[test]
    fn a_phrase_of_only_common_words_is_refused() {
        // Rule 1: four independent words, but every one of them is in the
        // corpus, so the phrase is worth ~53 bits against a wordlist attack
        // while the character model would score it 4.
        assert!(contains("monkey dragon shadow master"));
    }

    #[test]
    fn the_coverage_boundary_is_where_the_documentation_says() {
        // The rule has a stated boundary; an undocumented drift in either
        // direction should go red here rather than quietly change policy.
        assert!(contains("password moje"), "66 % over two words must refuse");
        assert!(
            !contains("password poziomka"),
            "50 % over two words must accept"
        );
        assert!(
            !contains("password zielona"),
            "53 % over two words must accept"
        );
    }

    #[test]
    fn a_password_of_only_separators_does_not_panic_or_refuse() {
        // `long` is empty here, and "every word is common" over an empty set
        // would be vacuously true -- which would refuse every symbol-only
        // password. The guard for that is measured, not assumed.
        for pw in ["!!!!!!!!!!!!", "----", "    ", "@#$%^&*()_+{}"] {
            assert!(!contains(pw), "{pw:?} should not be blocklisted");
        }
    }

    #[test]
    fn a_strong_passphrase_is_not_blocked() {
        assert!(!contains("xkq7wm2ptz9lr4bv6nc8"));
        assert!(!contains("poziomka zielona kotwica"));
    }

    #[test]
    fn rank_reports_the_corpus_position() {
        assert_eq!(rank("123456"), Some(1));
        assert_eq!(rank("password"), Some(2));
        assert_eq!(rank("xkq7wm2ptz9lr4bv6nc8"), None);
    }

    #[test]
    fn supplement_only_matches_have_no_rank_but_are_still_blocked() {
        // Polish-locale entries the English corpus cannot contain. `zaq12wsx`
        // deliberately is NOT the example: it turns out to sit at corpus rank
        // 771, which is why the supplement claims no ranks of its own.
        for word in ["kochamcie", "warszawa", "haslo123"] {
            assert!(contains(word), "{word} should be blocklisted");
            assert_eq!(rank(word), None, "{word} should carry no corpus rank");
        }
    }

    #[test]
    fn a_supplement_entry_can_also_be_in_the_corpus() {
        // Overlap between the two tables is harmless: both are searched, and
        // the corpus rank still wins.
        assert!(contains("zaq12wsx"));
        assert_eq!(rank("zaq12wsx"), Some(771));
    }

    #[test]
    fn candidates_are_bounded_and_deduplicated() {
        let c = candidates("password");
        assert!(c.len() <= MAX_CANDIDATES);
        let mut sorted = c.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), c.len(), "duplicate candidate forms: {c:?}");
    }

    #[test]
    fn short_fragments_are_not_looked_up() {
        // Stripping "1234" of decoration leaves nothing; the raw form still hits.
        assert!(candidates("1234")
            .iter()
            .all(|c| c.chars().count() >= MIN_CANDIDATE_LEN));
        assert!(contains("1234"));
    }

    #[test]
    fn empty_and_whitespace_do_not_panic() {
        assert!(!contains(""));
        assert!(!contains("   "));
        assert_eq!(rank(""), None);
    }
}
