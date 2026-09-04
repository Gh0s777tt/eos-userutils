//! PIN assessment — **screen unlock only**.
//!
//! # Policy, decided by the owner on 2026-09-03 (Q1)
//!
//! A PIN unlocks the screen. It is **never** accepted for `sudo`, for `passwd`,
//! for `su`, for `eos-control`'s elevation, and **never** as the full-disk
//! encryption secret. This module cannot enforce that on its own — a caller
//! could call it from anywhere — so the rule is stated here, restated in
//! `docs/design.md`, and carried in the `cred.pin.unlock_only` guidance string
//! that every PIN enrolment screen must display.
//!
//! # Why the rule exists, in measured numbers
//!
//! At the image's argon2id parameters (`m=19456, t=2, p=1`) one hash costs
//! 14.06 ms on one core of the build container (ROADMAP §6.6, two runs: 15.3
//! and 14.06 ms). That is ~71 guesses per second, so exhausting the whole
//! keyspace offline costs:
//!
//! | digits | keyspace | offline, one core |
//! |---|---|---|
//! | 4 | 10 000 | 2.3 min |
//! | 6 | 1 000 000 | 3.9 h |
//! | 8 | 100 000 000 | 16 days |
//!
//! Divide by the number of cores the attacker has. A six-digit PIN is not
//! strong; it is *survivable*, and only because [`crate::counter::TryCounter`]
//! stops the attempts long before the keyspace runs out. That is why the floor
//! is six digits and not four, and why a PIN may not protect anything an
//! attacker can copy and attack offline.
//!
//! # Entropy is reported as keyspace, not discounted
//!
//! [`PinAssessment::entropy_bits`] is `digits * log2(10)` — the raw keyspace.
//! Patterns are reported as [`PinProblem`]s instead of being subtracted,
//! because for a PIN the defence is the try counter, not the entropy, and a
//! "corrected" entropy figure would invite comparing a PIN with a password on
//! one axis where they do not belong.

use std::time::Duration;

use crate::entropy::minimal_period;
use crate::GuessRate;

/// Fewest digits a PIN may have.
///
/// Six, decided 2026-09-03 (Q4). Four would be 2.3 min of offline work.
pub const MIN_PIN_DIGITS: usize = 6;

/// Most digits accepted, so a stray paste cannot become a PIN.
pub const MAX_PIN_DIGITS: usize = 12;

/// Fewest distinct digits before a PIN is called low-variety.
const MIN_DISTINCT_DIGITS: usize = 3;

/// Length of a ±1 run that is reported as sequential.
const SEQUENCE_RUN_THRESHOLD: usize = 4;

/// Well-known PINs that no structural rule above catches.
///
/// Runs, repeats and periodic patterns are found by [`assess_pin`] itself, so
/// this table holds only the shapes that are common because of where they sit
/// on a keypad (`159753` is a diagonal, `789456` is two rows) or because they
/// are a remembered pattern (`112233`, `123321`).
///
/// [UNVERIFIED]: authored from well-known keypad patterns, not measured from a
/// corpus of real PINs — no permissively licensed one was available offline.
const PIN_BLOCKLIST: [&str; 16] = [
    "102030", "112233", "123321", "123654", "147258", "147852", "159357", "159753", "258369",
    "369258", "456123", "741852", "753159", "789456", "852456", "987456",
];

/// What is wrong with a PIN.
///
/// Separate from [`crate::Problem`] on purpose: `NotDigits` and `DateLike` are
/// meaningless for a password, and a shared enum would force every password
/// caller to match arms that can never occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinProblem {
    /// Contains something other than an ASCII digit.
    NotDigits,
    /// Shorter than `min` digits.
    TooShort {
        /// The floor that was applied, [`MIN_PIN_DIGITS`].
        min: usize,
    },
    /// Longer than [`MAX_PIN_DIGITS`].
    TooLong {
        /// The ceiling that was applied.
        max: usize,
    },
    /// A known-common PIN, or one whose whole shape is a run or a repeat.
    Blocklisted,
    /// One digit repeated, or a repeating block such as `121212`.
    RepeatedDigits,
    /// A run of consecutive digits, ascending or descending.
    Sequential,
    /// Too few distinct digits.
    LowVariety,
    /// Reads as a date — `DDMMYY`, `MMDDYY` or `YYMMDD`. Birthdays are the
    /// first thing an attacker who knows the owner tries.
    DateLike,
}

/// The result of [`assess_pin`].
#[derive(Debug, Clone, PartialEq)]
pub struct PinAssessment {
    /// Number of digits (0 when the input is not all digits).
    pub digits: usize,
    /// Keyspace size in bits, `digits * log2(10)`. See the module docs: this is
    /// not discounted for patterns.
    pub entropy_bits: f64,
    /// Time to try **every** PIN of this length at
    /// [`GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE`], the measured E-OS cost.
    ///
    /// Full exhaustion, not the expected half — for a keyspace this small the
    /// honest number to show is the one that says "and then it is over".
    /// Use [`PinAssessment::time_to_exhaust_at`] for any other rate.
    pub time_to_exhaust: Duration,
    /// Everything wrong with it; empty means acceptable.
    pub problems: Vec<PinProblem>,
    /// i18n key for the message to show, resolved through
    /// [`crate::guidance::text`].
    pub guidance: &'static str,
}

impl PinAssessment {
    /// May this PIN be enrolled? True only when there are no problems at all.
    ///
    /// There is no environment escape here. `EOS_CREDPOLICY_ALLOW_WEAK` relaxes
    /// password rules; it does not touch PINs, because a PIN's whole safety
    /// argument is the size of the keyspace against a capped number of tries.
    pub fn is_acceptable(&self) -> bool {
        self.problems.is_empty()
    }

    /// Time to try every PIN of this length at `rate`.
    ///
    /// Saturates at [`Duration::MAX`] rather than panicking; at
    /// [`MAX_PIN_DIGITS`] digits and a very slow rate the product does not fit.
    pub fn time_to_exhaust_at(&self, rate: GuessRate) -> Duration {
        rate.time_for_guesses(self.keyspace())
    }

    /// Number of PINs of this length: `10^digits`, or 0 if it is not a PIN.
    pub fn keyspace(&self) -> f64 {
        if self.digits == 0 {
            0.0
        } else {
            10_f64.powi(self.digits as i32)
        }
    }
}

/// Assess `pin` at the measured E-OS hash cost.
///
/// ```
/// use eos_credpolicy::{assess_pin, pin::PinProblem};
/// assert!(!assess_pin("123456").is_acceptable());
/// assert!(assess_pin("12345").problems.contains(&PinProblem::TooShort { min: 6 }));
/// assert!(assess_pin("284915").is_acceptable());
/// ```
pub fn assess_pin(pin: &str) -> PinAssessment {
    assess_pin_at(pin, GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE)
}

/// Assess `pin`, computing [`PinAssessment::time_to_exhaust`] at `rate`.
///
/// Pass the rate this system actually measured — `GuessRate::from_hash_millis`
/// with the cost of one verify, multiplied by the cores an attacker would have.
pub fn assess_pin_at(pin: &str, rate: GuessRate) -> PinAssessment {
    let chars: Vec<char> = pin.chars().collect();
    let mut problems: Vec<PinProblem> = Vec::new();

    let all_digits = !chars.is_empty() && chars.iter().all(char::is_ascii_digit);
    if !all_digits {
        problems.push(PinProblem::NotDigits);
    }

    let digits = if all_digits { chars.len() } else { 0 };

    if chars.len() < MIN_PIN_DIGITS {
        problems.push(PinProblem::TooShort {
            min: MIN_PIN_DIGITS,
        });
    } else if chars.len() > MAX_PIN_DIGITS {
        problems.push(PinProblem::TooLong {
            max: MAX_PIN_DIGITS,
        });
    }

    // Structural analysis only for PINs that could still be accepted. An
    // over-long PIN is already refused by `TooLong`, and `pin_guidance` shows
    // `cred.pin.too_long` ahead of anything found here, so scanning a megabyte
    // paste for keypad patterns is work that cannot change the outcome — on a
    // pre-authentication path. It also stops the refusal reading "this PIN is a
    // run of consecutive digits" when the real answer is "that is not a PIN".
    if all_digits && chars.len() <= MAX_PIN_DIGITS {
        let period = minimal_period(&chars);
        let repeats = period < chars.len() && chars.len() / period >= 2;
        let all_same = period == 1;
        let sequence_run = longest_step_run(&chars);
        let whole_is_a_run = sequence_run == chars.len() && chars.len() >= MIN_PIN_DIGITS;

        if all_same || repeats {
            problems.push(PinProblem::RepeatedDigits);
        }
        if sequence_run >= SEQUENCE_RUN_THRESHOLD {
            problems.push(PinProblem::Sequential);
        }

        let mut distinct: Vec<char> = Vec::with_capacity(chars.len());
        for &c in &chars {
            if !distinct.contains(&c) {
                distinct.push(c);
            }
        }
        if distinct.len() < MIN_DISTINCT_DIGITS && chars.len() >= MIN_PIN_DIGITS {
            problems.push(PinProblem::LowVariety);
        }

        if all_same || whole_is_a_run || repeats || PIN_BLOCKLIST.binary_search(&pin).is_ok() {
            problems.push(PinProblem::Blocklisted);
        }

        if looks_like_date(&chars) {
            problems.push(PinProblem::DateLike);
        }
    }

    let entropy_bits = if digits == 0 {
        0.0
    } else {
        digits as f64 * 10_f64.log2()
    };

    let keyspace = if digits == 0 {
        0.0
    } else {
        10_f64.powi(digits as i32)
    };

    let guidance = pin_guidance(&problems);

    PinAssessment {
        digits,
        entropy_bits,
        time_to_exhaust: rate.time_for_guesses(keyspace),
        problems,
        guidance,
    }
}

/// Longest run of a constant ±1 step, in characters (`1234` → 4).
fn longest_step_run(chars: &[char]) -> usize {
    if chars.len() < 2 {
        return chars.len();
    }
    let mut best = 1_usize;
    let mut run = 1_usize;
    let mut previous_step = 0_i64;
    for i in 1..chars.len() {
        let step = i64::from(chars[i] as u32) - i64::from(chars[i - 1] as u32);
        if step == 1 || step == -1 {
            run = if run >= 2 && step == previous_step {
                run + 1
            } else {
                2
            };
            best = best.max(run);
        } else {
            run = 1;
        }
        previous_step = step;
    }
    best
}

/// Does this read as a six-digit date?
///
/// Checks `DDMMYY`, `MMDDYY` and `YYMMDD`. Only six digits: at other lengths
/// the reading is ambiguous enough that flagging would be guesswork, and
/// guesswork in a refusal message is worse than silence.
fn looks_like_date(chars: &[char]) -> bool {
    if chars.len() != 6 {
        return false;
    }
    let n = |a: usize, b: usize| -> u32 {
        let mut v = 0;
        for &c in &chars[a..b] {
            v = v * 10 + c.to_digit(10).unwrap_or(0);
        }
        v
    };
    let (first, middle, last) = (n(0, 2), n(2, 4), n(4, 6));

    let day_month = |d: u32, m: u32| (1..=31).contains(&d) && (1..=12).contains(&m);

    // DDMMYY or MMDDYY
    if day_month(first, middle) || day_month(middle, first) {
        return true;
    }
    // YYMMDD
    if (1..=12).contains(&middle) && (1..=31).contains(&last) {
        return true;
    }
    false
}

/// Pick the message key for a PIN, worst problem first.
fn pin_guidance(problems: &[PinProblem]) -> &'static str {
    if problems.iter().any(|p| matches!(p, PinProblem::NotDigits)) {
        return "cred.pin.not_digits";
    }
    // One arm per direction. These were folded together and both returned
    // `cred.pin.too_short`, so a thirteen-digit PIN was told, in both shipped
    // languages, that it was too short.
    if problems
        .iter()
        .any(|p| matches!(p, PinProblem::TooShort { .. }))
    {
        return "cred.pin.too_short";
    }
    if problems
        .iter()
        .any(|p| matches!(p, PinProblem::TooLong { .. }))
    {
        return "cred.pin.too_long";
    }
    if problems.contains(&PinProblem::Blocklisted) {
        return "cred.pin.blocklisted";
    }
    if problems.contains(&PinProblem::Sequential) {
        return "cred.pin.sequential";
    }
    if problems.contains(&PinProblem::RepeatedDigits) {
        return "cred.pin.repeated";
    }
    if problems.contains(&PinProblem::DateLike) {
        return "cred.pin.date_like";
    }
    if problems.contains(&PinProblem::LowVariety) {
        return "cred.pin.low_variety";
    }
    "cred.pin.ok"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_blocklist_is_sorted_for_binary_search() {
        for pair in PIN_BLOCKLIST.windows(2) {
            assert!(pair[0] < pair[1], "{} !< {}", pair[0], pair[1]);
        }
    }

    #[test]
    fn the_canonical_bad_pin_is_rejected() {
        let a = assess_pin("123456");
        assert!(!a.is_acceptable());
        assert!(a.problems.contains(&PinProblem::Sequential));
        assert!(a.problems.contains(&PinProblem::Blocklisted));
        assert_eq!(a.guidance, "cred.pin.blocklisted");
    }

    #[test]
    fn all_zeroes_is_rejected() {
        let a = assess_pin("000000");
        assert!(!a.is_acceptable());
        assert!(a.problems.contains(&PinProblem::RepeatedDigits));
        assert!(a.problems.contains(&PinProblem::Blocklisted));
        assert!(a.problems.contains(&PinProblem::LowVariety));
    }

    #[test]
    fn five_digits_is_too_short() {
        let a = assess_pin("28491");
        assert!(a.problems.contains(&PinProblem::TooShort { min: 6 }));
        assert_eq!(a.guidance, "cred.pin.too_short");
    }

    #[test]
    fn thirteen_digits_is_too_long() {
        let a = assess_pin("2849153729481");
        assert!(a.problems.contains(&PinProblem::TooLong { max: 12 }));
        assert_eq!(a.guidance, "cred.pin.too_long");
        assert!(!a.is_acceptable());
    }

    #[test]
    fn an_oversized_paste_is_refused_promptly_and_says_why() {
        // The PIN counterpart of the password length ceiling. This costs 16.6 ms
        // at one mebibyte today and was quadratic before `minimal_period` became
        // O(n); the structural scan is now skipped entirely for input that
        // `TooLong` has already refused.
        let pin: String = "1234567890".chars().cycle().take(1024 * 1024).collect();
        let started = std::time::Instant::now();
        let a = assess_pin(&pin);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(200),
            "1 MiB PIN took {elapsed:?}"
        );
        assert!(!a.is_acceptable());
        assert_eq!(a.guidance, "cred.pin.too_long");
        // The refusal names the length, and does not also claim the paste is a
        // keypad pattern -- those checks no longer run on input this long.
        assert_eq!(a.problems, vec![PinProblem::TooLong { max: 12 }]);
        // The digit count stays truthful even though the scan was skipped.
        assert_eq!(a.digits, 1024 * 1024);
    }

    #[test]
    fn letters_are_not_a_pin() {
        let a = assess_pin("12a456");
        assert!(a.problems.contains(&PinProblem::NotDigits));
        assert_eq!(a.digits, 0);
        assert_eq!(a.guidance, "cred.pin.not_digits");
        assert_eq!(a.entropy_bits, 0.0);
    }

    #[test]
    fn an_empty_pin_is_not_digits_and_does_not_panic() {
        let a = assess_pin("");
        assert!(a.problems.contains(&PinProblem::NotDigits));
        assert!(!a.is_acceptable());
        assert_eq!(a.keyspace(), 0.0);
    }

    #[test]
    fn a_repeating_pattern_is_rejected() {
        for pin in ["121212", "123123", "696969"] {
            let a = assess_pin(pin);
            assert!(!a.is_acceptable(), "{pin} should be rejected");
            assert!(a.problems.contains(&PinProblem::RepeatedDigits));
        }
    }

    #[test]
    fn descending_run_is_rejected() {
        let a = assess_pin("987654");
        assert!(a.problems.contains(&PinProblem::Sequential));
        assert!(a.problems.contains(&PinProblem::Blocklisted));
    }

    #[test]
    fn keypad_patterns_from_the_table_are_rejected() {
        for pin in ["159753", "789456", "112233"] {
            assert!(
                assess_pin(pin).problems.contains(&PinProblem::Blocklisted),
                "{pin} should be blocklisted"
            );
        }
    }

    #[test]
    fn a_birthday_shaped_pin_is_rejected() {
        let a = assess_pin("150385");
        assert!(a.problems.contains(&PinProblem::DateLike));
    }

    #[test]
    fn a_good_pin_is_accepted() {
        let a = assess_pin("284915");
        assert!(a.is_acceptable(), "problems: {:?}", a.problems);
        assert_eq!(a.digits, 6);
        assert_eq!(a.guidance, "cred.pin.ok");
    }

    #[test]
    fn entropy_is_the_keyspace_not_a_discount() {
        // "111111" and "284915" have the same keyspace; only the problems differ.
        let weak = assess_pin("111111");
        let good = assess_pin("284915");
        assert!((weak.entropy_bits - good.entropy_bits).abs() < 1e-9);
        assert!(!weak.is_acceptable());
        assert!(good.is_acceptable());
    }

    #[test]
    fn six_digits_take_about_four_hours_at_the_measured_rate() {
        // ROADMAP §6.6 quotes 4.2 h at 15.3 ms/hash; this crate pins the faster
        // of the two measured runs (14.06 ms), which gives 3.9 h. Both are the
        // same measurement, read conservatively.
        let a = assess_pin("284915");
        let hours = a.time_to_exhaust.as_secs_f64() / 3600.0;
        assert!((3.8..4.0).contains(&hours), "hours = {hours}");
    }

    #[test]
    fn a_faster_attacker_needs_less_time() {
        let a = assess_pin("284915");
        let one_core = a.time_to_exhaust_at(GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE);
        let eight_cores =
            a.time_to_exhaust_at(GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE.with_cores(8));
        assert!(eight_cores < one_core);
        let ratio = one_core.as_secs_f64() / eight_cores.as_secs_f64();
        assert!((7.9..8.1).contains(&ratio), "ratio = {ratio}");
    }

    #[test]
    fn longer_pins_take_longer_to_exhaust() {
        let mut previous = Duration::ZERO;
        for pin in ["284915", "2849153", "28491537", "284915372"] {
            let t = assess_pin(pin).time_to_exhaust;
            assert!(t > previous, "{pin}: {t:?} !> {previous:?}");
            previous = t;
        }
    }

    #[test]
    fn every_pin_guidance_key_resolves_and_is_the_right_one() {
        // This gate used to assert only that the key EXISTS, which is precisely
        // the CLAUDE.md 5.4 failure mode: a key that exists and is WRONG passes
        // a presence check. It did -- `TooLong` returned `cred.pin.too_short`,
        // so a thirteen-digit PIN was told it was too short, in both languages.
        // Naming the expected key per input is what makes that visible.
        use crate::guidance::{key_exists, text, Lang};
        let cases: [(&str, &str); 11] = [
            ("", "cred.pin.not_digits"),
            ("12a456", "cred.pin.not_digits"),
            ("12345", "cred.pin.too_short"),
            ("2849153729481", "cred.pin.too_long"),
            ("123456", "cred.pin.blocklisted"),
            ("000000", "cred.pin.blocklisted"),
            ("121212", "cred.pin.blocklisted"),
            ("987654", "cred.pin.blocklisted"),
            ("150385", "cred.pin.date_like"),
            ("284915", "cred.pin.ok"),
            ("159753", "cred.pin.blocklisted"),
        ];
        for (pin, expected) in cases {
            let key = assess_pin(pin).guidance;
            assert!(key_exists(key), "{pin:?} produced unknown key {key}");
            assert_eq!(key, expected, "{pin:?} got the wrong guidance key");
            // And the rendered text must not be the missing-key marker.
            assert_ne!(text(key, Lang::Pl), crate::guidance::MISSING_KEY);
            assert_ne!(text(key, Lang::En), crate::guidance::MISSING_KEY);
        }
    }

    #[test]
    fn a_too_long_pin_is_not_told_it_is_too_short() {
        use crate::guidance::{text, Lang};
        let a = assess_pin("2849153729481");
        assert!(a.problems.contains(&PinProblem::TooLong { max: 12 }));
        assert_eq!(a.guidance, "cred.pin.too_long");
        // The rendered strings, because the key being right is only half of it:
        // both languages have to name the ceiling, not the floor.
        assert!(
            text(a.guidance, Lang::Pl).contains("12"),
            "pl text is wrong"
        );
        assert!(
            text(a.guidance, Lang::En).contains("12"),
            "en text is wrong"
        );
        assert!(!text(a.guidance, Lang::En).contains("at least"));
    }

    #[test]
    fn the_unlock_only_message_exists_for_enrolment_screens() {
        use crate::guidance::{key_exists, text, Lang};
        assert!(key_exists("cred.pin.unlock_only"));
        assert!(text("cred.pin.unlock_only", Lang::En).contains("screen"));
        assert!(text("cred.pin.unlock_only", Lang::Pl).contains("ekran"));
    }
}
