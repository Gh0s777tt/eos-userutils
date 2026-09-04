//! Shape analysis: how much of a password is actually *new* material.
//!
//! This is an **estimator**, not a proof. It answers one question — "how many
//! guesses would a search that knows the obvious patterns need?"
//!
//! # Cost, measured rather than asserted
//!
//! Every loop here is linear or `n log n` in the number of characters, and
//! [`crate::assess_password`] never hands it more than
//! [`crate::MAX_PASSWORD_LEN`] of them, so the cost per keystroke is bounded by
//! a constant no matter what is pasted into the field.
//!
//! That sentence used to read "cheaply enough to run on every keystroke in the
//! greeter" with nothing behind it, and it was **false**: [`minimal_period`]
//! was a naive O(n²) scan and the distinct-character count was a `Vec::contains`
//! loop, so cost grew with the square of the input. Measured on this crate
//! before the fix, in release mode, on `"a".repeat(n - 1) + "b"`:
//!
//! | characters | before | after |
//! |---|---|---|
//! | 1 000 | 814 µs | 21.6 µs |
//! | 4 000 | 11.2 ms | 21.2 µs |
//! | 16 000 | 351 ms | 21.0 µs |
//! | 64 000 | 7.63 s | 20.8 µs |
//! | 1 048 576 | not run — extrapolates to ~34 min | 20.5 µs |
//!
//! Four times the length cost roughly twenty times the work — quadratic, over
//! three decades. Afterwards the cost is flat, because the ceiling is reached
//! before any of it. The fixes are a length ceiling in the caller, an O(n)
//! [`minimal_period`], and a sorted distinct count.
//!
//! The second shape, 64 000 characters drawn from a 20 000-symbol alphabet,
//! exercised the `Vec::contains` distinct count instead of the period scan:
//! **173 ms** before, **54 µs** after.
//!
//! The model has three parts and each one exists because a naive
//! `len * log2(charset)` gets a specific case badly wrong:
//!
//! | naive result | reality | what fixes it here |
//! |---|---|---|
//! | `aaaaaaaaaaaaaaaaaaaa` → 94 bits | one guess | run weights + period cap |
//! | `abcdefghijkl` → 56 bits | one guess | sequence weights |
//! | `abababababab` → 56 bits | ~two guesses | period cap |
//!
//! Nothing here consults a dictionary; that is [`crate::blocklist`]'s job. The
//! two are combined in [`crate::assess_password`].

/// A character that repeats the one before it costs a quarter of a character.
///
/// Not zero: `aa` inside an otherwise good password is not free to guess, it is
/// just cheap. Chosen so `aaaa` (1 + 3 × 0.25 = 1.75 characters) reads as
/// slightly more than a single character and far less than four.
pub(crate) const REPEAT_WEIGHT: f64 = 0.25;

/// A character continuing an ascending or descending run of ±1 costs 0.4.
///
/// Higher than [`REPEAT_WEIGHT`] because the guesser must also know the
/// direction and the starting point, lower than 1.0 because `1234` is not four
/// independent choices.
pub(crate) const SEQUENCE_WEIGHT: f64 = 0.40;

/// A run of four or more identical or ±1-stepping characters is reported as a
/// problem, not merely discounted.
///
/// Four, not three: three-character ascending runs occur inside ordinary words
/// (`worst` contains `rst`), so a threshold of three would flag passwords that
/// are not actually patterned. Measured against the word list in
/// `blocklist_data.rs` this threshold keeps the check quiet on real words.
pub(crate) const RUN_PROBLEM_THRESHOLD: usize = 4;

/// Below this many distinct characters a password of at least
/// [`VARIETY_MIN_LEN`] characters is reported as low-variety.
pub(crate) const MIN_DISTINCT_CHARS: usize = 5;

/// Length at which [`MIN_DISTINCT_CHARS`] starts to apply. A short password is
/// already refused by the length floor, so flagging its variety adds noise.
pub(crate) const VARIETY_MIN_LEN: usize = 6;

/// Everything the estimator measured about one candidate string.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Shape {
    /// Number of `char`s (Unicode scalar values), not bytes.
    pub len: usize,
    /// Number of distinct `char`s.
    pub distinct: usize,
    /// Longest run of the same character, in characters (`aaa` → 3).
    pub max_repeat_run: usize,
    /// Longest run stepping by a constant ±1 (`abcd` → 4, `4321` → 4).
    pub max_sequence_run: usize,
    /// Smallest `p` with `c[i] == c[i - p]` for every `i >= p`; equals `len`
    /// when the string does not repeat at all.
    pub period: usize,
    /// Size of the alphabet a guesser would have to cover, from the character
    /// classes actually present.
    pub charset: f64,
    /// `len` after run, sequence and period discounts. A diagnostic, in
    /// characters; [`Shape::bits`] is the figure policy acts on.
    pub effective_len: f64,
    /// `effective_len * log2(charset)`, or 0.0 for an empty string — except
    /// that a periodic string is additionally capped at
    /// `period * log2(charset) + log2(len / period)` bits, which is the block
    /// plus the repeat count charged at one bit per doubling. So `bits` is not
    /// always `effective_len * log2(charset)`; where they differ, `bits` is the
    /// smaller and the honest one.
    pub bits: f64,
}

/// Measure one string. `chars` is the password as scalar values.
pub(crate) fn analyse(chars: &[char]) -> Shape {
    let len = chars.len();
    if len == 0 {
        return Shape {
            len: 0,
            distinct: 0,
            max_repeat_run: 0,
            max_sequence_run: 0,
            period: 0,
            charset: 1.0,
            effective_len: 0.0,
            bits: 0.0,
        };
    }

    let charset = charset_size(chars);
    let period = minimal_period(chars);

    let mut effective = 0.0_f64;
    let mut max_repeat_run = 1_usize;
    let mut repeat_run = 1_usize;
    let mut max_sequence_run = 1_usize;
    let mut sequence_run = 1_usize;

    for i in 0..len {
        if i == 0 {
            effective += 1.0;
            continue;
        }

        let step = i64::from(chars[i] as u32) - i64::from(chars[i - 1] as u32);

        if step == 0 {
            repeat_run += 1;
            max_repeat_run = max_repeat_run.max(repeat_run);
            sequence_run = 1;
            effective += REPEAT_WEIGHT;
            continue;
        }
        repeat_run = 1;

        if step == 1 || step == -1 {
            let previous_step = if i >= 2 {
                i64::from(chars[i - 1] as u32) - i64::from(chars[i - 2] as u32)
            } else {
                0
            };
            if step == previous_step {
                sequence_run += 1;
                max_sequence_run = max_sequence_run.max(sequence_run);
                effective += SEQUENCE_WEIGHT;
                continue;
            }
            // First ±1 step: the run has started but this character is still a
            // free choice, so it is charged in full.
            sequence_run = 2;
            max_sequence_run = max_sequence_run.max(sequence_run);
            effective += 1.0;
            continue;
        }

        sequence_run = 1;
        effective += 1.0;
    }

    // A string that is a repetition of a shorter block costs the block plus the
    // repeat count, never the full length: `abcabcabc` is `abc` and "three
    // times", not nine independent characters.
    //
    // The cap is applied in BITS, not in characters. Adding `log2(len / period)`
    // to a character count and then multiplying the sum by `log2(charset)`
    // charges `log2(charset)` bits — 4.7 for lowercase — for every doubling of
    // the repeat count, when a doubling is worth exactly one bit. Measured
    // consequence of getting this wrong: `"a" * 128` scored 37.6 bits and was
    // ACCEPTED by the strict policy, while `"a" * 12` scored 17.6 and was
    // refused, so a longer run of one character was treated as stronger. Both
    // are one guess. See `a_longer_run_is_never_stronger_than_a_shorter_one`.
    let charset_bits = charset.log2();
    let mut bits = effective * charset_bits;
    if period < len {
        let block_bits = period as f64 * charset_bits;
        let repeat_bits = (len as f64 / period as f64).log2();
        bits = bits.min(block_bits + repeat_bits);
        // `effective_len` stays in characters and keeps the old, coarser cap:
        // it is a reported diagnostic, and `bits` is the number policy uses.
        effective = effective.min(period as f64 + repeat_bits);
    }

    // Sorted, not `Vec::contains`: the linear scan made this O(n * distinct),
    // which is quadratic for input with many distinct characters. Measured on
    // 64 000 characters drawn from a 20 000-symbol alphabet, one assessment
    // cost 173 ms with `contains` and 54 us without it.
    let mut distinct_seen: Vec<char> = chars.to_vec();
    distinct_seen.sort_unstable();
    distinct_seen.dedup();

    Shape {
        len,
        distinct: distinct_seen.len(),
        max_repeat_run,
        max_sequence_run,
        period,
        charset,
        effective_len: effective,
        bits,
    }
}

/// Alphabet size implied by the character classes present.
///
/// Deliberately coarse. The numbers are the sizes a guesser would enumerate:
/// 26 letters per case, 10 digits, 32 printable ASCII symbols, 1 for the space.
/// Anything outside ASCII contributes a flat 100 — a guesser who has decided to
/// try non-ASCII at all has a very large space to cover, and pretending to know
/// how large would be false precision.
fn charset_size(chars: &[char]) -> f64 {
    let mut size = 0_u32;
    if chars.iter().any(char::is_ascii_lowercase) {
        size += 26;
    }
    if chars.iter().any(char::is_ascii_uppercase) {
        size += 26;
    }
    if chars.iter().any(char::is_ascii_digit) {
        size += 10;
    }
    if chars.contains(&' ') {
        size += 1;
    }
    if chars
        .iter()
        .any(|c| c.is_ascii_graphic() && !c.is_ascii_alphanumeric())
    {
        size += 32;
    }
    if chars.iter().any(|c| !c.is_ascii()) {
        size += 100;
    }
    f64::from(size.max(1))
}

/// Smallest `p >= 1` such that `chars[i] == chars[i - p]` for every `i >= p`.
///
/// Returns `chars.len()` when there is no shorter period. Periods that do not
/// divide the length count: `ababa` has period 2.
///
/// Linear time, via the Knuth–Morris–Pratt failure function: the smallest
/// period of a string is `len - fail[len - 1]`, where `fail[i]` is the length
/// of the longest proper prefix of `chars[..=i]` that is also its suffix. The
/// previous implementation tried every `p` in turn and compared the whole
/// suffix, which is O(n²) whenever the comparisons do not fail early —
/// `"a".repeat(n - 1) + "b"` is the worst case and cost 7.63 s at 64 000
/// characters. `naive_and_kmp_agree` below is the differential test that this
/// rewrite did not change a single answer.
pub(crate) fn minimal_period(chars: &[char]) -> usize {
    let len = chars.len();
    if len == 0 {
        return 1;
    }

    let mut fail = vec![0_usize; len];
    let mut k = 0_usize;
    for i in 1..len {
        while k > 0 && chars[i] != chars[k] {
            k = fail[k - 1];
        }
        if chars[i] == chars[k] {
            k += 1;
        }
        fail[i] = k;
    }

    len - fail[len - 1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(s: &str) -> Shape {
        analyse(&s.chars().collect::<Vec<char>>())
    }

    #[test]
    fn empty_string_has_no_bits() {
        let s = shape("");
        assert_eq!(s.len, 0);
        assert_eq!(s.bits, 0.0);
    }

    #[test]
    fn twenty_identical_characters_cost_about_one_character() {
        // The case the naive model gets wrong: 20 * log2(26) would be 94 bits.
        let s = shape("aaaaaaaaaaaaaaaaaaaa");
        assert_eq!(s.period, 1);
        assert_eq!(s.max_repeat_run, 20);
        assert!(s.effective_len < 6.0, "effective_len = {}", s.effective_len);
        assert!(s.bits < 30.0, "bits = {}", s.bits);
    }

    #[test]
    fn alphabet_run_is_discounted() {
        let s = shape("abcdefghijkl");
        assert_eq!(s.max_sequence_run, 12);
        assert!(s.effective_len < 7.0, "effective_len = {}", s.effective_len);
    }

    #[test]
    fn descending_digits_are_a_sequence_too() {
        let s = shape("987654");
        assert_eq!(s.max_sequence_run, 6);
    }

    #[test]
    fn repeated_block_is_capped_by_its_period() {
        let s = shape("abcabcabcabc");
        assert_eq!(s.period, 3);
        assert!(s.effective_len < 6.0, "effective_len = {}", s.effective_len);
    }

    #[test]
    fn non_dividing_period_is_found() {
        assert_eq!(minimal_period(&"ababa".chars().collect::<Vec<char>>()), 2);
    }

    /// The definition, written out literally and slowly. Only a test lives
    /// here; `minimal_period` is the O(n) version that ships.
    fn naive_minimal_period(chars: &[char]) -> usize {
        let len = chars.len();
        for p in 1..len {
            if chars[p..].iter().zip(chars.iter()).all(|(a, b)| a == b) {
                return p;
            }
        }
        len.max(1)
    }

    #[test]
    fn naive_and_kmp_agree() {
        // Level 4, the counter-control: the fast implementation is only a fix
        // if it returns exactly what the slow one returned. Exhaustive over
        // every string of length <= 8 on a 3-symbol alphabet (9841 strings),
        // which covers every period that divides and every period that does
        // not, plus the shapes the estimator actually cares about.
        let alphabet = ['a', 'b', 'c'];
        let mut checked = 0_u32;
        for len in 0..=8_usize {
            let mut idx = vec![0_usize; len];
            loop {
                let s: Vec<char> = idx.iter().map(|&i| alphabet[i]).collect();
                assert_eq!(
                    minimal_period(&s),
                    naive_minimal_period(&s),
                    "disagreement on {s:?}"
                );
                checked += 1;

                let mut pos = len;
                loop {
                    if pos == 0 {
                        break;
                    }
                    pos -= 1;
                    idx[pos] += 1;
                    if idx[pos] < alphabet.len() {
                        break;
                    }
                    idx[pos] = 0;
                    if pos == 0 {
                        pos = usize::MAX;
                        break;
                    }
                }
                if pos == usize::MAX || len == 0 {
                    break;
                }
            }
        }
        assert_eq!(checked, 9841, "the sweep did not cover what it claims");

        // And the shapes that made the old version quadratic.
        for n in [1_usize, 2, 3, 16, 64, 257] {
            let mut s: Vec<char> = "a".repeat(n.saturating_sub(1)).chars().collect();
            s.push('b');
            assert_eq!(minimal_period(&s), naive_minimal_period(&s), "a^{n}b");
        }
    }

    #[test]
    fn an_empty_slice_has_period_one() {
        assert_eq!(minimal_period(&[]), 1);
    }

    #[test]
    fn a_longer_run_is_never_stronger_than_a_shorter_one() {
        // Repeating one character adds no search space: "a" * 256 is the same
        // single guess as "a" * 12. Before the period cap was moved into bits,
        // this grew -- 12 -> 17.6 bits, 128 -> 37.6 bits, 256 -> 42.3 bits --
        // and at 128 characters it crossed the score-2 threshold, so the strict
        // policy ACCEPTED a password of 128 identical characters.
        let mut previous = f64::MAX;
        for n in [12_usize, 20, 32, 64, 128, 200, 256] {
            let s = shape(&"a".repeat(n));
            assert_eq!(s.period, 1);
            // 14 bits, not 36: the score-2 threshold is 36 bits, and the whole
            // defect was that a long run of one character crossed it. At 256
            // characters the honest figure is log2(26) + log2(256) = 12.7.
            assert!(
                s.bits < 14.0,
                "{n} identical characters scored {:.1} bits",
                s.bits
            );
            // Monotone non-increasing is too strong (one more character is one
            // more bit of "how long is the run"), but the growth must be in the
            // repeat count, not in the alphabet.
            assert!(
                s.bits <= previous || s.bits - previous < 1.01,
                "{n} identical characters jumped from {previous:.1} to {:.1} bits",
                s.bits
            );
            previous = s.bits;
        }
    }

    #[test]
    fn a_doubling_of_a_repeated_block_costs_one_bit() {
        // The dimensional check, stated directly: doubling the repeat count of
        // a periodic string adds one bit, not log2(charset) of them.
        let four = shape(&"abc".repeat(4));
        let eight = shape(&"abc".repeat(8));
        let delta = eight.bits - four.bits;
        assert!(
            (0.99..1.01).contains(&delta),
            "doubling the repeats changed bits by {delta:.3}, expected 1.0"
        );
    }

    #[test]
    fn unpatterned_string_has_period_equal_to_length() {
        let s = shape("xkq7wm2p");
        assert_eq!(s.period, s.len);
        assert_eq!(s.effective_len, 8.0);
    }

    #[test]
    fn charset_grows_with_character_classes() {
        assert_eq!(shape("abcd").charset, 26.0);
        assert_eq!(shape("abcD").charset, 52.0);
        assert_eq!(shape("abcD1").charset, 62.0);
        assert_eq!(shape("abcD1!").charset, 94.0);
        assert_eq!(shape("abcD1! ").charset, 95.0);
    }

    #[test]
    fn non_ascii_widens_the_charset() {
        assert!(shape("zażółć").charset >= 126.0);
    }

    #[test]
    fn distinct_counts_scalar_values_not_bytes() {
        let s = shape("żżż");
        assert_eq!(s.len, 3);
        assert_eq!(s.distinct, 1);
    }

    #[test]
    fn bits_grow_with_length_for_unpatterned_input() {
        let short = shape("xkq7wm2p");
        let long = shape("xkq7wm2ptz9lr4bv");
        assert!(long.bits > short.bits, "{} !> {}", long.bits, short.bits);
    }

    #[test]
    fn first_step_of_a_run_is_charged_in_full() {
        // "ab" is two free characters; only the third character of a run is cheap.
        assert_eq!(shape("ab").effective_len, 2.0);
        assert!((shape("abc").effective_len - 2.4).abs() < 1e-9);
    }
}
