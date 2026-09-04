//! `eos-credpolicy` — one credential policy for all five E-OS authentication
//! paths.
//!
//! Vendored into the `eos-userutils` fork as `src/credpolicy/` and exposed
//! there as a `lib` target (owner's decision Q3, 2026-09-03), so `passwd`,
//! `login`, the `orblogin` greeter, the sudo daemon and `eos-control` cannot
//! disagree about what a good password is. Today they do disagree: the only
//! judgement in the tree is the literal `"password"`, refused in two places
//! with no shared code (`orblogin/main.rs:164-179`, `login.rs:195-243`).
//!
//! # What it decides
//!
//! | rule | value | decided |
//! |---|---|---|
//! | password length floor | 12 characters | Q4, 2026-09-03 |
//! | PIN length floor | 6 digits | Q4, 2026-09-03 |
//! | PIN scope | screen unlock only — never `sudo`, `passwd` or FDE | Q1 |
//! | PIN try counter | per-account file, root may delete | Q5 |
//!
//! # The rate is the caller's, and E-OS has measured it
//!
//! Every "time to crack" here is a division: guesses ÷ guesses-per-second. The
//! second number is a property of *this system's* hashing cost, so the caller
//! supplies it and the crate never invents one.
//!
//! Measured on one core of the E-OS build container (ROADMAP §6.6, #27):
//!
//! | path | parameters | per hash | guesses/s |
//! |---|---|---|---|
//! | image build (`installer`, `rust-argon2 3.0.0`) | argon2id `m=19456, t=2, p=1` | 14.06 ms (second run 15.3 ms) | **71.1** |
//! | running system (`redox_users 0.4.6` → `rust-argon2 0.8.3`) | argon2i `m=4096, t=3` | 4.03 ms | **248.1** |
//!
//! [`GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE`] is the default and pins the
//! **faster** of the two argon2id runs. That is deliberate: when two
//! measurements of the same thing disagree, the honest one to show a user is
//! the one that gives the attacker the advantage. It also means the numbers
//! here are slightly smaller than the ones in ROADMAP §6.6, which quotes the
//! 15.3 ms run — same measurement, read conservatively.
//!
//! The runtime path being 3.5× cheaper than the image path is issue #27,
//! tracked as `R-602g`. When that is fixed, `EOS_RUNTIME_ARGON2I_ONE_CORE`
//! stops being the right rate for anything and should be deleted.
//!
//! # Fail-closed, with one escape that cannot reach the blocklist
//!
//! [`PasswordPolicy::default`] refuses. `EOS_CREDPOLICY_ALLOW_WEAK=1`, read
//! **only** by [`PasswordPolicy::from_env`], waives the length floor and the
//! score floor — and never the blocklist. `eos` is in the blocklist, so the
//! install-smoke harness (`install-smoke-drive.py:27`, `PASSWORD = "eos"`)
//! cannot be talked into passing by an environment variable; its password has
//! to change in the same merge request that wires this in (`R-602e`).
//!
//! **Privileged callers must not use `from_env`.** `login`, `passwd`,
//! `orblogin`, the sudo daemon and `eos-control` run with an environment an
//! attacker may influence; they call [`PasswordPolicy::strict`].
//!
//! # Example
//!
//! ```
//! use eos_credpolicy::{assess_password, GuessRate, PasswordPolicy, Verdict};
//! use eos_credpolicy::guidance::{text, Lang};
//!
//! let a = assess_password("poziomka zielona kotwica");
//! assert_eq!(a.score, 4);
//! assert!(matches!(PasswordPolicy::strict().verdict(&a), Verdict::Accept));
//!
//! let bad = assess_password("eos");
//! assert_eq!(bad.score, 0);
//! assert_eq!(text(bad.guidance, Lang::En), "A password must be at least 12 characters.");
//!
//! // Same password, an attacker with 16 cores.
//! let rate = GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE.with_cores(16);
//! let _ = a.time_to_crack_at(rate);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::time::Duration;

mod blocklist_data;
mod blocklist_supplement;
mod entropy;

pub mod blocklist;
pub mod counter;
pub mod guidance;
pub mod pin;

pub use pin::{assess_pin, assess_pin_at, PinAssessment, PinProblem, MIN_PIN_DIGITS};

/// Fewest characters a password may have.
///
/// Twelve, decided 2026-09-03 (Q4). Measured justification: of the 9916 entries
/// in the corpus blocklist, **24** are twelve characters or longer — the floor
/// alone refuses 99.8% of the most common passwords before any lookup happens.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Most characters of a password that are ever analysed.
///
/// Not a limit on what a user may *choose* — a longer password is accepted, it
/// is simply judged on its first 256 characters. It is a bound on the work one
/// keystroke can cause, and it is the password-side counterpart of
/// [`pin::MAX_PIN_DIGITS`], which the PIN path has had from the start.
///
/// # Why a ceiling exists at all
///
/// [`assess_password`] runs on a pre-authentication path, in the greeter, on
/// every keystroke. Without a ceiling, one paste is unbounded work in a process
/// no one has authenticated to yet. Measured before this ceiling existed, in
/// release mode, on `"a".repeat(n - 1) + "b"`: 64 000 characters cost
/// **7.63 s** of CPU, and the cost grew with the square of the length.
///
/// # Why truncating is safe, and in which direction it errs
///
/// Judging a prefix can only **under**-estimate: appending characters to a
/// strong prefix never makes a password weaker, and a weak prefix stays weak
/// and is still refused. The blocklist keeps its reach too, because every
/// entry in both tables is far shorter than 256 characters, and a repeated
/// block survives truncation as long as the block is shorter than the ceiling.
/// So the rule this ceiling can break is "a 300-character password whose first
/// 256 characters are strong is accepted" — which is the correct answer.
pub const MAX_PASSWORD_LEN: usize = 256;

/// Environment variable that relaxes the password floors. Never the blocklist.
pub const ALLOW_WEAK_ENV: &str = "EOS_CREDPOLICY_ALLOW_WEAK";

/// A guessing rate, in guesses per second.
///
/// Construct it from what this system measured, not from a constant someone
/// remembered. The crate ships the two rates E-OS has actually measured; both
/// name the measurement in their documentation.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct GuessRate(f64);

impl GuessRate {
    /// Passwords hashed at image-build time: argon2id `m=19456, t=2, p=1` via
    /// `rust-argon2 3.0.0`, measured at **14.06 ms** per hash on one core of
    /// the build container (ROADMAP §6.6). The default rate for this crate.
    pub const EOS_IMAGE_ARGON2ID_ONE_CORE: GuessRate = GuessRate::from_hash_millis(14.06);

    /// Passwords set in the running system: argon2i `m=4096, t=3` via
    /// `redox_users 0.4.6` → `rust-argon2 0.8.3`, measured at **4.03 ms** per
    /// hash on one core (issue #27).
    ///
    /// This is the weaker of the two paths and is a defect, not a design —
    /// `R-602g`. Delete this constant when the defect is fixed.
    pub const EOS_RUNTIME_ARGON2I_ONE_CORE: GuessRate = GuessRate::from_hash_millis(4.03);

    /// A rate straight from a measured per-hash cost in milliseconds.
    ///
    /// A non-positive or non-finite cost yields a rate of one guess per second
    /// rather than an infinity that would make every password look unbreakable.
    pub const fn from_hash_millis(millis: f64) -> Self {
        if millis > 0.0 && millis.is_finite() {
            GuessRate(1000.0 / millis)
        } else {
            GuessRate(1.0)
        }
    }

    /// A rate given directly. Values that are not positive and finite become 1.
    pub const fn from_guesses_per_second(rate: f64) -> Self {
        if rate > 0.0 && rate.is_finite() {
            GuessRate(rate)
        } else {
            GuessRate(1.0)
        }
    }

    /// The same hashing cost on `cores` cores. Linear on purpose — memory-hard
    /// hashing does not scale perfectly, so this over-estimates the attacker,
    /// which is the direction to be wrong in.
    pub fn with_cores(self, cores: u32) -> Self {
        GuessRate::from_guesses_per_second(self.0 * f64::from(cores.max(1)))
    }

    /// Guesses per second.
    pub fn as_guesses_per_second(self) -> f64 {
        self.0
    }

    /// How long `guesses` take at this rate.
    ///
    /// Saturates at [`Duration::MAX`]: above roughly 71 bits the answer stops
    /// fitting in a `Duration`, and a front-end should render `Duration::MAX`
    /// as "longer than any attacker will wait", not as a number.
    pub fn time_for_guesses(self, guesses: f64) -> Duration {
        if !guesses.is_finite() || guesses <= 0.0 {
            return Duration::ZERO;
        }
        Duration::try_from_secs_f64(guesses / self.0).unwrap_or(Duration::MAX)
    }
}

/// Something wrong with a password.
///
/// `TooShort` and `Blocklisted` are hard: they always refuse.
/// `RepeatedChars`, `Sequential` and `LowVariety` are soft — they lower
/// [`Assessment::score`] and choose the guidance message, and refuse only
/// through [`PasswordPolicy::min_score`].
///
/// `BelowScore` is neither, and is the one variant [`assess_password`] never
/// produces: it exists only relative to a policy, so it appears only in a
/// [`Verdict`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// Fewer than `min` characters.
    TooShort {
        /// The floor that was applied, [`MIN_PASSWORD_LEN`].
        min: usize,
    },
    /// Found in [`blocklist`], in some normalised form.
    Blocklisted,
    /// Contains a run of four or more identical characters, or is a short block
    /// repeated (`abcabcabc`).
    RepeatedChars,
    /// Contains a run of four or more consecutive characters (`abcd`, `4321`).
    Sequential,
    /// Uses fewer than five distinct characters.
    LowVariety,
    /// The password broke no single rule but did not reach the policy's
    /// [`PasswordPolicy::min_score`].
    ///
    /// Produced by [`PasswordPolicy::verdict`], never by [`assess_password`]:
    /// the assessment measures and the policy decides, so a problem that exists
    /// only relative to a policy cannot be part of the measurement. It carries
    /// both numbers so a front-end can say which threshold was missed and by
    /// how much.
    ///
    /// This variant exists because `verdict` used to push a
    /// [`Problem::LowVariety`] the assessment had never reported, as filler
    /// whenever the score alone decided the outcome — putting a problem the
    /// password does not have into an audit field.
    BelowScore {
        /// The score the policy required.
        min: u8,
        /// The score the assessment gave.
        got: u8,
    },
}

/// The result of [`assess_password`].
#[derive(Debug, Clone, PartialEq)]
pub struct Assessment {
    /// 0 (refused) to 4 (strong).
    ///
    /// 0 whenever a hard problem is present, so a caller that only looks at the
    /// score still refuses the right things. A soft problem caps it at 2.
    pub score: u8,
    /// Estimated bits of search space, after the discounts in
    /// the `entropy` module. An estimate, not a proof — see that module.
    pub entropy_bits: f64,
    /// Expected time to find this password at
    /// [`GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE`], the measured E-OS cost.
    ///
    /// "Expected", so half the keyspace. Use [`Assessment::time_to_crack_at`]
    /// for a caller-supplied rate — that is the one to use when the caller has
    /// measured its own hashing cost or knows the attacker's core count.
    pub time_to_crack: Duration,
    /// Everything wrong with it, in a stable order: hard problems first.
    pub problems: Vec<Problem>,
    /// i18n key for the message to show, resolved through
    /// [`guidance::text`]. Never prose.
    pub guidance: &'static str,
}

impl Assessment {
    /// Expected guesses to find this password: half the search space.
    pub fn expected_guesses(&self) -> f64 {
        if self.entropy_bits <= 0.0 {
            return 1.0;
        }
        2_f64.powf(self.entropy_bits - 1.0)
    }

    /// Expected time to find this password at `rate`.
    pub fn time_to_crack_at(&self, rate: GuessRate) -> Duration {
        rate.time_for_guesses(self.expected_guesses())
    }

    /// Is a hard problem present? Hard problems refuse under every policy.
    pub fn has_hard_problem(&self) -> bool {
        self.problems
            .iter()
            .any(|p| matches!(p, Problem::TooShort { .. } | Problem::Blocklisted))
    }
}

/// What a policy decided about an [`Assessment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Accept it.
    Accept,
    /// Accept it only because [`ALLOW_WEAK_ENV`] is set.
    ///
    /// The caller **must** show `cred.pw.waived_by_env` — an escape nobody sees
    /// used is an escape that becomes permanent.
    AcceptRelaxed {
        /// The problems that were waived.
        waived: Vec<Problem>,
        /// Guidance key to render: `cred.pw.waived_by_env`.
        guidance: &'static str,
    },
    /// Refuse, for these reasons.
    Reject {
        /// Why.
        problems: Vec<Problem>,
        /// Guidance key to render for the refusal.
        ///
        /// Usually [`Assessment::guidance`], but not always: a password that
        /// breaks no rule and merely misses [`PasswordPolicy::min_score`] has
        /// an assessment guidance of `cred.pw.ok_weak`, whose text begins
        /// "Password accepted" — which would be shown next to a refusal. That
        /// case renders `cred.pw.below_score` instead. Reachable: measured on
        /// `aabbccddeeff`, score 1, no problems.
        guidance: &'static str,
    },
}

impl Verdict {
    /// Was the password accepted, relaxed or not?
    pub fn is_accepted(&self) -> bool {
        matches!(self, Verdict::Accept | Verdict::AcceptRelaxed { .. })
    }
}

/// The rules a caller applies to an [`Assessment`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Minimum length. [`MIN_PASSWORD_LEN`] unless relaxed.
    pub min_len: usize,
    /// Minimum [`Assessment::score`]. 2 unless relaxed.
    pub min_score: u8,
    /// True when [`ALLOW_WEAK_ENV`] relaxed this policy. There is no way to set
    /// it without the environment variable.
    pub relaxed_by_env: bool,
}

impl Default for PasswordPolicy {
    /// The same as [`PasswordPolicy::strict`]. `default_is_strict` fails if a
    /// later edit makes the default read the environment.
    fn default() -> Self {
        Self::strict()
    }
}

impl PasswordPolicy {
    /// The shipped policy: 12 characters, score 2, no escapes.
    ///
    /// Every privileged caller uses this. It reads nothing from the
    /// environment, so it cannot be weakened by whoever starts the process.
    pub const fn strict() -> Self {
        Self {
            min_len: MIN_PASSWORD_LEN,
            min_score: 2,
            relaxed_by_env: false,
        }
    }

    /// [`PasswordPolicy::strict`], unless [`ALLOW_WEAK_ENV`] is exactly `1`.
    ///
    /// For build tooling and recovery images. **Not** for `login`, `passwd`,
    /// `orblogin`, the sudo daemon or `eos-control`: those run with an
    /// environment an attacker may control.
    ///
    /// Even when relaxed, the blocklist still refuses. That is the one rule
    /// with no escape hatch, and it is what keeps the harness password `eos`
    /// out of the image.
    pub fn from_env() -> Self {
        match std::env::var(ALLOW_WEAK_ENV) {
            Ok(v) if v == "1" => Self {
                min_len: 1,
                min_score: 0,
                relaxed_by_env: true,
            },
            _ => Self::strict(),
        }
    }

    /// Apply this policy to an assessment.
    pub fn verdict(&self, assessment: &Assessment) -> Verdict {
        // No policy, and no environment variable, waives the blocklist.
        if assessment.problems.contains(&Problem::Blocklisted) {
            return Verdict::Reject {
                problems: assessment.problems.clone(),
                guidance: assessment.guidance,
            };
        }

        let too_short = assessment
            .problems
            .iter()
            .any(|p| matches!(p, Problem::TooShort { .. }));
        let under_score = assessment.score < self.min_score;

        if !too_short && !under_score {
            return Verdict::Accept;
        }

        // The score shortfall is a real, derived problem, so it is reported as
        // one. Nothing here invents a problem the assessment did not measure:
        // every other entry is copied from `assessment.problems`.
        let below_score = Problem::BelowScore {
            min: self.min_score,
            got: assessment.score,
        };

        if self.relaxed_by_env {
            let mut waived: Vec<Problem> = assessment
                .problems
                .iter()
                .filter(|p| matches!(p, Problem::TooShort { .. }))
                .cloned()
                .collect();
            if under_score {
                waived.push(below_score);
            }
            return Verdict::AcceptRelaxed {
                waived,
                guidance: "cred.pw.waived_by_env",
            };
        }

        let mut problems = assessment.problems.clone();
        // `cred.pw.ok_weak` reads "Password accepted, but weak" -- correct for
        // an assessment, wrong next to a refusal.
        let guidance = if assessment.problems.is_empty() {
            "cred.pw.below_score"
        } else {
            assessment.guidance
        };
        if under_score {
            problems.push(below_score);
        }
        Verdict::Reject { problems, guidance }
    }
}

/// Assess `password` at the measured E-OS hash cost.
///
/// The length floor is always [`MIN_PASSWORD_LEN`]: the assessment measures,
/// [`PasswordPolicy`] decides. That split is why the environment escape lives
/// in exactly one place and cannot quietly change what a score means.
///
/// ```
/// let a = eos_credpolicy::assess_password("password");
/// assert_eq!(a.score, 0);
/// assert!(a.problems.contains(&eos_credpolicy::Problem::Blocklisted));
/// ```
pub fn assess_password(password: &str) -> Assessment {
    assess_password_at(password, GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE)
}

/// Assess `password`, computing [`Assessment::time_to_crack`] at `rate`.
pub fn assess_password_at(password: &str, rate: GuessRate) -> Assessment {
    // `take` is lazy, so a one-megabyte paste is never decoded past the
    // ceiling: this is O(MAX_PASSWORD_LEN), not O(password.len()). Anything
    // below that reads the whole password, which is the common case and cheap.
    let chars: Vec<char> = password.chars().take(MAX_PASSWORD_LEN).collect();
    let shape = entropy::analyse(&chars);

    let mut problems: Vec<Problem> = Vec::new();

    // Hard problems first, so `problems[0]` is the one worth showing.
    // `chars` is capped, but MAX_PASSWORD_LEN > MIN_PASSWORD_LEN, so a capped
    // password is never mistaken for a short one.
    if chars.len() < MIN_PASSWORD_LEN {
        problems.push(Problem::TooShort {
            min: MIN_PASSWORD_LEN,
        });
    }
    // The capped form, not the raw one: `blocklist` bounds its own input as
    // well, but passing the full string would decode it a second time.
    let capped: String = chars.iter().collect();
    if blocklist::contains(&capped) {
        problems.push(Problem::Blocklisted);
    }

    let repeats_a_block = shape.period < shape.len && shape.len / shape.period >= 2;
    if shape.max_repeat_run >= entropy::RUN_PROBLEM_THRESHOLD || repeats_a_block {
        problems.push(Problem::RepeatedChars);
    }
    if shape.max_sequence_run >= entropy::RUN_PROBLEM_THRESHOLD {
        problems.push(Problem::Sequential);
    }
    if shape.len >= entropy::VARIETY_MIN_LEN && shape.distinct < entropy::MIN_DISTINCT_CHARS {
        problems.push(Problem::LowVariety);
    }

    let score = score_for(&problems, shape.bits);
    let guidance = password_guidance(&problems, score);

    Assessment {
        score,
        entropy_bits: shape.bits,
        time_to_crack: rate.time_for_guesses(expected_guesses(shape.bits)),
        problems,
        guidance,
    }
}

/// Half the search space, floored at one guess.
fn expected_guesses(bits: f64) -> f64 {
    if bits <= 0.0 {
        return 1.0;
    }
    2_f64.powf(bits - 1.0)
}

/// Map estimated bits and problems onto 0..=4.
///
/// The thresholds are round numbers chosen to line up with the floor: a
/// 12-character all-lowercase password is 56 bits and lands on 3 — acceptable,
/// visibly not the best it could be.
fn score_for(problems: &[Problem], bits: f64) -> u8 {
    let hard = problems
        .iter()
        .any(|p| matches!(p, Problem::TooShort { .. } | Problem::Blocklisted));
    if hard {
        return 0;
    }

    let base = if bits < 28.0 {
        0
    } else if bits < 36.0 {
        1
    } else if bits < 50.0 {
        2
    } else if bits < 70.0 {
        3
    } else {
        4
    };

    let soft = !problems.is_empty();
    if soft {
        base.min(2)
    } else {
        base
    }
}

/// Pick the message key, worst problem first, else the score.
fn password_guidance(problems: &[Problem], score: u8) -> &'static str {
    if problems
        .iter()
        .any(|p| matches!(p, Problem::TooShort { .. }))
    {
        return "cred.pw.too_short";
    }
    if problems.contains(&Problem::Blocklisted) {
        return "cred.pw.blocklisted";
    }
    if problems.contains(&Problem::RepeatedChars) {
        return "cred.pw.repeated";
    }
    if problems.contains(&Problem::Sequential) {
        return "cred.pw.sequential";
    }
    if problems.contains(&Problem::LowVariety) {
        return "cred.pw.low_variety";
    }
    match score {
        4 => "cred.pw.ok_strong",
        3 => "cred.pw.ok_fair",
        _ => "cred.pw.ok_weak",
    }
}

/// Turn a [`Verdict`] into the lines a caller should print, in order.
///
/// WHY THIS LIVES IN THE LIBRARY AND NOT IN `passwd`. The binaries of this crate cannot be built
/// on a developer host at all -- `libredox` has no macOS target -- so anything placed in
/// `src/bin/` is unreachable by `cargo test` and provable only by building a Redox image. Moving
/// the DECISION and its wording here leaves the binary a thin caller (assess, verdict, print,
/// exit) and puts the part worth testing where `credpolicy-hostcheck` already runs it.
///
/// The rendering is the same for every caller by construction, which is what `R-602f` asks for:
/// `passwd`, the greeter and the installer cannot drift apart in what they tell a person, because
/// they do not each write it.
///
/// Returns `(lines, accepted)`. `accepted` is false only for [`Verdict::Reject`]; a relaxed
/// acceptance still returns lines, and the caller must print them -- an escape nobody sees used is
/// an escape that becomes permanent.
pub fn render_verdict(verdict: &Verdict, lang: guidance::Lang) -> (Vec<String>, bool) {
    match verdict {
        Verdict::Accept => (Vec::new(), true),
        Verdict::AcceptRelaxed {
            waived,
            guidance: key,
        } => {
            let mut lines = vec![guidance::text(key, lang).to_string()];
            lines.extend(waived.iter().map(describe_problem));
            (lines, true)
        }
        Verdict::Reject {
            problems,
            guidance: key,
        } => {
            let mut lines = vec![guidance::text(key, lang).to_string()];
            lines.extend(problems.iter().map(describe_problem));
            (lines, false)
        }
    }
}

/// One short line per problem. Deliberately not `Debug`: a person reading `TooShort { min: 12 }`
/// learns the rule exists but not what to do, and this text is the only thing most people will
/// ever read about the policy.
fn describe_problem(problem: &Problem) -> String {
    match problem {
        Problem::TooShort { min } => {
            format!("za krotkie: potrzeba co najmniej {min} znakow")
        }
        Problem::Blocklisted => {
            "to haslo jest na liscie najczesciej uzywanych - zgadywarka zaczyna od niej".to_string()
        }
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklisted_passwords_are_refused() {
        for pw in ["password", "qwerty", "1234", "123456", "letmein"] {
            let a = assess_password(pw);
            assert!(
                a.problems.contains(&Problem::Blocklisted),
                "{pw:?} should be blocklisted, got {:?}",
                a.problems
            );
            assert_eq!(a.score, 0, "{pw:?}");
            assert!(!PasswordPolicy::strict().verdict(&a).is_accepted());
        }
    }

    #[test]
    fn eos_fails_the_length_floor() {
        let a = assess_password("eos");
        assert!(a.problems.contains(&Problem::TooShort { min: 12 }));
        assert_eq!(a.guidance, "cred.pw.too_short");
        assert_eq!(a.score, 0);
    }

    #[test]
    fn a_twenty_character_passphrase_scores_four() {
        let a = assess_password("poziomka zielona kot");
        assert_eq!(
            a.score, 4,
            "problems: {:?}, bits: {}",
            a.problems, a.entropy_bits
        );
        assert!(a.problems.is_empty());
        assert_eq!(a.guidance, "cred.pw.ok_strong");
    }

    #[test]
    fn a_long_decorated_common_password_is_still_refused() {
        // Fourteen characters: passes the floor, fails the blocklist.
        let a = assess_password("P@ssw0rd!2026");
        assert!(a.problems.contains(&Problem::Blocklisted));
        assert_eq!(a.score, 0);
    }

    #[test]
    fn twelve_identical_characters_pass_the_floor_and_fail_on_score() {
        let a = assess_password("aaaaaaaaaaaa");
        assert!(!a.problems.contains(&Problem::TooShort { min: 12 }));
        assert!(a.problems.contains(&Problem::RepeatedChars));
        assert!(a.problems.contains(&Problem::LowVariety));
        assert!(a.score < 2, "score = {}", a.score);
        assert!(!PasswordPolicy::strict().verdict(&a).is_accepted());
    }

    #[test]
    fn an_alphabet_run_is_refused_on_score() {
        let a = assess_password("abcdefghijkl");
        assert!(a.problems.contains(&Problem::Sequential));
        assert!(!PasswordPolicy::strict().verdict(&a).is_accepted());
    }

    #[test]
    fn a_soft_problem_caps_the_score_at_two() {
        // Long and varied, but contains a four-character run.
        let a = assess_password("zmvqtr1234xkpwbn");
        assert!(a.problems.contains(&Problem::Sequential));
        assert!(a.score <= 2, "score = {}", a.score);
    }

    #[test]
    fn a_megabyte_paste_is_assessed_in_bounded_time() {
        // The greeter calls this on every keystroke, before anyone has
        // authenticated. Without MAX_PASSWORD_LEN this input cost 7.63 s at
        // 64 000 characters in RELEASE mode and grew quadratically; one mebibyte
        // extrapolates to roughly 34 minutes of CPU per keystroke.
        //
        // The shape matters: "a"*(n-1) + "b" is the worst case for the old
        // period scan, because every candidate period compares almost the whole
        // string before failing. A random string is NOT a regression test here,
        // it short-circuits on the first character.
        let mut pw: String = "a".repeat(1024 * 1024 - 1);
        pw.push('b');

        let started = std::time::Instant::now();
        let a = assess_password(&pw);
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(50),
            "1 MiB password took {elapsed:?}; the length ceiling is not being applied"
        );
        // It is still judged, not waved through: a megabyte of "a" is refused.
        assert!(a.problems.contains(&Problem::RepeatedChars));
        assert!(!PasswordPolicy::strict().verdict(&a).is_accepted());
    }

    #[test]
    fn truncation_means_exactly_the_first_max_password_len_characters() {
        // The precise statement of what the ceiling does, so "it was truncated"
        // is a measured claim and not a comment. Whatever the assessment of a
        // long password is, it must equal the assessment of its own prefix --
        // which is also why truncation cannot invent a verdict of its own.
        for source in [
            "poziomka zielona kotwica burza nad jeziorem w maju ",
            "password",
            "a",
            "xkq7wm2ptz9lr4bv6nc8",
        ] {
            let long: String = source.chars().cycle().take(MAX_PASSWORD_LEN * 3).collect();
            let prefix: String = long.chars().take(MAX_PASSWORD_LEN).collect();
            assert_eq!(
                assess_password(&long),
                assess_password(&prefix),
                "{source:?} padded past the ceiling was not judged on its prefix"
            );
        }
    }

    #[test]
    fn a_long_password_is_judged_on_its_first_characters_not_refused() {
        // A ceiling that refused long passwords would punish exactly the users
        // doing the right thing. 300 characters of good material is accepted.
        let pw: String = "poziomka zielona kotwica burza nad jeziorem w maju "
            .chars()
            .cycle()
            .take(300)
            .collect();
        assert!(pw.chars().count() > MAX_PASSWORD_LEN);
        let a = assess_password(&pw);
        assert!(
            PasswordPolicy::strict().verdict(&a).is_accepted(),
            "a 300-character passphrase was refused: {:?}",
            a.problems
        );
    }

    #[test]
    fn the_ceiling_does_not_let_a_common_password_through() {
        // Truncation must not become an escape. A repeated blocklisted word
        // longer than the ceiling still shows its period after truncation,
        // because the block is far shorter than MAX_PASSWORD_LEN.
        let doubled: String = "password"
            .chars()
            .cycle()
            .take(MAX_PASSWORD_LEN * 2)
            .collect();
        let b = assess_password(&doubled);
        assert!(
            b.problems.contains(&Problem::Blocklisted),
            "problems: {:?}",
            b.problems
        );
        assert!(!PasswordPolicy::strict().verdict(&b).is_accepted());
    }

    #[test]
    fn a_long_run_of_one_character_is_refused_at_every_length() {
        // The hole the length ceiling exposed, now closed. `"a" * 128` scored 2
        // and was ACCEPTED by the strict policy before the period cap was moved
        // into bits; every length must be refused, since all of them are one
        // guess. 4096 is past the ceiling and checks the two fixes together.
        for n in [12_usize, 20, 32, 64, 128, 200, 256, 4096] {
            let pw: String = "a".repeat(n);
            let a = assess_password(&pw);
            assert!(
                !PasswordPolicy::strict().verdict(&a).is_accepted(),
                "{n} identical characters were accepted: score {}, {:.1} bits",
                a.score,
                a.entropy_bits
            );
        }
    }

    #[test]
    fn an_empty_password_does_not_panic() {
        let a = assess_password("");
        assert_eq!(a.score, 0);
        assert_eq!(a.entropy_bits, 0.0);
        assert!(a.problems.contains(&Problem::TooShort { min: 12 }));
    }

    #[test]
    fn hard_problems_come_first_in_the_list() {
        let a = assess_password("1234");
        assert!(matches!(a.problems[0], Problem::TooShort { .. }));
    }

    #[test]
    fn time_to_crack_is_monotonic_in_length() {
        // Prefixes of one unpatterned string: each extra character can only add
        // search space, so the time must never fall.
        let source = "xkq7wm2ptz9lr4bv6nc8";
        let mut previous = Duration::ZERO;
        for len in 1..=source.chars().count() {
            let candidate: String = source.chars().take(len).collect();
            let t = assess_password(&candidate).time_to_crack;
            assert!(
                t >= previous,
                "length {len} ({candidate:?}): {t:?} < {previous:?}"
            );
            previous = t;
        }
    }

    #[test]
    fn time_to_crack_is_strictly_increasing_below_saturation() {
        // Above ~71 bits every answer is Duration::MAX, so strictness can only
        // be asserted below that.
        let source = "xkq7wm2ptz9lr";
        let mut previous = Duration::ZERO;
        for len in 4..=source.chars().count() {
            let candidate: String = source.chars().take(len).collect();
            let a = assess_password(&candidate);
            assert!(a.entropy_bits < 71.0, "test outgrew the saturation point");
            assert!(
                a.time_to_crack > previous,
                "length {len} ({candidate:?}): {:?} !> {previous:?}",
                a.time_to_crack
            );
            previous = a.time_to_crack;
        }
    }

    #[test]
    fn time_to_crack_saturates_instead_of_panicking() {
        let a = assess_password("poziomka zielona kotwica burzowa niedziela");
        assert_eq!(a.time_to_crack, Duration::MAX);
    }

    #[test]
    fn a_faster_attacker_cracks_sooner() {
        let a = assess_password("zmvqtrxkpwbn");
        let one = a.time_to_crack_at(GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE);
        let many = a.time_to_crack_at(GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE.with_cores(64));
        assert!(many < one);
    }

    #[test]
    fn the_runtime_hashing_path_is_measurably_weaker() {
        // Issue #27 in one assertion: the same password falls 3.5x faster on
        // the path `passwd` actually uses today.
        let a = assess_password("zmvqtrxkpwbn");
        let image = a.time_to_crack_at(GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE);
        let runtime = a.time_to_crack_at(GuessRate::EOS_RUNTIME_ARGON2I_ONE_CORE);
        assert!(runtime < image);
        let ratio = image.as_secs_f64() / runtime.as_secs_f64();
        assert!((3.4..3.6).contains(&ratio), "ratio = {ratio}");
    }

    #[test]
    fn guess_rate_rejects_nonsense_inputs() {
        assert_eq!(
            GuessRate::from_hash_millis(0.0).as_guesses_per_second(),
            1.0
        );
        assert_eq!(
            GuessRate::from_hash_millis(-5.0).as_guesses_per_second(),
            1.0
        );
        assert_eq!(
            GuessRate::from_hash_millis(f64::NAN).as_guesses_per_second(),
            1.0
        );
        assert_eq!(
            GuessRate::from_guesses_per_second(f64::INFINITY).as_guesses_per_second(),
            1.0
        );
        assert_eq!(
            GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE
                .with_cores(0)
                .as_guesses_per_second(),
            GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE.as_guesses_per_second()
        );
    }

    #[test]
    fn the_measured_rate_is_about_seventy_one_guesses_per_second() {
        let r = GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE.as_guesses_per_second();
        assert!((71.0..71.2).contains(&r), "rate = {r}");
    }

    #[test]
    fn default_policy_is_strict() {
        // If a later edit makes the default read the environment, this fails.
        assert_eq!(PasswordPolicy::default(), PasswordPolicy::strict());
        assert!(!PasswordPolicy::default().relaxed_by_env);
        assert_eq!(PasswordPolicy::default().min_len, MIN_PASSWORD_LEN);
    }

    #[test]
    fn a_relaxed_policy_waives_the_floor_but_never_the_blocklist() {
        // Constructed directly: from_env() reads a process-global and would
        // race other tests.
        let relaxed = PasswordPolicy {
            min_len: 1,
            min_score: 0,
            relaxed_by_env: true,
        };

        let short = assess_password("abq");
        assert!(matches!(
            relaxed.verdict(&short),
            Verdict::AcceptRelaxed { .. }
        ));

        let harness = assess_password("eos");
        assert!(
            !relaxed.verdict(&harness).is_accepted(),
            "EOS_CREDPOLICY_ALLOW_WEAK must not rescue the harness password"
        );
        assert!(!relaxed.verdict(&assess_password("password")).is_accepted());
    }

    #[test]
    fn neither_harness_password_survives_the_env_escape() {
        // ROADMAP R-602e: install-smoke-drive.py sets PASSWORD = "eos" (line 27)
        // and DISK_PASSWORD = "eosdisk" (line 28). Both must be impossible to
        // wave through, so the harness has to change its passwords rather than
        // set EOS_CREDPOLICY_ALLOW_WEAK. Measured: "eosdisk" failed only the
        // length floor -- which the escape waives -- until it was added to the
        // supplement blocklist. Drop it again and this test goes red.
        let relaxed = PasswordPolicy {
            min_len: 1,
            min_score: 0,
            relaxed_by_env: true,
        };
        for pw in ["eos", "eosdisk"] {
            let a = assess_password(pw);
            assert!(
                a.problems.contains(&Problem::Blocklisted),
                "{pw:?} must be blocklisted, not merely too short: {:?}",
                a.problems
            );
            assert!(
                !relaxed.verdict(&a).is_accepted(),
                "{pw:?} was rescued by the environment escape"
            );
        }
    }

    #[test]
    fn a_relaxed_acceptance_carries_a_message_to_display() {
        let relaxed = PasswordPolicy {
            min_len: 1,
            min_score: 0,
            relaxed_by_env: true,
        };
        match relaxed.verdict(&assess_password("abq")) {
            Verdict::AcceptRelaxed { guidance, waived } => {
                assert!(guidance::key_exists(guidance));
                assert!(!waived.is_empty());
            }
            other => panic!("expected AcceptRelaxed, got {other:?}"),
        }
    }

    #[test]
    fn a_verdict_never_reports_a_problem_the_assessment_did_not_measure() {
        // `waived` is an audit field a front-end is required to display, and it
        // used to be filled with a fabricated Problem::LowVariety whenever the
        // score alone decided. Measured: assessing "xkq7wm2ptz9lrrrr" yields
        // [RepeatedChars], and the verdict reported waived: [LowVariety] -- a
        // problem the password does not have.
        //
        // `!waived.is_empty()` cannot tell a real waiver from an invented one.
        // This can: every entry must either come from the assessment, or be the
        // BelowScore that the policy itself derived, with both its numbers right.
        let policies = [
            PasswordPolicy {
                min_len: 1,
                min_score: 4,
                relaxed_by_env: true,
            },
            PasswordPolicy {
                min_len: 1,
                min_score: 4,
                relaxed_by_env: false,
            },
            PasswordPolicy::strict(),
        ];
        let samples = [
            "xkq7wm2ptz9lrrrr",
            "aabbccddeeff",
            "abq",
            "poziomka zielona kot",
            "abcdefghijkl",
            "aaaaaaaaaaaa",
            "",
        ];

        for policy in &policies {
            for pw in samples {
                let a = assess_password(pw);
                let reported: Vec<Problem> = match policy.verdict(&a) {
                    Verdict::Accept => continue,
                    Verdict::AcceptRelaxed { waived, .. } => waived,
                    Verdict::Reject { problems, .. } => problems,
                };
                for p in &reported {
                    match p {
                        Problem::BelowScore { min, got } => {
                            assert_eq!(*min, policy.min_score, "{pw:?}: wrong min");
                            assert_eq!(*got, a.score, "{pw:?}: wrong got");
                            assert!(a.score < policy.min_score, "{pw:?}: not below score");
                        }
                        other => assert!(
                            a.problems.contains(other),
                            "{pw:?}: verdict reported {other:?}, \
                             which the assessment never measured: {:?}",
                            a.problems
                        ),
                    }
                }
            }
        }
    }

    #[test]
    fn a_refusal_never_renders_an_acceptance_message() {
        // "aabbccddeeff" scores 1 with an empty problems list, so its
        // assessment guidance is `cred.pw.ok_weak` -- "Password accepted, but
        // weak". Rendering that beside a refusal is the same class of defect as
        // telling a too-long PIN it is too short.
        let a = assess_password("aabbccddeeff");
        assert!(
            a.problems.is_empty(),
            "sample stopped being the right shape"
        );
        assert_eq!(a.guidance, "cred.pw.ok_weak");

        match PasswordPolicy::strict().verdict(&a) {
            Verdict::Reject { guidance, problems } => {
                assert_eq!(guidance, "cred.pw.below_score");
                assert!(guidance::key_exists(guidance));
                assert!(!guidance::text(guidance, guidance::Lang::En).contains("accepted"));
                assert_eq!(
                    problems,
                    vec![Problem::BelowScore { min: 2, got: 1 }],
                    "the refusal must name the score, not invent a rule"
                );
            }
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    #[test]
    fn every_rejection_guidance_key_resolves() {
        for pw in [
            "",
            "eos",
            "password",
            "aaaaaaaaaaaa",
            "abcdefghijkl",
            "aabbccddeeff",
            "1234",
            "password password",
        ] {
            if let Verdict::Reject { guidance, .. } =
                PasswordPolicy::strict().verdict(&assess_password(pw))
            {
                assert!(
                    guidance::key_exists(guidance),
                    "{pw:?} refused with unknown key {guidance}"
                );
            }
        }
    }

    #[test]
    fn from_env_defaults_to_strict_when_unset() {
        // Only the absent case is asserted; setting a variable would leak into
        // every other test in this binary.
        if std::env::var(ALLOW_WEAK_ENV).is_err() {
            assert_eq!(PasswordPolicy::from_env(), PasswordPolicy::strict());
        }
    }

    #[test]
    fn a_rejection_always_names_at_least_one_problem() {
        for pw in [
            "",
            "eos",
            "password",
            "aaaaaaaaaaaa",
            "abcdefghijkl",
            "aaaa",
        ] {
            match PasswordPolicy::strict().verdict(&assess_password(pw)) {
                Verdict::Reject { problems, .. } => {
                    assert!(!problems.is_empty(), "{pw:?} refused with no reason")
                }
                other => panic!("{pw:?} should be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_good_password_is_accepted() {
        for pw in [
            "poziomka zielona kot",
            "xkq7wm2ptz9lr4bv6nc8",
            "burza nad jeziorem w maju",
        ] {
            let a = assess_password(pw);
            assert!(
                PasswordPolicy::strict().verdict(&a).is_accepted(),
                "{pw:?} refused: {:?}",
                a.problems
            );
        }
    }

    #[test]
    fn score_is_always_within_range() {
        for pw in [
            "",
            "a",
            "eos",
            "password",
            "aaaaaaaaaaaa",
            "abcdefghijkl",
            "poziomka zielona kot",
            "xkq7wm2ptz9lr4bv6nc8Q!",
        ] {
            let s = assess_password(pw).score;
            assert!(s <= 4, "{pw:?} scored {s}");
        }
    }

    #[test]
    fn every_emitted_password_key_resolves() {
        // The gate that stops a missing translation reaching a user as a raw
        // key. Remove an entry from GUIDANCE and this fails.
        for pw in [
            "",
            "eos",
            "password",
            "aaaaaaaaaaaa",
            "abcdefghijkl",
            "zmvqtr1234xkpwbn",
            "poziomka zielona kot",
            "abqzmvtrpwkx",
        ] {
            let key = assess_password(pw).guidance;
            assert!(
                guidance::key_exists(key),
                "{pw:?} produced unknown guidance key {key}"
            );
        }
    }

    #[test]
    fn expected_guesses_is_half_the_space() {
        let a = assess_password("xkq7wm2ptz9lr4");
        let ratio = 2_f64.powf(a.entropy_bits) / a.expected_guesses();
        assert!((1.99..2.01).contains(&ratio), "ratio = {ratio}");
    }

    #[test]
    fn render_accept_says_nothing() {
        let (lines, accepted) = render_verdict(&Verdict::Accept, guidance::Lang::Pl);
        assert!(accepted);
        assert!(
            lines.is_empty(),
            "an accepted password should print nothing: {lines:?}"
        );
    }

    #[test]
    fn render_reject_leads_with_guidance_then_lists_every_problem() {
        let assessment = assess_password("eos");
        let verdict = PasswordPolicy::strict().verdict(&assessment);
        let (lines, accepted) = render_verdict(&verdict, guidance::Lang::Pl);
        assert!(!accepted, "three characters must be refused");
        assert!(
            lines.len() >= 2,
            "guidance plus at least one problem: {lines:?}"
        );
        assert!(
            lines[1..].iter().any(|l| l.contains("12")),
            "the refusal must say what the floor is: {lines:?}"
        );
    }

    #[test]
    fn render_relaxed_still_speaks() {
        // The escape must never be silent. Built by hand rather than through the environment so
        // the test does not depend on process-wide state.
        let verdict = Verdict::AcceptRelaxed {
            waived: vec![Problem::TooShort { min: 12 }],
            guidance: "cred.pw.waived_by_env",
        };
        let (lines, accepted) = render_verdict(&verdict, guidance::Lang::Pl);
        assert!(accepted);
        assert!(
            !lines.is_empty(),
            "a waived acceptance must still print why"
        );
    }

    #[test]
    fn problems_are_described_not_debug_printed() {
        let text = describe_problem(&Problem::TooShort { min: 12 });
        assert!(
            !text.contains("TooShort"),
            "a person should not read a Rust variant: {text}"
        );
        assert!(text.contains("12"));
    }

    #[test]
    fn unicode_is_counted_by_character_not_byte() {
        // Eleven characters, more than twelve bytes: the floor must count
        // characters or this password would pass on its UTF-8 length.
        let pw = "zażółćgęślą";
        assert_eq!(pw.chars().count(), 11);
        assert!(pw.len() > 12);
        assert!(assess_password(pw)
            .problems
            .contains(&Problem::TooShort { min: 12 }));
    }
}
