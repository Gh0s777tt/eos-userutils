//! Per-account PIN try counter with exponential back-off.
//!
//! Owner's decision (2026-09-03, Q5): the counter is **a per-account file that
//! root may delete**. Deleting it is the sanctioned unlock, so a missing file
//! is a fresh counter, not an error.
//!
//! # What this replaces
//!
//! ROADMAP `R-602d`, measured: `redox_users` sleeps a fixed 3 s after a failed
//! verify (`lib.rs:518,526`), **per process** — two parallel sessions walk
//! around it. `sudo.rs:22` has `MAX_ATTEMPTS = 3`, in-process, forgotten on the
//! next invocation. Neither is a lockout, because neither survives the process.
//! A file does.
//!
//! # Pure logic; the caller sleeps
//!
//! [`TryCounter::lockout`] takes the current time and returns what the state
//! *is*. It does not sleep, does not read a clock and does not touch the
//! filesystem, so it can be tested exhaustively without waiting for wall time.
//! The caller decides whether to sleep, refuse, or show a countdown.
//!
//! # Fail-closed
//!
//! A missing file is an open counter (root deleted it — that is the unlock).
//! A file that exists but cannot be read or parsed is **not**: that is
//! [`TryCounter::load_fail_closed`], which returns a hard-locked counter.
//! An attacker who can corrupt the file must not thereby clear it.
//!
//! ```
//! use userutils::credpolicy::counter::{LockoutPolicy, Lockout, TryCounter};
//! let policy = LockoutPolicy::default();
//! let mut c = TryCounter::fresh("/tmp/does-not-matter");
//! for attempt in 0..4 {
//!     c.record_failure(1_000 + attempt);
//! }
//! // Four failures, three free: the first delay is the base delay.
//! assert!(matches!(c.lockout(&policy, 1_003), Lockout::Locked { .. }));
//! ```

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// First line of the file; a file without it is not ours.
const MAGIC: &str = "# eos-credpolicy try-counter v1";

/// How many failures are free, how fast the delay grows, and where it stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockoutPolicy {
    /// Failures that cost nothing. A mistyped PIN should not lock a screen.
    pub free_attempts: u32,
    /// Delay applied to the first failure past `free_attempts`.
    pub base_delay: Duration,
    /// Ceiling on the doubling.
    pub max_delay: Duration,
    /// Failures after which only an administrator can unlock, by deleting the
    /// file. `None` disables the hard lock — back-off then continues at
    /// `max_delay` forever.
    pub hard_lock_after: Option<u32>,
}

impl Default for LockoutPolicy {
    /// Three free tries, then 5 s doubling to a 15 min ceiling, hard lock at 10.
    ///
    /// At [`crate::credpolicy::GuessRate::EOS_IMAGE_ARGON2ID_ONE_CORE`] a six-digit PIN
    /// takes 3.9 h to exhaust offline. Online, against this policy, ten guesses
    /// cost 5+10+20+40+80+160+320 s ≈ 10.6 min and then stop entirely — which
    /// is the whole reason a six-digit PIN is allowed to unlock a screen at all.
    fn default() -> Self {
        Self {
            free_attempts: 3,
            base_delay: Duration::from_secs(5),
            max_delay: Duration::from_secs(900),
            hard_lock_after: Some(10),
        }
    }
}

/// What the counter says right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lockout {
    /// An attempt may proceed.
    Open,
    /// Refuse for `remaining` longer. The caller sleeps, or shows a countdown.
    Locked {
        /// Time left on the current back-off.
        remaining: Duration,
        /// Guidance key to render: `cred.lockout.locked`.
        guidance: &'static str,
    },
    /// Refuse until an administrator deletes the counter file.
    HardLocked {
        /// Guidance key to render: `cred.lockout.hard_locked`.
        guidance: &'static str,
    },
}

impl Lockout {
    /// May an attempt proceed?
    pub fn is_open(&self) -> bool {
        matches!(self, Lockout::Open)
    }
}

/// Why a counter file could not be turned into a [`TryCounter`].
#[derive(Debug)]
pub enum CounterError {
    /// The file exists but is not a v1 counter, or a field will not parse.
    Malformed {
        /// Human-readable detail; not shown to end users.
        detail: String,
    },
    /// The file exists but could not be read or written.
    Io(io::Error),
}

impl fmt::Display for CounterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CounterError::Malformed { detail } => write!(f, "malformed try counter: {detail}"),
            CounterError::Io(e) => write!(f, "try counter I/O: {e}"),
        }
    }
}

impl std::error::Error for CounterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CounterError::Io(e) => Some(e),
            CounterError::Malformed { .. } => None,
        }
    }
}

impl From<io::Error> for CounterError {
    fn from(e: io::Error) -> Self {
        CounterError::Io(e)
    }
}

/// A per-account failure count and the time of the last failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TryCounter {
    path: PathBuf,
    failures: u32,
    last_failure: u64,
}

impl TryCounter {
    /// A zeroed counter for `path`, without touching the filesystem.
    pub fn fresh<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            failures: 0,
            last_failure: 0,
        }
    }

    /// Read the counter at `path`.
    ///
    /// A missing file is a fresh counter — root deleting the file is the
    /// documented unlock (Q5). Any other I/O failure, or a file that does not
    /// parse, is an error; see [`TryCounter::load_fail_closed`] for the login
    /// path, which must not treat an unreadable file as "no failures".
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, CounterError> {
        let path = path.as_ref();
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Self::fresh(path)),
            Err(e) => return Err(CounterError::Io(e)),
        };
        Self::parse(path, &text)
    }

    /// [`TryCounter::load`], but an unreadable or malformed file yields a
    /// counter that is already hard-locked under `policy`.
    ///
    /// This is what `login`, `orblogin` and the screen locker call. Corrupting
    /// the file must never be a way to clear it, and the only unlock is the one
    /// the owner chose: root deletes it.
    pub fn load_fail_closed<P: AsRef<Path>>(path: P, policy: &LockoutPolicy) -> Self {
        let path = path.as_ref();
        match Self::load(path) {
            Ok(c) => c,
            Err(_) => Self {
                path: path.to_path_buf(),
                failures: policy.hard_lock_after.unwrap_or(u32::MAX).max(1),
                last_failure: u64::MAX,
            },
        }
    }

    /// Parse the plain-text format. Tolerates comments, blank lines, CRLF and
    /// unknown keys; rejects a missing magic line and unparsable numbers.
    fn parse(path: &Path, text: &str) -> Result<Self, CounterError> {
        let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
        match lines.next() {
            Some(first) if first.trim() == MAGIC => {}
            other => {
                return Err(CounterError::Malformed {
                    detail: format!("first line is {other:?}, expected {MAGIC:?}"),
                })
            }
        }

        let mut failures: Option<u32> = None;
        let mut last_failure: Option<u64> = None;

        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| CounterError::Malformed {
                    detail: format!("line {line:?} is not key=value"),
                })?;
            match key.trim() {
                "failures" => {
                    failures = Some(value.trim().parse().map_err(|e| CounterError::Malformed {
                        detail: format!("failures={value:?}: {e}"),
                    })?)
                }
                "last_failure" => {
                    last_failure =
                        Some(value.trim().parse().map_err(|e| CounterError::Malformed {
                            detail: format!("last_failure={value:?}: {e}"),
                        })?)
                }
                // Unknown keys are ignored on purpose, so a later version can
                // add a field without making old files unreadable.
                _ => {}
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            failures: failures.ok_or_else(|| CounterError::Malformed {
                detail: "no failures= line".to_string(),
            })?,
            last_failure: last_failure.unwrap_or(0),
        })
    }

    /// Serialise to the on-disk format.
    pub fn to_text(&self) -> String {
        format!(
            "{MAGIC}\nfailures={}\nlast_failure={}\n",
            self.failures, self.last_failure
        )
    }

    /// Write the counter, staging through `<path>.partial` and renaming.
    ///
    /// CLAUDE.md P-4: a plain redirect creates the file before the write, so a
    /// crash leaves a zero-length file that parses as "no failures" — which
    /// would be an unlock. Rename is atomic on RedoxFS and on APFS.
    pub fn save(&self) -> Result<(), CounterError> {
        let partial = partial_path(&self.path);
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&partial, self.to_text())?;
        fs::rename(&partial, &self.path)?;
        Ok(())
    }

    /// Delete the counter file. This is the unlock (Q5).
    ///
    /// A missing file is success, so this is safe to call unconditionally after
    /// a correct PIN.
    pub fn forget<P: AsRef<Path>>(path: P) -> Result<(), CounterError> {
        match fs::remove_file(path.as_ref()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(CounterError::Io(e)),
        }
    }

    /// Record one failed attempt at `now_unix` (seconds since the epoch).
    ///
    /// Saturating: a counter cannot be wrapped back to zero by failing
    /// `u32::MAX` times.
    pub fn record_failure(&mut self, now_unix: u64) {
        self.failures = self.failures.saturating_add(1);
        self.last_failure = now_unix;
    }

    /// Clear the in-memory counter. Persist with [`TryCounter::save`], or call
    /// [`TryCounter::forget`] to remove the file instead.
    pub fn reset(&mut self) {
        self.failures = 0;
        self.last_failure = 0;
    }

    /// Failures recorded so far.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Unix time of the last recorded failure, or 0 if there is none.
    pub fn last_failure(&self) -> u64 {
        self.last_failure
    }

    /// Path this counter reads and writes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The back-off this many failures earns, before any time has passed.
    ///
    /// `free_attempts` failures cost nothing; each one after that doubles the
    /// delay, capped at `max_delay`.
    pub fn delay_for(policy: &LockoutPolicy, failures: u32) -> Duration {
        if failures <= policy.free_attempts {
            return Duration::ZERO;
        }
        let steps = failures - policy.free_attempts - 1;
        if steps >= 32 {
            return policy.max_delay;
        }
        let factor = 1_u64 << steps;
        let secs = policy.base_delay.as_secs().saturating_mul(factor);
        let delay = Duration::from_secs(secs);
        if delay > policy.max_delay {
            policy.max_delay
        } else {
            delay
        }
    }

    /// What the counter says at `now_unix`. Pure: no clock, no filesystem.
    ///
    /// A `now_unix` earlier than the recorded failure — a clock that went
    /// backwards, or was pushed backwards — restarts the full delay rather than
    /// clearing it.
    pub fn lockout(&self, policy: &LockoutPolicy, now_unix: u64) -> Lockout {
        if let Some(limit) = policy.hard_lock_after {
            if self.failures >= limit {
                return Lockout::HardLocked {
                    guidance: "cred.lockout.hard_locked",
                };
            }
        }

        let delay = Self::delay_for(policy, self.failures);
        if delay.is_zero() {
            return Lockout::Open;
        }

        // Clock moved backwards: charge the whole delay again.
        if now_unix < self.last_failure {
            return Lockout::Locked {
                remaining: delay,
                guidance: "cred.lockout.locked",
            };
        }

        let elapsed = Duration::from_secs(now_unix - self.last_failure);
        if elapsed >= delay {
            Lockout::Open
        } else {
            Lockout::Locked {
                remaining: delay - elapsed,
                guidance: "cred.lockout.locked",
            }
        }
    }
}

/// `<path>.partial`, the staging name used by [`TryCounter::save`].
fn partial_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".partial");
    PathBuf::from(name)
}

/// Seconds since the Unix epoch, or 0 if the clock is before it.
///
/// The only clock read in this crate. Callers that already have a timestamp —
/// or a test — should pass their own to [`TryCounter::lockout`] instead.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch path per test; no test depends on another's file.
    fn scratch(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("eos-credpolicy-test-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn missing_file_is_a_fresh_counter() {
        // Root deleting the file is the sanctioned unlock (Q5).
        let p = scratch("missing");
        let c = TryCounter::load(&p).expect("missing file must not be an error");
        assert_eq!(c.failures(), 0);
        assert!(c.lockout(&LockoutPolicy::default(), 0).is_open());
    }

    #[test]
    fn round_trip_through_a_file() {
        let p = scratch("roundtrip");
        let mut c = TryCounter::fresh(&p);
        c.record_failure(1_700_000_000);
        c.record_failure(1_700_000_005);
        c.save().expect("save");
        let back = TryCounter::load(&p).expect("load");
        assert_eq!(back.failures(), 2);
        assert_eq!(back.last_failure(), 1_700_000_005);
        fs::remove_file(&p).ok();
    }

    #[test]
    fn save_leaves_no_partial_behind() {
        let p = scratch("partial");
        let mut c = TryCounter::fresh(&p);
        c.record_failure(10);
        c.save().expect("save");
        assert!(!partial_path(&p).exists(), "staging file was left behind");
        fs::remove_file(&p).ok();
    }

    #[test]
    fn forget_removes_the_file_and_tolerates_it_missing() {
        let p = scratch("forget");
        let mut c = TryCounter::fresh(&p);
        c.record_failure(10);
        c.save().expect("save");
        assert!(p.exists());
        TryCounter::forget(&p).expect("first forget");
        assert!(!p.exists());
        TryCounter::forget(&p).expect("second forget must be a no-op");
    }

    #[test]
    fn a_file_without_the_magic_line_is_malformed() {
        let p = scratch("nomagic");
        fs::write(&p, "failures=3\n").expect("write");
        assert!(matches!(
            TryCounter::load(&p),
            Err(CounterError::Malformed { .. })
        ));
        fs::remove_file(&p).ok();
    }

    #[test]
    fn a_zero_length_file_is_malformed_not_an_unlock() {
        // P-4: a crashed redirect leaves a zero-length file. It must not read
        // as "no failures".
        let p = scratch("empty");
        fs::write(&p, "").expect("write");
        assert!(matches!(
            TryCounter::load(&p),
            Err(CounterError::Malformed { .. })
        ));
        fs::remove_file(&p).ok();
    }

    #[test]
    fn malformed_file_fails_closed_to_hard_locked() {
        let p = scratch("failclosed");
        fs::write(&p, "garbage\n").expect("write");
        let policy = LockoutPolicy::default();
        let c = TryCounter::load_fail_closed(&p, &policy);
        assert!(matches!(
            c.lockout(&policy, now_unix()),
            Lockout::HardLocked { .. }
        ));
        fs::remove_file(&p).ok();
    }

    #[test]
    fn unknown_keys_and_crlf_are_tolerated() {
        let p = scratch("tolerant");
        fs::write(
            &p,
            format!(
                "{MAGIC}\r\n# a comment\r\n\r\nfailures=4\r\nfuture_field=x\r\nlast_failure=99\r\n"
            ),
        )
        .expect("write");
        let c = TryCounter::load(&p).expect("load");
        assert_eq!(c.failures(), 4);
        assert_eq!(c.last_failure(), 99);
        fs::remove_file(&p).ok();
    }

    #[test]
    fn a_non_numeric_count_is_malformed() {
        let p = scratch("nonnumeric");
        fs::write(&p, format!("{MAGIC}\nfailures=many\n")).expect("write");
        assert!(matches!(
            TryCounter::load(&p),
            Err(CounterError::Malformed { .. })
        ));
        fs::remove_file(&p).ok();
    }

    #[test]
    fn free_attempts_cost_nothing() {
        let policy = LockoutPolicy::default();
        for failures in 0..=policy.free_attempts {
            assert_eq!(
                TryCounter::delay_for(&policy, failures),
                Duration::ZERO,
                "{failures} failures should still be free"
            );
        }
    }

    #[test]
    fn delay_doubles_past_the_free_attempts() {
        let policy = LockoutPolicy::default();
        assert_eq!(TryCounter::delay_for(&policy, 4), Duration::from_secs(5));
        assert_eq!(TryCounter::delay_for(&policy, 5), Duration::from_secs(10));
        assert_eq!(TryCounter::delay_for(&policy, 6), Duration::from_secs(20));
        assert_eq!(TryCounter::delay_for(&policy, 7), Duration::from_secs(40));
        assert_eq!(TryCounter::delay_for(&policy, 8), Duration::from_secs(80));
        assert_eq!(TryCounter::delay_for(&policy, 9), Duration::from_secs(160));
    }

    #[test]
    fn delay_is_capped_and_never_overflows() {
        let policy = LockoutPolicy {
            hard_lock_after: None,
            ..LockoutPolicy::default()
        };
        assert_eq!(TryCounter::delay_for(&policy, 100), policy.max_delay);
        assert_eq!(TryCounter::delay_for(&policy, u32::MAX), policy.max_delay);
    }

    #[test]
    fn lockout_opens_again_once_the_delay_has_passed() {
        let policy = LockoutPolicy::default();
        let mut c = TryCounter::fresh("unused");
        for _ in 0..4 {
            c.record_failure(1_000);
        }
        match c.lockout(&policy, 1_000) {
            Lockout::Locked { remaining, .. } => assert_eq!(remaining, Duration::from_secs(5)),
            other => panic!("expected Locked, got {other:?}"),
        }
        match c.lockout(&policy, 1_002) {
            Lockout::Locked { remaining, .. } => assert_eq!(remaining, Duration::from_secs(3)),
            other => panic!("expected Locked, got {other:?}"),
        }
        assert!(c.lockout(&policy, 1_005).is_open());
    }

    #[test]
    fn hard_lock_never_reopens_with_time() {
        let policy = LockoutPolicy::default();
        let mut c = TryCounter::fresh("unused");
        for _ in 0..10 {
            c.record_failure(1_000);
        }
        assert!(matches!(
            c.lockout(&policy, u64::MAX),
            Lockout::HardLocked { .. }
        ));
    }

    #[test]
    fn a_backwards_clock_does_not_clear_the_lockout() {
        let policy = LockoutPolicy::default();
        let mut c = TryCounter::fresh("unused");
        for _ in 0..4 {
            c.record_failure(1_000);
        }
        match c.lockout(&policy, 0) {
            Lockout::Locked { remaining, .. } => assert_eq!(remaining, Duration::from_secs(5)),
            other => panic!("a backwards clock must not unlock, got {other:?}"),
        }
    }

    #[test]
    fn reset_clears_the_counter() {
        let mut c = TryCounter::fresh("unused");
        c.record_failure(5);
        c.record_failure(6);
        assert_eq!(c.failures(), 2);
        c.reset();
        assert_eq!(c.failures(), 0);
        assert_eq!(c.last_failure(), 0);
        assert!(c.lockout(&LockoutPolicy::default(), 0).is_open());
    }

    #[test]
    fn failures_saturate_instead_of_wrapping() {
        let mut c = TryCounter::fresh("unused");
        for _ in 0..3 {
            c.record_failure(1);
        }
        // Reach the ceiling the cheap way, then prove it does not wrap to 0.
        let mut c2 = TryCounter::fresh("unused");
        c2.failures = u32::MAX;
        c2.record_failure(2);
        assert_eq!(c2.failures(), u32::MAX);
        assert_eq!(c.failures(), 3);
    }

    #[test]
    fn lockout_guidance_keys_exist() {
        use crate::credpolicy::guidance::key_exists;
        let policy = LockoutPolicy::default();
        let mut c = TryCounter::fresh("unused");
        for _ in 0..4 {
            c.record_failure(1_000);
        }
        match c.lockout(&policy, 1_000) {
            Lockout::Locked { guidance, .. } => assert!(key_exists(guidance)),
            other => panic!("expected Locked, got {other:?}"),
        }
        for _ in 0..10 {
            c.record_failure(1_000);
        }
        match c.lockout(&policy, 1_000) {
            Lockout::HardLocked { guidance } => assert!(key_exists(guidance)),
            other => panic!("expected HardLocked, got {other:?}"),
        }
    }
}
