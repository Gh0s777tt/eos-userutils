# eos-credpolicy — design and wiring plan

**Status:** draft, not yet wired · **Review date:** 2026-09-03 · **Owner:** Gh0s777tt
**Tracks:** ROADMAP `R-602a` (strength estimate), `R-602b` (blocklist), `R-602c` (guidance),
`R-602d` (PIN), `R-602e` (negative controls), `R-602f` (GUI ↔ TUI parity)

This document says how the five password paths call this library, what each of them does with
the answer, and which things are **[UNVERIFIED]** because nothing has been built or booted yet.
No part of this has run on Redox. Everything measured below was measured on the host in
§7.

---

## 1. The decisions this implements

Owner's answers, 2026-09-03:

| # | Question | Decision | Where it lives in the code |
|---|---|---|---|
| Q1 | What may a PIN unlock? | Screen unlock **only** — never `sudo`, `passwd`, `su` or FDE | `src/pin.rs` module docs; `cred.pin.unlock_only` guidance string |
| Q3 | Where does the policy live? | A `lib` target inside the **`eos-userutils`** fork | this crate, vendored as `src/credpolicy/` |
| Q4 | Floors | Password **12** characters, PIN **6** digits, plus a blocklist | `MIN_PASSWORD_LEN`, `MIN_PIN_DIGITS`, `src/blocklist.rs` |
| Q5 | PIN try counter | A per-account file **root may delete** | `src/counter.rs` |

---

## 2. What the tree looks like today

Measured facts, all from ROADMAP §6.6 and the audit entries it cites — not re-measured here,
so they carry their original references:

- The only password judgement anywhere is the literal `"password"`, refused in **two places
  with no shared code**: `orblogin/main.rs:164-179` (*"weak password"*) and `login.rs:195-243`.
- There is **no** length floor, **no** strength estimate, **no** blocklist and **no** PIN concept.
- There is **no lockout**. `redox_users` sleeps a fixed 3 s per failed verify (`lib.rs:518,526`),
  **per process**, so parallel sessions walk around it. `sudo.rs:22` has `MAX_ATTEMPTS = 3`,
  in-process, forgotten on the next invocation.
- Hashing has **two strengths** (#27): image-build argon2id `m=19456, t=2` at 14.06 ms per hash,
  runtime argon2i `m=4096, t=3` at 4.03 ms. That is `R-602g`, and it is **not** this library's
  job — but every number this library prints is divided by one of those two costs, so the two
  changes are read together.

---

## 3. The five callers

Five paths, one library (`R-602f`). Each entry says **when** it calls, **what** it calls, and
**what it does with the answer**.

### 3.1 `passwd` — `eos-userutils`, `src/passwd.rs`

The only path whose whole job is *choosing* a credential, so it uses the full API.

```rust
use eos_credpolicy::{assess_password, PasswordPolicy, Verdict};
use eos_credpolicy::guidance::{text, Lang, ADVICE_KEYS};

let assessment = assess_password(&candidate);
match PasswordPolicy::strict().verdict(&assessment) {
    Verdict::Accept => { /* hash and store */ }
    Verdict::AcceptRelaxed { guidance, .. } => {
        eprintln!("{}", text(guidance, Lang::Pl));   // must be shown, never swallowed
        /* hash and store */
    }
    // Render the verdict's own guidance, NOT `assessment.guidance`: a password
    // that breaks no rule and only misses the score has an assessment guidance
    // of `cred.pw.ok_weak`, which begins "Password accepted" (§7.5).
    Verdict::Reject { guidance, problems: _ } => {
        eprintln!("{}", text(guidance, Lang::Pl));
        /* re-prompt; do NOT store */
    }
}
```

- **Strict policy**, not `from_env` — see §5.
- Shows the score, the estimated time to crack and the four `ADVICE_KEYS` while typing
  (`R-602a`, `R-602c`).
- Time to crack comes from `assessment.time_to_crack`, which is already at the measured E-OS
  rate. If `passwd` ever measures the local hash cost itself, it passes that through
  `assess_password_at` instead — that is the whole reason the rate is a parameter.

### 3.2 `login` — `eos-userutils`, `src/login.rs`

Two distinct moments, and they must not be confused:

| moment | call | why |
|---|---|---|
| **verifying** an existing password | *nothing from this crate* | the stored hash decides; scoring a password at verify time would leak its shape into timing |
| **forced enrolment** (`force_first_boot_passwd`, `R-602`) | the §3.1 flow | this is a `passwd` in disguise |

`login.rs:195-243` currently hard-codes `""` and `"password"`. That block is **replaced** by
`assess_password` + `PasswordPolicy::strict().verdict()`; the two literals then come from the
blocklist like every other word, and the message comes from a guidance key instead of English
prose baked into a TTY path.

### 3.3 `orblogin` — `eos-orbutils`, `orblogin/main.rs`

Same two moments as `login`, plus the only PIN path.

- Enrolment (`main.rs:164-179`, the in-window *New password → Confirm* flow from `U-079`):
  the §3.1 flow, rendered as a strength meter rather than a line of text.
- **PIN unlock** (`R-602d`): `assess_pin` at enrolment, `TryCounter` at every attempt.
  The greeter must display `cred.pin.unlock_only` on the enrolment screen — that string is the
  only place a user is told the rule from Q1.

```rust
use eos_credpolicy::counter::{LockoutPolicy, Lockout, TryCounter, now_unix};

let policy = LockoutPolicy::default();
let mut counter = TryCounter::load_fail_closed(&path_for(user), &policy);   // note: fail-closed

match counter.lockout(&policy, now_unix()) {
    Lockout::HardLocked { guidance } => { show(guidance); return Refused; }
    Lockout::Locked { remaining, guidance } => { show(guidance); sleep(remaining); return Refused; }
    Lockout::Open => {}
}

if verify_pin_hash(&entered) {
    TryCounter::forget(&path_for(user))?;      // success clears the counter
} else {
    counter.record_failure(now_unix());
    counter.save()?;                            // persist BEFORE telling the user
}
```

The library never sleeps; the greeter does. That keeps the lockout arithmetic testable without
wall-clock time (99 unit tests run in 0.01 s), and lets a GUI show a countdown instead of
freezing.

**Counter path.** `/var/lib/eos/credpolicy/<uid>.tries`, mode `0600`, owned by root.
`R-602d` requires it to survive the process, so it cannot live in `/tmp`, and it must be
writable by whatever verifies the PIN — which on Redox means the greeter needs a capability for
that directory. **[UNVERIFIED]:** the exact path and who may write it are not settled; they are
a `login_schemes.toml` question and therefore a CLAUDE.md §5.6 area needing a risk analysis
and a rollback plan of their own.

### 3.4 The sudo daemon — behind `/scheme/sudo`, used by `sudo` and `su`

**Verification only.** This path never enrols a credential, so it calls **nothing** from this
crate for scoring.

What it does take is the shape of the counter: `sudo.rs:22`'s in-process `MAX_ATTEMPTS = 3`
should become a `TryCounter` on a **separate** file from the PIN counter, so that failing sudo
does not lock the screen and vice versa.

**A PIN must never be accepted here (Q1).** That is not something this library can enforce — it
exposes `assess_pin`, and any caller could call it — so the rule is carried three ways: this
document, the `src/pin.rs` module documentation, and the fact that a PIN is stored in a
**separate credential slot** from the password (`R-602d`), which the sudo daemon simply never
reads.

### 3.5 `eos-control` elevation — `src/elevate.rs:27`, stdin in `power.rs` / `netcfg.rs`

**Verification only**, same as §3.4: `to_root(password)` writes the password to `/scheme/sudo`
and the daemon decides. Nothing from this crate is called on the elevation path.

Where `eos-control` *does* call it: if it ever grows a "change your password" panel, that panel
uses the §3.1 flow. Until then, `eos-control` is listed here so the count of paths stays honest
at five and nobody later discovers a sixth.

### 3.6 Dependency consequence, stated plainly

Q3 puts the library inside `eos-userutils`. `orblogin` lives in **`eos-orbutils`** and
`eos-control` is its **own repository**, so both take a git dependency on `eos-userutils`
pinned in `repos.toml` *and* in their recipes. That is new coupling between three type-C repos
and it costs the CLAUDE.md §20.5 loop — push to both remotes, bump `pinned_rev` in `repos.toml`
**and** `rev` in `recipes/*/recipe.toml`, `eos-repos.sh pins --strict` → `drift=0`,
`eos-sync-buildtree.sh --apply`, rebuild, boot-smoke.

The alternative — a 31st repository holding only this crate — was **not** chosen. It is
recorded here because the coupling above is the price of the decision, and a future reader
should see that the price was named rather than discovered.

---

## 4. What the library decides, and why those numbers

### 4.1 The 12-character floor does almost all the work

Measured on the shipped corpus: **24 of 9916** entries are twelve characters or longer. The
floor alone refuses 99.8 % of the most common passwords before the blocklist is consulted.

That is also the argument for the normalisation in `blocklist::contains`. A raw table lookup
would be nearly redundant with the floor; what is not redundant is `P@ssw0rd!2026` — fourteen
characters, passes the floor, and is `password` (§7.3).

**The argument had a hole, closed 2026-09-03.** Because the whole justification for shipping
300 KiB of tables rests on "reach through decoration", the one form of decoration that was *not*
handled mattered more than any other — and it was the most likely one, a space. Measured before
the fix, every one of these was `Accept` under the strict policy:

| password | before | after |
|---|---|---|
| `password password` | Accept, score 2 | Reject |
| `password-password` | Accept, score 3 | Reject |
| `password moje` | Accept | Reject |
| `qwerty warszawa` | Accept, score 4 | Reject |
| `letmein please` | Accept | Reject |
| `correct horse battery staple` | Accept, score 4 | Reject |

The separator-free spellings (`PasswordPassword`, `correcthorsebatterystaple`) were already
refused, which is exactly why the existing test could not see the gap: it only ever tried those.
The supplement entry `correcthorsebatterystaple` therefore did not catch the canonical spelling
of the password it had been authored for.

**The rule is dominance, not appearance.** Refusing a password because it contains one common
word would refuse ordinary passphrases — measured against the shipped tables, `coffee table green
window` has three of its four words in the corpus (77 % of its characters) and `the quick brown
fox jumps` has one. So `contains` refuses only when common words *dominate*:

1. every word of ≥ 3 characters is common, or
2. it is at most **2** distinct words *and* common words cover at least **60 %** of its
   alphanumeric characters.

`correct horse battery staple` is caught by neither — 48 % over four words — and is refused
because the candidate list now also contains the words joined together. The boundary is stated
rather than hidden: `password poziomka` (50 %) is accepted, and lowering the threshold to catch
it would start refusing `password zielona` (53 %) and other legitimate two-word Polish phrases.

### 4.1a Work per keystroke, and the ceiling that bounds it

`assess_password` runs pre-authentication, in the greeter, on every keystroke, so unbounded work
there is a denial of service against a process nobody has authenticated to. It **was** unbounded:
`minimal_period` was a naive O(n²) scan and the distinct-character count was a `Vec::contains`
loop. Measured in release mode on `"a".repeat(n - 1) + "b"`, the worst case for that scan:

| characters | before | after |
|---|---|---|
| 1 000 | 814 µs | 21.6 µs |
| 4 000 | 11.2 ms | 21.2 µs |
| 16 000 | 351 ms | 21.0 µs |
| 64 000 | 7.63 s | 20.8 µs |
| 1 048 576 | not run — extrapolates to ~34 min | 20.5 µs |

Three fixes, not one: `MAX_PASSWORD_LEN = 256` bounds the input, `minimal_period` is now the
O(n) Knuth–Morris–Pratt computation (verified against the naive definition on all 9841 strings
of length ≤ 8 over a 3-symbol alphabet), and the distinct count sorts instead of rescanning.

Truncation errs in the safe direction: a prefix can only under-estimate, since appending
characters never weakens a password and a weak prefix stays weak. A 300-character passphrase is
accepted, not refused — `MAX_PASSWORD_LEN` is a bound on work, not on what a user may choose.

The PIN path had the same shape and is bounded the same way: an over-long PIN is already refused
by `TooLong`, so the structural scan no longer runs on it at all.

### 4.2 The blocklist and its licence

| table | entries | source | licence |
|---|---|---|---|
| `src/blocklist_data.rs` | 9916 | SecLists `Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt`, from Mark Burnett's 2015 *Ten Million Passwords* | **MIT**, © 2018 Daniel Miessler — text kept verbatim in `fetch/SECLISTS-LICENSE` |
| `src/blocklist_supplement.rs` | 145 | authored: E-OS vocabulary + Polish-locale passwords | this crate, AGPL-3.0-or-later |

**Cost, measured.** The two tables are compiled in rather than read from a file, because a
blocklist that can go missing is a control that disappears quietly (CLAUDE.md §5.5). The price
is **~300 KiB** of read-only data: 65 KiB of strings and 235 KiB of pointer table. A linked
release binary of `examples/assess` is 1409 KiB in total. If that ever becomes the binding
constraint the answer is a denser encoding, not a file on disk.

**[UNVERIFIED] — provenance of the corpus.** The file was downloaded by an **earlier,
interrupted run of this task**, not by the run that produced this crate, and it has not been
re-fetched or diffed against upstream. What *is* measured: its SHA-256
(`c63d5e4ccc31344d662583cc39ca4bd5bd20517ff1d24501f0c4e0c22d9b722a`), pinned in
`tools/gen_blocklist.py` and re-checked on every regeneration; that all 10 000 lines are
printable ASCII; and that line 43 of the published file is blank. Two other fetches in that
directory (`fetch/top1000.txt`, `fetch/top10000.txt`) contain the string `404: Not Found` and
are evidence of a failed download, not data — they are kept rather than deleted so the record
of what happened stays legible.

**[UNVERIFIED] — the supplement.** Authored from well-known patterns. No frequency is claimed
for any entry and none is stored, which is why `blocklist::rank` returns `None` for a
supplement-only hit even though `contains` returns `true`. If a permissively licensed Polish
corpus becomes available, replace the table with a generated one.

**[UNVERIFIED] — the PIN table.** The 16 keypad patterns in `src/pin.rs` are likewise authored.

### 4.3 Six digits, and why a PIN is allowed at all

At 14.06 ms per hash (§4.4) a six-digit keyspace falls in **3.9 h** offline on one core, and
faster on more. A PIN survives only because the try counter caps the attempts:
`LockoutPolicy::default()` lets ten guesses cost 5+10+20+40+80+160+320 s ≈ **10.6 min** and
then stops entirely. That is the entire security argument, and it is why Q1 forbids a PIN
anywhere an attacker can take the ciphertext away and attack it offline.

### 4.4 The rate, and a deliberate disagreement with the ROADMAP

ROADMAP §6.6 records two runs of the same measurement: **15.3 ms** and **14.06 ms** per
argon2id hash on one core. This crate pins the **faster** one (71.1 guesses/s), because when
two measurements of the same thing disagree, the number to show a user is the one that gives
the attacker the advantage.

Consequence, so nobody reads it as a contradiction: this crate says a six-digit PIN takes
**3.9 h** to exhaust where ROADMAP §6.6 says **4.2 h**. Same measurement, read conservatively.

---

## 5. Fail-closed, and the one escape

`PasswordPolicy::default()` **is** `PasswordPolicy::strict()` — 12 characters, score ≥ 2, no
environment read at all. A test asserts that equality so a later edit cannot quietly make the
default environment-sensitive.

`EOS_CREDPOLICY_ALLOW_WEAK=1`, read **only** by `PasswordPolicy::from_env()`, waives the length
floor and the score floor. It **never** waives the blocklist. Measured in §7.4.

**No privileged caller may use `from_env`.** `login`, `passwd`, `orblogin`, the sudo daemon and
`eos-control` run with an environment an attacker may influence; an env-var-weakened floor on
those paths would be a vulnerability, not a convenience. They call `strict()`. `from_env()`
exists for build tooling and recovery images.

There is **no escape at all for PINs**. `PinAssessment::is_acceptable` reads no environment.

---

## 6. The rule about the harness password

> **The harness password `eos` changes in the same merge request that wires the floor in.**

This is `R-602e`. `scripts/install-smoke-drive.py:27` sets `PASSWORD = "eos"` — three
characters — and line 28 sets `DISK_PASSWORD = "eosdisk"` for the `EOS_SMOKE_FDE=1` path. The
moment a twelve-character floor is enforced, `R-601` and `R-601c` go red unless both change in
the same change.

It is not left as a note in a document. Both strings are **in the blocklist**, and the
blocklist is the one rule the environment escape cannot reach, so:

- setting `EOS_CREDPOLICY_ALLOW_WEAK=1` in the harness **does not** make it pass;
- the only way forward is to change the harness passwords.

That was not true when this crate was first written: `eosdisk` failed **only** the length
floor, which the escape waives, so the escape would have rescued it. It was measured (§7.4),
found, and closed by adding `eosdisk` to the supplement. The test
`neither_harness_password_survives_the_env_escape` fails if either entry is removed.

**Also in the same MR:** `ci-install-smoke.sh` on its FDE path, per `R-602e`.

---

## 7. Measured on the host, 2026-09-03

macOS on Apple Silicon, `cargo 1.98.0`, `rustc 1.98.0`. These are the runs, not a summary of them.

### 7.1 Build, tests, lint, format

```
$ cargo test
running 119 tests
test result: ok. 119 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
running 6 tests
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 2.12s

$ cargo clippy --all-targets -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.07s

$ cargo fmt --check          # exit 0
```

99 tests before the 2026-09-03 review, 119 after: twenty were added for the defects in §4.1,
§4.1a and §7.5, each one first seen red against the unfixed code.

Clippy earned its keep once already: `Cargo.toml` claimed `rust-version = "1.66"`, and
`clippy::incompatible_msrv` refused it —

```
error: current MSRV (Minimum Supported Rust Version) is `1.66.0` but this item is stable in a `const` context since `1.83.0`
   --> src/lib.rs:129:35
```

`f64::is_finite` became const-usable in 1.83, which `GuessRate::from_hash_millis` needs. The
manifest now says **1.83**, and that is measured by a lint rather than remembered.

### 7.2 Every gate seen red — `bash tools/mutation-check.sh`

```
== baseline: the unmutated crate must be green ==
  test result: ok. 119 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s

== phase 1: Rust gates ==
  caught      password length floor 12 -> 3
              by eos_fails_the_length_floor (6 test(s) red in total)
  caught      blocklist never matches
              by blocklisted_passwords_are_refused (19 test(s) red in total)
  caught      PIN floor 6 -> 4
              by five_digits_is_too_short (2 test(s) red in total)
  caught      lockout stops being exponential
              by delay_doubles_past_the_free_attempts (1 test(s) red in total)
  caught      unreadable counter file stops failing closed
              by malformed_file_fails_closed_to_hard_locked (1 test(s) red in total)
  caught      guidance key loses its translation
              by every_emitted_password_key_resolves (2 test(s) red in total)
  caught      the env escape reaches the blocklist
              by a_relaxed_policy_waives_the_floor_but_never_the_blocklist (2 test(s) red in total)
  caught      the password length ceiling is removed
              by a_megabyte_paste_is_assessed_in_bounded_time (2 test(s) red in total)
  caught      separators defeat the blocklist again
              by a_separator_does_not_defeat_the_blocklist (3 test(s) red in total)
  caught      the coverage threshold drops to 1 percent
              by the_coverage_boundary_is_where_the_documentation_says (1 test(s) red in total)
  caught      coverage stops being gated on the word count
              by an_ordinary_passphrase_survives_the_token_rule (1 test(s) red in total)
  caught      a too-long PIN is told it is too short
              by a_too_long_pin_is_not_told_it_is_too_short (4 test(s) red in total)
  caught      the verdict fabricates a problem again
              by a_verdict_never_reports_a_problem_the_assessment_did_not_measure (2 test(s) red in total)
  caught      an oversized PIN paste is scanned anyway
              by an_oversized_paste_is_refused_promptly_and_says_why (1 test(s) red in total)
  caught      the period cap goes back to charging characters
              by a_longer_run_is_never_stronger_than_a_shorter_one (4 test(s) red in total)

== phase 2: generator gates ==
  caught      unmutated corpus is accepted (exit 0)
  caught      checksum mismatch (exit 2)
  caught      malformed entry with a space (exit 3)
  caught      line count changed (exit 4)

== summary ==
  caught: 19   not caught: 0
mutation-check: PASS -- every gate was seen red
```

Each mutation is checked against **the test named for it**, not merely against "something went
red" (CLAUDE.md §5.9 level 2 — a mutation that lands beside the gate looks exactly like a gate
that works).

**The harness has its own negative controls**, because a mutation script that can only report
PASS is the same failure as a gate that can only pass:

| control | result |
|---|---|
| point a mutation at a test that will not fail | `WRONG TEST … expected a_good_password_is_accepted to fail`, **exit 1** |
| run it where there is no crate to copy | `FAIL (instrument): no crate at …`, **exit 2** |

That second control found a real defect while it was being written: `fresh_copy` did not check
`cp`, so a failed copy exited **1** (a defect in the tree) where the header promised **2** (a
defect in the toolbox) — the exact confusion `U-177` exists to prevent. Fixed, then re-measured.

### 7.3 What the policy says — `cargo run --example assess`

```
$ cargo run -q --example assess -- pw eos
score      0/4
entropy    14.1 bits
crack      2.1 min
problems   [TooShort { min: 12 }, Blocklisted]
guidance   cred.pw.too_short
  pl       Hasło musi mieć co najmniej 12 znaków.
verdict    Reject { problems: [TooShort { min: 12 }, Blocklisted] }
```

### 7.4 The escape, before and after `eosdisk` was added

```
--- EOS_CREDPOLICY_ALLOW_WEAK unset ---
       eos relaxed=false -> Reject { problems: [TooShort { min: 12 }, Blocklisted] }
   eosdisk relaxed=false -> Reject { problems: [TooShort { min: 12 }] }
  password relaxed=false -> Reject { problems: [TooShort { min: 12 }, Blocklisted] }

--- EOS_CREDPOLICY_ALLOW_WEAK=1, before the fix ---
       eos relaxed=true -> Reject { problems: [TooShort { min: 12 }, Blocklisted] }
   eosdisk relaxed=true -> AcceptRelaxed { waived: [TooShort { min: 12 }], guidance: "cred.pw.waived_by_env" }
  password relaxed=true -> Reject { problems: [TooShort { min: 12 }, Blocklisted] }

--- EOS_CREDPOLICY_ALLOW_WEAK=1, after adding eosdisk to the supplement ---
     eos relaxed=true -> Reject { problems: [TooShort { min: 12 }, Blocklisted] }
 eosdisk relaxed=true -> Reject { problems: [TooShort { min: 12 }, Blocklisted] }
```

The middle block is the defect; the bottom block is the fix. Both are kept, because a fix
without the measurement that motivated it is an assertion.

### 7.5 Three defects the tests could not see, found in review 2026-09-03

Each of these passed the whole suite. They are recorded with the measurement, not just the fix.

**A PIN that is too long was told it was too short.** `pin_guidance` folded `TooShort` and
`TooLong` into one arm returning `cred.pin.too_short`:

```
$ cargo run -q --example assess -- pin 2849153729481
digits     13
problems   [TooLong { max: 12 }]
guidance   cred.pin.too_short
pl         PIN musi mieć co najmniej 6 cyfr.
```

The gate that should have caught it, `every_pin_guidance_key_resolves`, asserted only that the
key **exists** — so a key that exists and is wrong passed it. That is CLAUDE.md §5.4 exactly.
The gate is now a table of `(input, expected key)`, `cred.pin.too_long` exists in both
languages, and the mutation that swaps the two keys back is caught.

**The verdict invented a problem the assessment never measured.** `AcceptRelaxed.waived` is an
audit field a front-end is required to display, and it was filled with a fabricated
`Problem::LowVariety` whenever the score alone decided:

```
assessment.problems = [RepeatedChars]                    ("xkq7wm2ptz9lrrrr")
  -> AcceptRelaxed { waived: [LowVariety], … }           LowVariety was never measured
```

The old test asserted `!waived.is_empty()`, which cannot tell a real waiver from an invented
one. There is now a `Problem::BelowScore { min, got }` carrying both numbers, and the test walks
every reported problem and requires it to be either present in `assessment.problems` or a
`BelowScore` whose two numbers match the policy and the assessment.

Fixing that exposed a second, reachable case: `aabbccddeeff` scores 1 with **no** problems, so
its guidance is `cred.pw.ok_weak` — *"Password accepted, but weak"* — while the strict policy
rejects it. `Verdict::Reject` now carries its own guidance key and renders
`cred.pw.below_score` in that case, so a refusal can never display an acceptance message.

**A longer run of one character scored higher than a short one.** The period cap added the
repeat count to a **character** count and then multiplied the sum by `log2(charset)`, charging
4.7 bits per doubling instead of 1. Measured before the fix:

| password | bits | score | strict verdict |
|---|---|---|---|
| `"a" × 12` | 17.6 | 0 | refused |
| `"a" × 64` | 32.9 | 1 | refused |
| `"a" × 128` | 37.6 | 2 | **ACCEPTED** |
| `"a" × 256` | 42.3 | 2 | **ACCEPTED** |

All of them are one guess. The cap is now applied in bits — `period × log2(charset) +
log2(len/period)` — and `"a" × 256` is 12.7 bits and refused at every length. This one was not
in the review; it surfaced because the length ceiling in §4.1a made 256-character inputs a
normal case and a test written for the ceiling failed on it.

---

## 8. [UNVERIFIED] — everything not measured

Listed so no reader has to guess which claims were tested.

| claim | status |
|---|---|
| builds for `*-unknown-redox` | **[UNVERIFIED]** — the target is not installed on this host; §9 records what was checked instead |
| runs on Redox at all | **[UNVERIFIED]** — nothing here has been on a Redox image |
| the wiring in §3 compiles against the real `passwd.rs` / `login.rs` / `orblogin` | **[UNVERIFIED]** — no fork was modified; the snippets are a plan, not a diff |
| counter path `/var/lib/eos/credpolicy/<uid>.tries` is writable by the greeter | **[UNVERIFIED]** — a `login_schemes.toml` and capability question (§5.6 area) |
| corpus provenance | **[UNVERIFIED]** — §4.2; checksum pinned, download not re-performed |
| supplement and PIN tables | **[UNVERIFIED]** — authored, not measured from a corpus |
| the entropy estimator agrees with zxcvbn | **[UNVERIFIED]** — not compared; it is a cheaper model and only claims to be an estimate |
| MSRV 1.83 builds on an actual 1.83 toolchain | **[UNVERIFIED]** — derived from `clippy::incompatible_msrv` on 1.98, not from a 1.83 build |
| the argon2id/argon2i costs | **not measured here** — taken from ROADMAP §6.6 and #27, which measured them |

## 9. Portability, as far as it was checked

No dependencies beyond `std`, and `#![forbid(unsafe_code)]`. The only platform surface used is
`std::fs`, `std::path`, `std::io`, `std::env`, `std::time` and `std::error` — all of which Redox
`std` provides. `counter::now_unix` is the single clock read in the crate, and every lockout
decision takes the time as a parameter so it can be tested without one.

What was actually run, rather than reasoned:

```
$ cargo build --target x86_64-unknown-redox
error[E0463]: can't find crate for `std`
  = note: the `x86_64-unknown-redox` target may not be installed

$ rustup target list --installed
aarch64-apple-darwin
```

So the Redox build is **[UNVERIFIED]**, and no attempt was made to install the target —
Redox `std` needs the redoxer toolchain, not a rustup target, and downloading one was out of
scope for this artefact.

Three mechanical checks stand in for it, each a grep over `src/` that would fail loudly:

| check | result |
|---|---|
| `#[cfg(target_os …)]`, `#[cfg(unix)]`, `#[cfg(windows)]`, `std::os::` | none |
| `unsafe` anywhere | none — and `#![forbid(unsafe_code)]` makes adding one a compile error |
| non-`std` imports | none |

The complete set of `std` modules the crate touches is `env`, `error`, `fmt`, `fs`, `io`,
`path`, `process` (tests and the example only) and `time`. Redox `std` provides all of them.

That is an argument, not a build. The claim "it builds for Redox" is not made.

## 10. Before this is merged

- [ ] `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check` — §7.1
- [ ] `bash tools/mutation-check.sh` → `PASS`, and its two negative controls — §7.2
- [ ] Harness passwords changed in the **same** MR: `install-smoke-drive.py:27` and `:28`,
      plus `ci-install-smoke.sh` on the FDE path — §6
- [ ] `R-602g` decided, since every printed number depends on which hash the runtime uses — §2
- [ ] Counter path and its capability settled — a §5.6 area, so risk analysis + rollback plan
- [ ] `repos.toml` / recipe pins for the new `eos-orbutils` → `eos-userutils` and
      `eos-control` → `eos-userutils` dependencies; `pins --strict` → `drift=0` — §3.6
- [ ] `CHANGELOG.md`, `ROADMAP.md` (`R-602a`…`f`), `README.md`, `SECURITY.md` in the same MR
      (CLAUDE.md §5.8)
- [ ] Boot-smoke on both architectures after the image carries the new `passwd` and greeter
