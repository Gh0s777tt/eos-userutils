//! Ask the shipped policy what it thinks of a password, so a harness password is CHOSEN by the
//! policy rather than guessed at and hoped for.
use userutils::credpolicy::{assess_password, guidance, render_verdict, PasswordPolicy};
fn main() {
    for pw in std::env::args().skip(1) {
        let a = assess_password(&pw);
        let v = PasswordPolicy::strict().verdict(&a);
        let (lines, ok) = render_verdict(&v, guidance::Lang::Pl);
        println!("{:>28}  score={} len={} -> {}", pw, a.score, pw.chars().count(),
                 if ok { "ACCEPT" } else { "REJECT" });
        for l in lines { println!("{:>30}{}", "", l); }
    }
}
