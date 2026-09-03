#[macro_use]
extern crate clap;

use std::io;
use std::io::Write;
use std::process::exit;

use extra::option::OptionalExt;
use libredox::flag::O_CLOEXEC;
use libredox::errno::EPERM;
use redox_users::{All, AllUsers, Config, get_uid};
use termion::input::TermRead;

const _MAN_PAGE: &'static str = /* @MANSTART{passwd} */
    r#"
NAME
    passwd - modify a user's password

SYNOPSIS
    passwd [ LOGIN ]
    passwd [ -h | --help ]

DESCRIPTION
    The passwd utility changes the user's local password. If the user is not
    the super-user, passwd first prompts for the current password and will
    not continue unless the correct password is entered.

OPTIONS

    -h, --help
        Display this help and exit.

    -l, --lock
        Lock the password of the named account. This changes the stored password
        hash so that it matches no encrypted value ("!")

        Users with locked passwords are not allowed to change their password.

AUTHOR
    Written by Jeremy Soller, Jose Narvaez.
"#; /* @MANEND */

fn main() {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr();

    let args = clap_app!(passwd =>
        (author: "Jeremy Soller, Jose Narvaez")
        (about: "Set user passwords")
        (@arg LOGIN: "Apply to login. Sets password for current user if not supplied")
        (@arg LOCK: -l --lock "Lock the password for an account (no login)")
    )
    .get_matches();

    if args.is_present("LOCK") {
        if get_uid().unwrap_or_exit(1) != 0 {
            eprintln!("passwd: only root is allowed to lock accounts");
            exit(1);
        }

        let mut users =
            AllUsers::authenticator(Config::default().writeable(true)).unwrap_or_exit(1);

        let Some(login) = args.value_of("LOGIN") else {
            eprintln!("passwd: no account specified to lock");
            exit(1);
        };

        let user = users.get_mut_by_name(login).unwrap_or_else(|| {
            eprintln!("passwd: user does not exist: {}", login);
            exit(1);
        });

        user.unset_passwd();
        users.save().unwrap_or_exit(1);

        return;
    }

    let uid = get_uid().unwrap_or_exit(1);

    if uid == 0 {
        let mut users =
            AllUsers::authenticator(Config::default().writeable(true)).unwrap_or_exit(1);

        let user = find_user(&args, &mut users);

        let msg = format!("changing password for '{}' \n", user.user);
        stdout.write_all(&msg.as_bytes()).r#try(&mut stderr);
        stdout.flush().r#try(&mut stderr);

        let new_password = ask_new_password(stdin, stdout, stderr);

        user.set_passwd(&new_password).unwrap_or_exit(1);
        users.save().unwrap_or_exit(1);

        return;
    }

    let mut users = AllUsers::basic(Config::default()).unwrap_or_exit(1);

    let user = find_user(&args, &mut users);

    if user.uid != uid {
        eprintln!(
            "passwd: you do not have permission to set the password of '{}'",
            user.user
        );
        exit(1);
    }

    let msg = format!("changing password for '{}' \n", user.user);
    stdout.write_all(&msg.as_bytes()).r#try(&mut stderr);
    stdout.flush().r#try(&mut stderr);

    drop(users); // Unlock /etc/passwd

    stdout.write_all(b"current password: ").r#try(&mut stderr);
    stdout.flush().r#try(&mut stderr);

    let file = libredox::call::open("/scheme/sudo/passwd", O_CLOEXEC, 0).unwrap();

    if let Some(password) = stdin.read_passwd(&mut stdout).r#try(&mut stderr) {
        stdout.write(b"\n").r#try(&mut stderr);
        stdout.flush().r#try(&mut stderr);

        match libredox::call::write(file, password.as_bytes()) {
            Ok(_) => {}
            Err(err) if err.errno() == EPERM => {
                eprintln!("passwd: incorrect current password");
                exit(1);
            }
            Err(err) => panic!("{err}"),
        }
    } else {
        eprintln!("passwd: incorrect current password");
        exit(1);
    }

    let new_password = ask_new_password(stdin, stdout, stderr);

    match libredox::call::write(file, new_password.as_bytes()) {
        Ok(_) => {}
        Err(err) if err.errno() == EPERM => {
            eprintln!("passwd: invalid new password");
            exit(1);
        }
        Err(err) => panic!("{err}"),
    }
}

fn find_user<'a, T: Default>(
    args: &clap::ArgMatches<'_>,
    users: &'a mut AllUsers<T>,
) -> &'a mut redox_users::User<T> {
    let uid = get_uid().unwrap_or_exit(1);
    match args.value_of("LOGIN") {
        Some(login) => users.get_mut_by_name(login).unwrap_or_else(|| {
            eprintln!("passwd: user does not exist: {}", login);
            exit(1);
        }),
        None => users.get_mut_by_id(uid).unwrap_or_else(|| {
            eprintln!("passwd: you do not exist");
            exit(1);
        }),
    }
}

fn ask_new_password(
    mut stdin: io::StdinLock<'_>,
    mut stdout: io::StdoutLock<'_>,
    mut stderr: io::Stderr,
) -> String {
    stdout.write_all(b"new password: ").r#try(&mut stderr);
    stdout.flush().r#try(&mut stderr);
    let Some(new_password) = stdin.read_passwd(&mut stdout).r#try(&mut stderr) else {
        eprintln!("passwd: no new password provided");
        exit(1);
    };

    stdout.write(b"\nconfirm password: ").r#try(&mut stderr);
    stdout.flush().r#try(&mut stderr);
    let Some(confirm_password) = stdin.read_passwd(&mut stdout).r#try(&mut stderr) else {
        eprintln!("\npasswd: no confirm password provided");
        exit(1);
    };

    stdout.write(b"\n").r#try(&mut stderr);
    stdout.flush().r#try(&mut stderr);

    if new_password != confirm_password {
        eprintln!("passwd: new password does not match confirm password");
        exit(1);
    }

    enforce_policy(&new_password, &mut stderr);
    new_password
}

/// Apply the shipped credential policy to a password about to be SET.
///
/// WHY HERE AND NOWHERE ELSE ON THIS PATH. `ask_new_password` is the single funnel: both the
/// self-service branch and the root branch call it, so one insertion point covers `passwd`
/// entirely. Putting the same check in `login` would be a different and much worse thing --
/// `login` VERIFIES an existing password, and a floor applied there locks out every account
/// created before the floor existed. A policy belongs where a secret is chosen, not where it
/// is presented.
///
/// The wording lives in `credpolicy::render_verdict`, not here. The binaries of this crate
/// cannot be built on a developer host (`libredox` has no macOS target), so anything written in
/// `src/bin/` is provable only by building a Redox image; the decision and its text sit in the
/// library, where `credpolicy-hostcheck` runs them. It is also what keeps `passwd`, the greeter
/// and the installer saying the same thing (`R-602f`) -- they do not each write it.
fn enforce_policy(password: &str, stderr: &mut io::Stderr) {
    use userutils::credpolicy::{PasswordPolicy, assess_password, guidance, render_verdict};

    let verdict = PasswordPolicy::from_env().verdict(&assess_password(password));
    let (lines, accepted) = render_verdict(&verdict, guidance::Lang::Pl);
    for line in &lines {
        let _ = writeln!(stderr, "passwd: {line}");
    }
    if !accepted {
        exit(1);
    }
}
