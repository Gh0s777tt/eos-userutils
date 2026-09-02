#[macro_use]
extern crate clap;

use core::ptr::slice_from_raw_parts;
use std::error::Error;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Stderr, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process::{Child, Command, Stdio};
use std::str;
use std::time::{Duration, Instant};

use event::{EventFlags, RawEventQueue};
use extra::io::fail;
use libc::{grantpt, ptsname, strlen, unlockpt};
use libredox::call as redox;
use libredox::errno::EAGAIN;
use libredox::flag;

const _MAN_PAGE: &'static str = /* @MANSTART{getty} */
    r#"
NAME
    getty - set terminal mode

SYNOPSIS
    getty [-J | --noclear | -C | --contain ] tty
    getty [ -h | --help ]

DESCRIPTION
    The getty utility is called by init(8) to open and initialize the tty line,
    read a login name, and invoke login(1).

OPTIONS

    -h, --help
        Display this help and exit.

    -J, --noclear
        Do not clear the screen before forking login(1).

    -C, --contain
        Run contain_login instead of login

AUTHOR
    Written by Jeremy Soller.
"#; /* @MANEND */

const DEFAULT_COLS: u16 = 80;
const DEFAULT_LINES: u16 = 30;

pub fn handle(
    event_queue: &mut RawEventQueue,
    tty_fd: RawFd,
    master_fd: RawFd,
    process: &mut Child,
) {
    // tty_fd => Display
    // master_fd => PTY

    let handle_event = |event_id: usize| {
        if event_id as RawFd == tty_fd {
            let mut packet = [0; 4096];
            loop {
                let count = match redox::read(tty_fd as usize, &mut packet) {
                    Ok(0) => return,
                    Ok(count) => count,
                    Err(ref err) if err.errno() == EAGAIN => break,
                    Err(_) => panic!("getty: failed to read from TTY"),
                };
                redox::write(master_fd as usize, &packet[..count])
                    .expect("getty: failed to write master PTY");
            }
        } else if event_id as RawFd == master_fd {
            let mut packet = [0; 4096];
            loop {
                let count = match redox::read(master_fd as usize, &mut packet) {
                    Ok(0) => return,
                    Ok(count) => count,
                    Err(ref err) if err.errno() == EAGAIN => break,
                    Err(_) => panic!("getty: failed to read from master TTY"),
                };
                redox::write(tty_fd as usize, &packet[1..count])
                    .expect("getty: failed to write to TTY");
                if packet[0] & 1 == 1 {
                    let _ = redox::fsync(tty_fd as usize);
                }
            }
        }
    };

    handle_event(tty_fd as usize);
    handle_event(master_fd as usize);

    'events: loop {
        let sys_event = event_queue
            .next()
            .expect("getty: event queue stopped")
            .expect("getty: failed to read event file");
        handle_event(sys_event.fd);

        match process.try_wait() {
            Ok(status) => match status {
                Some(_code) => break 'events,
                None => (),
            },
            Err(err) => match err.kind() {
                ErrorKind::WouldBlock => (),
                _ => panic!("getty: failed to wait on child: {:?}", err),
            },
        }
    }

    let _ = process.kill();
    process.wait().expect("getty: failed to wait on login");
}

pub fn getpty(columns: u16, lines: u16) -> (RawFd, String) {
    let master = redox::open(
        "/scheme/pty/ptmx",
        flag::O_CLOEXEC | flag::O_RDWR | flag::O_CREAT | flag::O_NONBLOCK,
        0,
    )
    .expect("getty: failed to create PTY");

    if let Ok(winsize_fd) = redox::dup(master, b"winsize") {
        let _ = redox::write(
            winsize_fd,
            &redox_termios::Winsize {
                ws_row: lines,
                ws_col: columns,
            },
        );
        let _ = redox::close(winsize_fd);
    }
    let _ = unsafe { grantpt(master as RawFd) };
    let _ = unsafe { unlockpt(master as RawFd) };

    let name = unsafe { ptsname(master as RawFd) };
    let count = unsafe { strlen(name) };
    let buf = unsafe { &*slice_from_raw_parts(name.cast(), count) };
    (master as RawFd, unsafe {
        String::from_utf8_unchecked(Vec::from(&buf[..count]))
    })
}

// termion cursor_pos prone to error and does not work on nonblocking files
/// Ask the terminal where the cursor is, WITHOUT eating anything the user typed meanwhile.
///
/// E-OS: the old version read from the TTY for 500 ms and dropped every byte that was not the
/// `R` terminating a cursor-position reply. On a real terminal the reply lands in microseconds
/// and nothing else is in flight, so that was invisible. On a SERIAL console there is no
/// terminal on the other end to answer `\x1B[6n` at all -- so the loop always ran the full
/// 500 ms, and anything typed in that window was read and thrown away.
///
/// Measured 2026-09-02 driving the installer over QEMU's serial socket: the `root` typed at the
/// login prompt vanished, `login` never got a username, and the password that followed was
/// echoed into a fresh login prompt and rejected. Typing SLOWER made it worse, which is the
/// signature of a window being hit rather than a buffer overflowing.
///
/// Bytes that are not part of the reply are appended to `pending` so the caller can give them
/// back. Dropping user input silently is the defect; the timeout is not.
fn tty_cursor_pos(tty: &mut File, pending: &mut Vec<u8>) -> Result<(u16, u16), Box<dyn Error>> {
    write!(tty, "\x1B[6n")?;
    tty.flush()?;

    let timeout = Duration::from_millis(500);
    let instant = Instant::now();
    let mut data = String::new();
    let mut got_reply = false;
    while instant.elapsed() < timeout {
        let mut bytes = [0];
        match tty.read(&mut bytes) {
            Ok(count) => {
                if count == 1 {
                    let c = bytes[0] as char;
                    if c == 'R' {
                        got_reply = true;
                        break;
                    }
                    data.push(c);
                }
            }
            Err(err) => {
                if err.kind() != ErrorKind::WouldBlock {
                    // Whatever was read before the error is still the user's.
                    pending.extend_from_slice(data.as_bytes());
                    return Err(err.into());
                }
            }
        }
    }

    // No reply at all: every byte read is the user's, and none of it is ours to discard.
    if !got_reply {
        pending.extend_from_slice(data.as_bytes());
        return Err("cursor position timed out".into());
    }

    if data.is_empty() {
        return Err("cursor position reply was empty".into());
    }

    // The reply is ESC [ row ; col R. Anything BEFORE the last ESC-[ arrived from the user
    // while we were waiting, and has to be handed back rather than parsed or dropped.
    let beg = match data.rfind('[') {
        Some(i) => i,
        None => {
            pending.extend_from_slice(data.as_bytes());
            return Err("failed to find [".into());
        }
    };
    let esc = data[..beg].rfind('\x1B').unwrap_or(beg);
    pending.extend_from_slice(data[..esc].as_bytes());
    let coords: String = data.chars().skip(beg + 1).collect();
    let mut nums = coords.split(';');

    let row = nums.next().ok_or("failed to find row")?.parse::<u16>()?;
    let col = nums.next().ok_or("failed to find col")?.parse::<u16>()?;

    Ok((col, row))
}

fn tty_columns_lines(
    tty: &mut File,
    pending: &mut Vec<u8>,
) -> Result<(u16, u16), Box<dyn Error>> {
    write!(tty, "{}", termion::cursor::Save)?;
    tty.flush()?;

    write!(tty, "{}", termion::cursor::Goto(999, 999))?;
    tty.flush()?;

    let res = tty_cursor_pos(tty, pending);

    write!(tty, "{}", termion::cursor::Restore)?;
    tty.flush()?;

    res
}

fn daemon(tty: &mut File, clear: bool, contain: bool, stderr: &mut Stderr) {
    // Anything typed while the terminal-size probe was waiting belongs to whoever typed it.
    // The probe used to swallow it; now it hands it back here and it is replayed into the pty,
    // so `login` reads it as if the probe had never run.
    let mut pending = Vec::new();
    let (columns, lines) =
        tty_columns_lines(tty, &mut pending).unwrap_or((DEFAULT_COLS, DEFAULT_LINES));
    let tty_fd = tty.as_raw_fd();

    let (master_fd, pty) = getpty(columns, lines);

    if !pending.is_empty() {
        let _ = redox::write(master_fd as usize, &pending);
    }

    let mut event_queue = event::RawEventQueue::new().expect("getty: failed to open event queue");

    event_queue
        .subscribe(tty_fd as usize, 0, EventFlags::READ)
        .expect("getty: failed to fevent TTY");

    event_queue
        .subscribe(master_fd as usize, 0, EventFlags::READ)
        .expect("getty: failed to fevent master PTY");

    loop {
        if clear {
            let _ = redox::write(tty_fd as usize, b"\x1Bc");
        }
        let _ = redox::fsync(tty_fd as usize);

        let slave_stdin = redox::open(&pty, flag::O_CLOEXEC | flag::O_RDONLY, 0)
            .expect("getty: failed to open slave stdin");
        let slave_stdout = redox::open(&pty, flag::O_CLOEXEC | flag::O_WRONLY, 0)
            .expect("getty: failed to open slave stdout");
        let slave_stderr = redox::open(&pty, flag::O_CLOEXEC | flag::O_WRONLY, 0)
            .expect("getty: failed to open slave stderr");

        let mut command = if contain {
            Command::new("contain_login")
        } else {
            Command::new("login")
        };
        unsafe {
            command
                .stdin(Stdio::from_raw_fd(slave_stdin as RawFd))
                .stdout(Stdio::from_raw_fd(slave_stdout as RawFd))
                .stderr(Stdio::from_raw_fd(slave_stderr as RawFd))
                .env("TERM", "xterm-256color")
                .env("TTY", &pty);
        }

        match command.spawn() {
            Ok(mut process) => {
                handle(&mut event_queue, tty_fd, master_fd, &mut process);
            }
            Err(err) => fail(&format!("getty: failed to execute login: {}", err), stderr),
        }
    }
}

pub fn main() {
    let mut stderr = io::stderr();

    let args = clap_app!(getty =>
        (author: "Jeremy Soller")
        (about: "Set terminal mode")
        (@arg TTY: +required "")
        (@arg NO_CLEAR: -J --("no-clear") "Do not clear the screen before forking")
        (@arg CONTAIN: -C --("contain") "Run contain_login instead of login")
    )
    .get_matches();

    let clear = !args.is_present("NO_CLEAR");

    let contain = args.is_present("CONTAIN");

    let vt = args.value_of("TTY").unwrap();

    let buf: String;
    let vt_path = if vt.parse::<usize>().is_ok() {
        buf = format!("/scheme/fbcon/{vt}");
        &*buf
    } else {
        vt
    };

    let mut tty = match redox::open(
        &vt_path,
        flag::O_CLOEXEC | flag::O_RDWR | flag::O_NONBLOCK,
        0,
    ) {
        Ok(fd) => unsafe { File::from_raw_fd(fd as RawFd) },
        Err(err) => fail(
            &format!("getty: failed to open TTY {}: {}", vt_path, err),
            &mut stderr,
        ),
    };

    daemon(&mut tty, clear, contain, &mut stderr);
}
