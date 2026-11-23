//! `secret-broker-dialog pinentry`: a pinentry (Assuan protocol on
//! stdin/stdout) with the same look, for gpg-agent's one passphrase prompt
//! at the first unlock after boot. Without a Wayland display it execs the
//! fallback pinentry (e.g. pinentry-curses) before speaking any protocol.

use crate::ui::{Tone, Ui, UiEvent, View};
use crate::Opts;
use std::io::{BufRead, Write};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const ERR_CANCELED: &str = "ERR 83886179 Operation cancelled <Pinentry>";
const ERR_NOT_CONFIRMED: &str = "ERR 83886194 Not confirmed <Pinentry>";

/// Assuan percent-decoding.
pub fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = b
                .get(i.saturating_add(1)..i.saturating_add(3))
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(v) = hex {
                out.push(v);
                i = i.saturating_add(3);
                continue;
            }
        }
        out.push(c);
        i = i.saturating_add(1);
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Assuan percent-encoding for D lines.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\r' => out.push_str("%0D"),
            '\n' => out.push_str("%0A"),
            c => out.push(c),
        }
    }
    out
}

#[derive(Default)]
struct St {
    title: String,
    desc: String,
    prompt: String,
    error: String,
    repeat: Option<String>,
    repeat_error: String,
    timeout: u64,
}

fn wayland_available() -> bool {
    smithay_client_toolkit::reexports::client::Connection::connect_to_env().is_ok()
}

fn view(st: &St, prompt: &str, error: &str, field: bool, footer: &str) -> View {
    View {
        title: if st.title.is_empty() { "Unlock".into() } else { st.title.clone() },
        body: st.desc.clone(),
        field: field.then(|| {
            let p = prompt.trim().trim_end_matches(':').trim();
            if p.is_empty() { "Passphrase".to_string() } else { p.to_string() }
        }),
        message: (!error.is_empty()).then(|| (error.to_string(), Tone::Error)),
        footer: footer.into(),
        deadline: (st.timeout > 0)
            .then(|| Instant::now().checked_add(Duration::from_secs(st.timeout)))
            .flatten(),
        ..Default::default()
    }
}

/// Show one dialog; Some(input) on Enter, None on cancel/timeout.
fn ask(opts: &Opts, v: View) -> Result<Option<Zeroizing<String>>, String> {
    let fonts = crate::load_fonts(opts)?;
    let theme = crate::theme::load(opts.theme.as_deref());
    let deadline = v.deadline;
    let mut ui = Ui::open(theme, fonts, opts.size())?;
    ui.set_view(v);
    loop {
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Ok(None);
        }
        match ui.wait(None)? {
            UiEvent::Submit(s) => return Ok(Some(s)),
            UiEvent::Cancel | UiEvent::Closed => return Ok(None),
            UiEvent::Readable | UiEvent::Tick => {}
        }
    }
}

fn getpin(opts: &Opts, st: &St) -> Result<Option<(Zeroizing<String>, bool)>, String> {
    let mut error = st.error.clone();
    loop {
        let Some(a) = ask(opts, view(st, &st.prompt, &error, true, "Enter  OK      Esc  cancel"))? else {
            return Ok(None);
        };
        let Some(rp) = &st.repeat else {
            return Ok(Some((a, false)));
        };
        let Some(b) = ask(opts, view(st, rp, "", true, "Enter  OK      Esc  cancel"))? else {
            return Ok(None);
        };
        if a.as_str() == b.as_str() {
            return Ok(Some((a, true)));
        }
        error = if st.repeat_error.is_empty() {
            "Passphrases do not match".into()
        } else {
            st.repeat_error.clone()
        };
    }
}

pub fn run(opts: &Opts, argv: &[String]) -> std::process::ExitCode {
    if !wayland_available() {
        if let Some(fb) = &opts.fallback {
            use std::os::unix::process::CommandExt;
            let e = std::process::Command::new(fb).args(argv).exec();
            eprintln!("secret-broker-dialog: exec {fb}: {e}");
        }
        eprintln!("secret-broker-dialog: no Wayland display and no --fallback pinentry");
        return std::process::ExitCode::from(1);
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    let say = |out: &mut std::io::StdoutLock<'_>, s: &str| -> bool {
        writeln!(out, "{s}").and_then(|()| out.flush()).is_ok()
    };
    if !say(&mut out, "OK Pleased to meet you") {
        return std::process::ExitCode::from(1);
    }
    let mut st = St::default();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let (cmd, arg) = line.split_once(' ').unwrap_or((line.as_str(), ""));
        let arg = unescape(arg);
        let reply: String = match cmd.to_ascii_uppercase().as_str() {
            "SETTITLE" => {
                st.title = arg;
                "OK".into()
            }
            "SETDESC" => {
                st.desc = arg;
                "OK".into()
            }
            "SETPROMPT" => {
                st.prompt = arg;
                "OK".into()
            }
            "SETERROR" => {
                st.error = arg;
                "OK".into()
            }
            "SETREPEAT" => {
                st.repeat = Some(if arg.is_empty() { "Repeat".into() } else { arg });
                "OK".into()
            }
            "SETREPEATERROR" => {
                st.repeat_error = arg;
                "OK".into()
            }
            "SETTIMEOUT" => {
                st.timeout = arg.trim().parse().unwrap_or(0);
                "OK".into()
            }
            "GETINFO" => match arg.trim() {
                "version" => format!("D {}\nOK", env!("CARGO_PKG_VERSION")),
                "pid" => format!("D {}\nOK", std::process::id()),
                "flavor" => "D secret-broker\nOK".into(),
                "ttyinfo" => "D - - -\nOK".into(),
                _ => "OK".into(),
            },
            "GETPIN" => {
                let r = getpin(opts, &st);
                st.error.clear();
                match r {
                    Ok(Some((pin, repeated))) => {
                        let mut s = Zeroizing::new(String::new());
                        if !pin.is_empty() {
                            s.push_str("D ");
                            s.push_str(&escape(&pin));
                            s.push('\n');
                        }
                        if repeated {
                            s.push_str("S PIN_REPEATED\n");
                        }
                        s.push_str("OK");
                        let ok = say(&mut out, &s);
                        if !ok {
                            break;
                        }
                        continue;
                    }
                    Ok(None) => ERR_CANCELED.into(),
                    Err(e) => {
                        eprintln!("secret-broker-dialog: {e}");
                        ERR_CANCELED.into()
                    }
                }
            }
            "CONFIRM" | "MESSAGE" => {
                let one = cmd.eq_ignore_ascii_case("MESSAGE") || arg.contains("--one-button");
                let footer = if one { "Enter  OK" } else { "Enter  OK      Esc  cancel" };
                let err = std::mem::take(&mut st.error);
                match ask(opts, view(&st, "", &err, false, footer)) {
                    Ok(Some(_)) => "OK".into(),
                    _ if one => "OK".into(),
                    _ => ERR_NOT_CONFIRMED.into(),
                }
            }
            "RESET" => {
                st = St::default();
                "OK".into()
            }
            "BYE" => {
                let _ = say(&mut out, "OK closing connection");
                break;
            }
            // OPTION, SETOK, SETCANCEL, SETNOTOK, SETKEYINFO, SETQUALITYBAR... accepted, ignored.
            _ => "OK".into(),
        };
        if !say(&mut out, &reply) {
            break;
        }
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn assuan_escaping() {
        assert_eq!(unescape("Please enter%0Athe passphrase%25 %zz"), "Please enter\nthe passphrase% %zz");
        assert_eq!(escape("a%b\nc\r"), "a%25b%0Ac%0D");
        assert_eq!(unescape(&escape("x%y\nz")), "x%y\nz");
    }
}
