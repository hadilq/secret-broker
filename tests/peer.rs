//! Peer credentials and caller details of another process over a real unix
//! socket: what the broker relies on to know who is asking. Portable (Linux:
//! SO_PEERCRED + pidfd + /proc; macOS: getpeereid + LOCAL_PEERPID + libproc).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use secret_broker::{caller, sys};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};

#[test]
fn a_child_client_is_identified() {
    // Short path: sun_path is 104 bytes on macOS.
    let dir = std::env::temp_dir().join(format!("sb-peer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("s.sock");
    let listener = UnixListener::bind(&sock).unwrap();

    // The real client: it connects, sends a request and waits for our reply,
    // so it stays alive while we look at it.
    let mut child = Command::new(env!("CARGO_BIN_EXE_secret-broker"))
        .arg("status")
        .env("SECRET_BROKER_SOCKET", &sock)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let (stream, _) = listener.accept().unwrap();
    let fd = stream.as_raw_fd();

    let cred = sys::peer_cred(fd).unwrap();
    assert_eq!(cred.pid, i32::try_from(child.id()).unwrap());
    assert_eq!(cred.uid, sys::getuid());
    let pin = sys::peer_pin(fd, cred.pid);
    if !cfg!(target_os = "linux") {
        assert!(pin.is_some(), "{}", sys::NO_PEER_PIN);
    }

    let c = caller::collect_live(cred.pid);
    assert!(
        c.exe.ends_with("/secret-broker"),
        "exe {:?} {:?}",
        c.exe,
        c.notes
    );
    assert_eq!(
        c.argv.get(1).map(String::as_str),
        Some("status"),
        "{:?}",
        c.argv
    );
    assert!(!c.cwd.is_empty(), "{:?}", c.notes);
    assert!(c.start_time > 0);
    let me = i32::try_from(sys::getpid()).unwrap();
    assert_eq!(
        c.parents.first().map(|p| p.pid),
        Some(me),
        "{:?}",
        c.parents
    );
    assert_eq!(c.parents.first().map(|p| p.uid), Some(sys::getuid()));
    if let Some(p) = &pin {
        assert!(p.alive());
    }

    drop(stream);
    let _ = child.wait();
    // Exited and reaped: the pin must notice, whatever the pid becomes.
    if let Some(p) = &pin {
        assert!(!p.alive());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn socketpair_peer_is_this_process() {
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    let cred = sys::peer_cred(a.as_raw_fd()).unwrap();
    assert_eq!(u32::try_from(cred.pid).unwrap(), sys::getpid());
    assert_eq!(cred.uid, sys::getuid());
}
