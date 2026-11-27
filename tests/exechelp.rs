//! Protocol tests for the privileged exec helper.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use secret_broker::exechelp::{self, SpawnReq};
use secret_broker::sys;
use std::os::fd::AsRawFd;
use std::path::Path;

#[test]
fn helper_refuses_uid_not_in_allowlist() {
    let exe = Path::new(env!("CARGO_BIN_EXE_secret-broker"));
    let Ok(h) = exechelp::Helper::spawn(exe, &[(u32::MAX, u32::MAX)]) else {
        return;
    };
    let n1 = std::fs::File::open("/dev/null").unwrap();
    let n2 = std::fs::File::open("/dev/null").unwrap();
    let n3 = std::fs::File::open("/dev/null").unwrap();
    let (_st_r, st_w) = sys::pipe().unwrap();
    let req = SpawnReq {
        command: "/bin/true".into(),
        args: vec![],
        extra_env: vec![],
        cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        uid: 1,
        gid: 1,
    };
    let err = h
        .start(
            &req,
            &[],
            [
                n1.as_raw_fd(),
                n2.as_raw_fd(),
                n3.as_raw_fd(),
                st_w.as_raw_fd(),
            ],
        )
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("not a configured profile user"),
        "{err}"
    );
}

#[test]
fn helper_refuses_kill_of_foreign_pid() {
    let exe = Path::new(env!("CARGO_BIN_EXE_secret-broker"));
    let Ok(h) = exechelp::Helper::spawn(exe, &[(u32::MAX, u32::MAX)]) else {
        return;
    };
    let err = h.kill(1).unwrap_err().to_string();
    assert!(err.contains("not a child"), "{err}");
}
