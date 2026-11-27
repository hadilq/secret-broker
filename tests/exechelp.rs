//! Protocol tests for the privileged exec helper.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use secret_broker::exechelp::{self, SpawnReq};
use secret_broker::sys;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;
use zeroize::Zeroizing;

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
    assert!(err.contains("not a configured profile user"), "{err}");
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

fn helper_for_self() -> Option<exechelp::Helper> {
    let exe = Path::new(env!("CARGO_BIN_EXE_secret-broker"));
    exechelp::Helper::spawn(exe, &[(sys::getuid(), sys::getgid())]).ok()
}

fn nulls() -> [std::fs::File; 3] {
    [
        std::fs::File::open("/dev/null").unwrap(),
        std::fs::File::open("/dev/null").unwrap(),
        std::fs::File::open("/dev/null").unwrap(),
    ]
}

/// Live spawn needs setgroups; skip when the helper is unprivileged.
fn start_or_skip(
    h: &exechelp::Helper,
    req: &SpawnReq,
    secrets: &[(String, Zeroizing<Vec<u8>>)],
    fds: [i32; 4],
) -> Option<u32> {
    match h.start(req, secrets, fds) {
        Ok(pid) => Some(pid),
        Err(e) => {
            let s = e.to_string();
            if s.contains("Operation not permitted") || s.contains("not permitted") {
                eprintln!("skip: exec-helper cannot setgroups/setuid ({s})");
                None
            } else {
                panic!("helper start: {s}");
            }
        }
    }
}

#[test]
fn helper_refuses_kill_after_child_exits() {
    let Some(h) = helper_for_self() else {
        return;
    };
    let n = nulls();
    let (st_r, st_w) = sys::pipe().unwrap();
    let req = SpawnReq {
        command: "/bin/true".into(),
        args: vec![],
        extra_env: vec![],
        cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        uid: sys::getuid(),
        gid: sys::getgid(),
    };
    let Some(pid) = start_or_skip(
        &h,
        &req,
        &[],
        [
            n[0].as_raw_fd(),
            n[1].as_raw_fd(),
            n[2].as_raw_fd(),
            st_w.as_raw_fd(),
        ],
    ) else {
        return;
    };
    drop(st_w);
    let mut buf = String::new();
    std::fs::File::from(st_r).read_to_string(&mut buf).unwrap();
    assert!(buf.contains("\"code\""), "{buf}");
    let err = h.kill(pid).unwrap_err().to_string();
    assert!(err.contains("not a child"), "{err}");
}

#[test]
fn helper_secret_env_roundtrip_keeps_binary() {
    let Some(h) = helper_for_self() else {
        return;
    };
    let stdin = std::fs::File::open("/dev/null").unwrap();
    let (out_r, out_w) = sys::pipe().unwrap();
    let stderr = std::fs::File::open("/dev/null").unwrap();
    let (st_r, st_w) = sys::pipe().unwrap();
    let req = SpawnReq {
        command: "/bin/sh".into(),
        args: vec!["-c".into(), "printf %s \"$TOK\"".into()],
        extra_env: vec![],
        cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        uid: sys::getuid(),
        gid: sys::getgid(),
    };
    let tok = Zeroizing::new(b"\xffsecret-bytes".to_vec());
    let Some(_) = start_or_skip(
        &h,
        &req,
        &[("TOK".into(), tok)],
        [
            stdin.as_raw_fd(),
            out_w.as_raw_fd(),
            stderr.as_raw_fd(),
            st_w.as_raw_fd(),
        ],
    ) else {
        return;
    };
    drop(out_w);
    drop(st_w);
    let mut out = Vec::new();
    std::fs::File::from(out_r).read_to_end(&mut out).unwrap();
    assert_eq!(out, b"\xffsecret-bytes");
    let mut st = String::new();
    std::fs::File::from(st_r).read_to_string(&mut st).unwrap();
    assert!(
        st.contains("\"code\":0") || st.contains("\"code\": 0"),
        "{st}"
    );
}
