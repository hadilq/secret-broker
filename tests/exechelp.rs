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
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

fn helper(allowed: &[(u32, u32)]) -> exechelp::Helper {
    let exe = Path::new(env!("CARGO_BIN_EXE_secret-broker"));
    exechelp::Helper::spawn(exe, allowed).expect("exec-helper must start")
}

fn which(name: &str) -> String {
    let found: Option<PathBuf> = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(name))
            .find(|c| c.is_file())
    });
    found
        .unwrap_or_else(|| panic!("{name} not on PATH"))
        .to_string_lossy()
        .into_owned()
}

fn nulls() -> [std::fs::File; 3] {
    [
        std::fs::File::open("/dev/null").unwrap(),
        std::fs::File::open("/dev/null").unwrap(),
        std::fs::File::open("/dev/null").unwrap(),
    ]
}

#[test]
fn helper_starts_and_answers() {
    let h = helper(&[(u32::MAX, u32::MAX)]);
    let err = h.kill(1).unwrap_err().to_string();
    assert!(err.contains("not a child"), "{err}");
}

#[test]
fn helper_refuses_uid_not_in_allowlist() {
    let h = helper(&[(u32::MAX, u32::MAX)]);
    let n = nulls();
    let (_st_r, st_w) = sys::pipe().unwrap();
    let req = SpawnReq {
        command: which("true"),
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
                n[0].as_raw_fd(),
                n[1].as_raw_fd(),
                n[2].as_raw_fd(),
                st_w.as_raw_fd(),
            ],
        )
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a configured profile user"), "{err}");
}

#[test]
fn helper_refuses_kill_of_foreign_pid() {
    let h = helper(&[(u32::MAX, u32::MAX)]);
    let err = h.kill(1).unwrap_err().to_string();
    assert!(err.contains("not a child"), "{err}");
}

#[test]
fn helper_refuses_kill_after_child_exits() {
    let h = helper(&[(sys::getuid(), sys::getgid())]);
    let n = nulls();
    let (st_r, st_w) = sys::pipe().unwrap();
    let req = SpawnReq {
        command: which("true"),
        args: vec![],
        extra_env: vec![],
        cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        uid: sys::getuid(),
        gid: sys::getgid(),
    };
    let pid = h
        .start(
            &req,
            &[],
            [
                n[0].as_raw_fd(),
                n[1].as_raw_fd(),
                n[2].as_raw_fd(),
                st_w.as_raw_fd(),
            ],
        )
        .expect("spawn as self must work without CAP_SETUID");
    drop(st_w);
    let mut buf = String::new();
    std::fs::File::from(st_r).read_to_string(&mut buf).unwrap();
    assert!(buf.contains("\"code\""), "{buf}");
    let err = h.kill(pid).unwrap_err().to_string();
    assert!(err.contains("not a child"), "{err}");
}

#[test]
fn helper_secret_env_roundtrip_keeps_binary() {
    let h = helper(&[(sys::getuid(), sys::getgid())]);
    let stdin = std::fs::File::open("/dev/null").unwrap();
    let (out_r, out_w) = sys::pipe().unwrap();
    let stderr = std::fs::File::open("/dev/null").unwrap();
    let (st_r, st_w) = sys::pipe().unwrap();
    let req = SpawnReq {
        command: which("sh"),
        args: vec!["-c".into(), "printf %s \"$TOK\"".into()],
        extra_env: vec![],
        cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        uid: sys::getuid(),
        gid: sys::getgid(),
    };
    let tok = Zeroizing::new(b"\xffsecret-bytes".to_vec());
    h.start(
        &req,
        &[("TOK".into(), tok)],
        [
            stdin.as_raw_fd(),
            out_w.as_raw_fd(),
            stderr.as_raw_fd(),
            st_w.as_raw_fd(),
        ],
    )
    .expect("spawn as self must work without CAP_SETUID");
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
