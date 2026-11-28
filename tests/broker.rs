//! End-to-end tests of the daemon's session states and quick approval over
//! its real sockets (no gpg: the test feeds the sops data key directly).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::string_slice,
    clippy::panic_in_result_fn,
    clippy::unwrap_in_result
)]

use secret_broker::policy::CLIENT_DENY;
use secret_broker::proto::{self, Answer, Prompt, Request, Response, Status};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testdata/");

struct Daemon {
    child: Child,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Daemon {
    fn main_sock(&self) -> PathBuf {
        self.dir.join("broker.sock")
    }
    fn agent_sock(&self) -> PathBuf {
        self.dir.join("agent.sock")
    }
}

fn data_key() -> Vec<u8> {
    let kh = std::fs::read_to_string(format!("{TESTDATA}datakey.hex")).unwrap();
    let kh = kh.trim();
    (0..kh.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&kh[i..i + 2], 16).unwrap())
        .collect()
}

/// None when the environment cannot pass the secrets-file trust check
/// (e.g. "/" owned by an unmapped uid in a user namespace).
fn start(name: &str, extra: serde_json::Value) -> Option<Daemon> {
    let secrets = format!("{TESTDATA}secrets.sops.json");
    if let Err(e) = secret_broker::config::check_trusted(Path::new(&secrets)) {
        eprintln!("SKIP {name}: {e}");
        return None;
    }
    let dir = std::env::temp_dir().join(format!("sb-it-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let mut cfg = serde_json::json!({
        "secrets_file": secrets,
        "state_dir": dir.join("state"),
        "default_ttl_seconds": 600,
        "profiles": {
            "echo": {
                "command": "/bin/sh",
                "fixed_args": ["-c", "test \"$T\" = tok-123456 && echo ran"],
                "env": {"T": "api.token"},
                "allow": [["**"]]
            }
        },
        "audit": {"directory": dir.join("audit"), "journal": false},
        "approval": {
            "timeout_seconds": 20,
            "pin": {"enable": true, "min_length": 4, "max_attempts": 3,
                    "argon2_memory_kib": 64, "argon2_iterations": 1, "argon2_parallelism": 1}
        }
    });
    if let (Some(a), Some(e)) = (cfg["approval"].as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            a.insert(k.clone(), v.clone());
        }
    }
    let cfg_path = dir.join("config.json");
    std::fs::write(&cfg_path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_secret-broker"))
        .arg("daemon")
        .arg("--config")
        .arg(&cfg_path)
        .arg("--socket")
        .arg(dir.join("broker.sock"))
        .arg("--agent-socket")
        .arg(dir.join("agent.sock"))
        .spawn()
        .unwrap();
    let d = Daemon { child, dir };
    let start = Instant::now();
    while !d.agent_sock().exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "daemon did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(d)
}

fn send(sock: &Path, req: &Request, frames: &[(u8, &[u8])]) -> UnixStream {
    let mut s = UnixStream::connect(sock).unwrap();
    proto::write_json(&mut s, proto::T_JSON, req).unwrap();
    for (t, b) in frames {
        proto::write_frame(&mut s, *t, b).unwrap();
    }
    s
}

fn call(sock: &Path, req: &Request, frames: &[(u8, &[u8])]) -> Response {
    let mut s = send(sock, req, frames);
    proto::read_json(&mut s, proto::T_JSON).unwrap()
}

fn req(op: &str) -> Request {
    Request {
        op: op.into(),
        ..Default::default()
    }
}

fn status(sock: &Path) -> Status {
    call(sock, &req("status"), &[]).status.unwrap()
}

/// Run the "echo" profile; Ok(stdout) or Err(error).
fn exec(sock: &Path) -> Result<String, String> {
    exec_args(sock, &[])
}

fn exec_args(sock: &Path, args: &[&str]) -> Result<String, String> {
    exec_profile(sock, "echo", args)
}

fn exec_profile(sock: &Path, profile: &str, args: &[&str]) -> Result<String, String> {
    let mut s = send(
        sock,
        &Request {
            op: "exec".into(),
            profile: profile.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
            ..Default::default()
        },
        &[],
    );
    let r: Response = proto::read_json(&mut s, proto::T_JSON).unwrap();
    if !r.ok {
        return Err(r.error);
    }
    let mut out = Vec::new();
    loop {
        let (t, p) = proto::read_frame(&mut s).unwrap();
        match t {
            proto::T_STDOUT => out.extend_from_slice(&p),
            proto::T_EXIT => {
                let info: proto::ExitInfo = serde_json::from_slice(&p).unwrap();
                if info.code != 0 {
                    return Err(if info.error.is_empty() {
                        format!("exit {}", info.code)
                    } else {
                        info.error
                    });
                }
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            _ => {}
        }
    }
}

fn set_pin(d: &Daemon, pin: &[u8]) {
    let key = data_key();
    let r = call(
        &d.main_sock(),
        &Request {
            op: "set_pin".into(),
            phrase: "blue otter".into(),
            ..Default::default()
        },
        &[(proto::T_KEY, &key), (proto::T_PIN, pin)],
    );
    assert!(r.ok, "{}", r.error);
}

struct Dialog {
    s: UnixStream,
}

impl Dialog {
    fn register(sock: &Path) -> Dialog {
        let mut s = send(sock, &req("prompter"), &[]);
        let r: Response = proto::read_json(&mut s, proto::T_JSON).unwrap();
        assert!(r.ok, "{}", r.error);
        // Cooldown/missing-ready bugs otherwise block forever on the next prompt.
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        Dialog { s }
    }
    fn next(&mut self) -> Prompt {
        proto::read_json(&mut self.s, proto::T_JSON).unwrap()
    }
    fn pin(&mut self, id: u64, pin: &[u8]) {
        proto::write_json(&mut self.s, proto::T_JSON, &Answer { kind: "pin".into(), id }).unwrap();
        proto::write_frame(&mut self.s, proto::T_PIN, pin).unwrap();
    }
    fn ready(&mut self, id: u64) {
        proto::write_json(&mut self.s, proto::T_JSON, &Answer { kind: "ready".into(), id }).unwrap();
    }
    fn deny(&mut self, id: u64) {
        proto::write_json(&mut self.s, proto::T_JSON, &Answer { kind: "deny".into(), id }).unwrap();
    }
}

#[test]
fn states_pin_and_restricted_socket() {
    let Some(d) = start("pin", serde_json::json!({})) else { return };
    let (main, agent) = (d.main_sock(), d.agent_sock());
    let key = data_key();

    assert_eq!(status(&main).state, "cold");
    assert!(exec(&agent).unwrap_err().contains("not in memory"));

    // gpg path (data key), no quick method yet: lock wipes.
    assert!(call(&main, &req("unlock"), &[(proto::T_KEY, &key)]).ok);
    assert_eq!(status(&main).state, "open");
    assert_eq!(exec(&agent).unwrap(), "ran\n");
    // A secret value in argv is redacted in the log.
    assert_eq!(exec_args(&agent, &["--token=tok-123456"]).unwrap(), "ran\n");
    let st = status(&main);
    let owner = st.session.as_ref().unwrap().unlocked.as_ref().unwrap();
    assert_eq!((owner.method.as_str(), owner.socket.as_str()), ("gpg", "broker.sock"));
    assert!(call(&main, &req("lock"), &[]).ok);
    assert_eq!(status(&main).state, "cold");

    // Wrong data key is refused.
    let bad = vec![0u8; 32];
    assert!(!call(&main, &req("unlock"), &[(proto::T_KEY, &bad)]).ok);

    // Restricted socket: no unlock, set_pin, approve or prompter.
    for op in ["unlock", "set_pin", "approve", "prompter"] {
        let r = call(&agent, &req(op), &[(proto::T_KEY, &key)]);
        assert!(!r.ok && r.error.contains("sandbox"), "{op}: {}", r.error);
    }
    assert!(status(&agent).restricted);

    // set-pin needs the data key and unlocks.
    set_pin(&d, b"2468");
    let st = status(&main);
    assert_eq!((st.state.as_str(), st.pin_set), ("open", true));
    assert_eq!(st.methods, vec!["pin"]);
    let mode = std::fs::metadata(d.dir.join("state/auth/pin")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    // Too-short PIN refused.
    let r = call(
        &main,
        &req("set_pin"),
        &[(proto::T_KEY, &key), (proto::T_PIN, b"12")],
    );
    assert!(!r.ok);

    // lock now seals.
    assert!(call(&main, &req("lock"), &[]).ok);
    assert_eq!(status(&main).state, "sealed");
    assert!(exec(&agent).unwrap_err().contains("no approval dialog"));

    // Dialog approves with the PIN (after one wrong try).
    let mut dlg = Dialog::register(&main);
    assert!(status(&main).prompter);
    let agent2 = agent.clone();
    let t = std::thread::spawn(move || exec(&agent2));
    let p = dlg.next();
    assert_eq!(p.kind, "request");
    assert_eq!(p.phrase, "blue otter");
    assert!(p.requester.as_ref().unwrap().sandboxed);
    assert!(p.purpose.contains("secret-run echo"));
    // The broker's own snapshot of the caller (this test process).
    let c = p.caller.as_ref().unwrap();
    assert!(c.sandboxed && c.socket == "agent.sock");
    assert!(c.verified, "{:?}", c.notes);
    assert!(!c.exe.is_empty() && !c.cwd.is_empty() && !c.argv.is_empty(), "{c:?}");
    assert!(!c.parents.is_empty());
    let sess = p.session.as_ref().unwrap();
    assert_eq!(sess.state, "sealed");
    assert_eq!(sess.unlocked.as_ref().unwrap().method, "gpg");
    dlg.pin(p.id, b"0000");
    let u = dlg.next();
    assert_eq!(u.kind, "update");
    assert!(u.message.contains("Wrong PIN"), "{}", u.message);
    // Backoff applies from the 2nd failure on; the right PIN works now.
    dlg.pin(p.id, b"2468");
    let done = dlg.next();
    assert!(done.ok, "{}", done.message);
    assert_eq!(t.join().unwrap().unwrap(), "ran\n");
    assert_eq!(status(&main).state, "open");

    // Deny.
    assert!(call(&main, &req("lock"), &[]).ok);
    let agent2 = agent.clone();
    let t = std::thread::spawn(move || exec(&agent2));
    let p = dlg.next();
    dlg.deny(p.id);
    assert!(!dlg.next().ok);
    assert!(t.join().unwrap().unwrap_err().contains("denied"));
    assert_eq!(status(&main).state, "sealed");
    // deny cooldown: a follow-up is refused without opening a dialog
    let e = exec(&agent).unwrap_err();
    assert!(e.contains("denied recently"), "{e}");
    std::thread::sleep(Duration::from_secs(4));

    // Lockout: 3 wrong PINs wipe the secrets (back to gpg).
    let agent2 = agent.clone();
    let t = std::thread::spawn(move || exec(&agent2));
    let p = dlg.next();
    for i in 0..3 {
        if i > 0 {
            // wait out the backoff
            std::thread::sleep(Duration::from_millis(1100 * (1 << (i - 1))));
        }
        dlg.pin(p.id, b"9999");
        let m = dlg.next();
        if i < 2 {
            assert_eq!(m.kind, "update", "{}", m.message);
        } else {
            assert_eq!(m.kind, "done");
            assert!(!m.ok && m.message.contains("Too many"), "{}", m.message);
        }
    }
    assert!(t.join().unwrap().is_err());
    let st = status(&main);
    assert_eq!(st.state, "cold");

    // gpg again resets; lock --forget wipes even with a PIN set.
    assert!(call(&main, &req("unlock"), &[(proto::T_KEY, &key)]).ok);
    assert!(!status(&main).pin_locked_out);
    assert!(call(&main, &Request { op: "lock".into(), forget: true, ..Default::default() }, &[]).ok);
    assert_eq!(status(&main).state, "cold");
    drop(dlg);
    // Client-side events (fido2-enroll) can be reported, not from a sandbox.
    let rep = Request {
        op: "report".into(),
        event: "fido2_enroll".into(),
        details: [("name".to_string(), "yubikey".to_string()), ("credential_id".to_string(), "Y3JlZA==".to_string())]
            .into_iter()
            .collect(),
        ..Default::default()
    };
    assert!(call(&main, &rep, &[]).ok);
    assert!(!call(&agent, &rep, &[]).ok);
    check_audit(&d);
}

#[test]
fn untrusted_prompter_is_refused() {
    let Some(d) = start(
        "prompter-exe",
        serde_json::json!({"prompter_exe": "/nonexistent/secret-broker-dialog"}),
    ) else {
        return;
    };
    let r = call(&d.main_sock(), &req("prompter"), &[]);
    assert!(!r.ok, "{}", r.error);
    assert!(
        r.error.contains("approval dialog must be") || r.error.contains("/nonexistent"),
        "{}",
        r.error
    );
    assert!(!status(&d.main_sock()).prompter);
}

#[test]
fn trusted_prompter_exe_still_gets_the_phrase() {
    let me = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
        .map(|p| p.to_string_lossy().into_owned());
    let Some(me) = me else { return };
    let Some(d) = start(
        "prompter-ok",
        serde_json::json!({"prompter_exe": me}),
    ) else {
        return;
    };
    let (main, agent) = (d.main_sock(), d.agent_sock());
    set_pin(&d, b"2468");
    assert!(call(&main, &req("lock"), &[]).ok);
    let mut dlg = Dialog::register(&main);
    assert!(status(&main).prompter);
    let t = std::thread::spawn(move || exec(&agent));
    let p = dlg.next();
    assert_eq!(p.kind, "request");
    assert_eq!(p.phrase, "blue otter");
    dlg.pin(p.id, b"2468");
    assert!(dlg.next().ok);
    assert_eq!(t.join().unwrap().unwrap(), "ran\n");
}

#[test]
fn deny_tokens_refuse_exec_even_with_globstar_allow() {
    let secrets = format!("{TESTDATA}secrets.sops.json");
    if secret_broker::config::check_trusted(Path::new(&secrets)).is_err() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sb-it-deny-tok-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let cfg = serde_json::json!({
        "secrets_file": secrets,
        "state_dir": dir.join("state"),
        "default_ttl_seconds": 600,
        "profiles": {
            "gh": {
                "command": "/bin/echo",
                "allow": [["pr", "list", "**"]],
                "deny_tokens": ["--hostname", "--hostname=*", "--debug"]
            }
        },
        "audit": {"directory": dir.join("audit"), "journal": false}
    });
    let cfg_path = dir.join("config.json");
    std::fs::write(&cfg_path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_secret-broker"))
        .arg("daemon")
        .arg("--config")
        .arg(&cfg_path)
        .arg("--socket")
        .arg(dir.join("broker.sock"))
        .arg("--agent-socket")
        .arg(dir.join("agent.sock"))
        .spawn()
        .unwrap();
    let d = Daemon { child, dir };
    let start = Instant::now();
    while !d.agent_sock().exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "daemon did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    let (main, agent) = (d.main_sock(), d.agent_sock());
    let key = data_key();
    assert!(call(&main, &req("unlock"), &[(proto::T_KEY, &key)]).ok);
    let ok = exec_profile(&agent, "gh", &["pr", "list"]);
    assert!(ok.is_ok(), "{ok:?}");
    let e = exec_profile(&agent, "gh", &["pr", "list", "--hostname", "evil.com"]).unwrap_err();
    assert_eq!(e, CLIENT_DENY, "{e}");
    assert!(!e.contains("evil.com") && !e.contains("--hostname"), "{e}");
    let e = exec_profile(&agent, "gh", &["pr", "list", "--debug"]).unwrap_err();
    assert_eq!(e, CLIENT_DENY, "{e}");
    assert!(!e.contains("--debug"), "{e}");
}

#[test]
fn exec_timeout_kills_the_child() {
    let secrets = format!("{TESTDATA}secrets.sops.json");
    if secret_broker::config::check_trusted(Path::new(&secrets)).is_err() {
        return;
    }
    let dir = std::env::temp_dir().join(format!("sb-it-timeout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    let cfg = serde_json::json!({
        "secrets_file": secrets,
        "state_dir": dir.join("state"),
        "default_ttl_seconds": 600,
        "profiles": {
            "nap": {
                "command": "/bin/sleep",
                "allow": [["**"]],
                "timeout_seconds": 1
            }
        },
        "audit": {"directory": dir.join("audit"), "journal": false}
    });
    let cfg_path = dir.join("config.json");
    std::fs::write(&cfg_path, serde_json::to_vec(&cfg).unwrap()).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_secret-broker"))
        .arg("daemon")
        .arg("--config")
        .arg(&cfg_path)
        .arg("--socket")
        .arg(dir.join("broker.sock"))
        .arg("--agent-socket")
        .arg(dir.join("agent.sock"))
        .spawn()
        .unwrap();
    let d = Daemon { child, dir };
    let start = Instant::now();
    while !d.agent_sock().exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "daemon did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    let (main, agent) = (d.main_sock(), d.agent_sock());
    let key = data_key();
    assert!(call(&main, &req("unlock"), &[(proto::T_KEY, &key)]).ok);
    let t0 = Instant::now();
    let e = exec_profile(&agent, "nap", &["30"]).unwrap_err();
    assert!(t0.elapsed() < Duration::from_secs(8), "{e} {:?}", t0.elapsed());
    assert!(e.contains("timeout") || e.contains("137") || e.contains("killed"), "{e}");
}

fn check_audit(d: &Daemon) {
    use secret_broker::audit;
    let dir = d.dir.join("audit");
    let lines = audit::read_all(&dir).unwrap();
    let r = audit::verify(&lines);
    assert!(r.problems.is_empty(), "{:?}", r.problems);
    assert_eq!(r.first_seq, 1);
    let mode = std::fs::metadata(dir.join(audit::FILE)).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o640);
    let raw: String = lines.iter().map(|l| l.raw.clone() + "\n").collect();
    assert!(!raw.contains("tok-123456"), "secret value in the audit log");
    assert!(raw.contains("--token=[REDACTED]"));
    let has = |event: &str, outcome: &str, extra: &dyn Fn(&serde_json::Value) -> bool| {
        lines.iter().filter_map(|l| l.value.as_ref()).any(|v| {
            v["event"] == event && v["outcome"] == outcome && extra(v)
        })
    };
    let any = |_: &serde_json::Value| true;
    assert!(has("broker_start", "ok", &any));
    assert!(has("unlock", "ok", &|v| v["method"] == "gpg" && v["caller"]["socket"] == "broker.sock"));
    assert!(has("unlock", "failed", &any));
    assert!(has("unlock", "refused", &|v| v["caller"]["socket"] == "agent.sock"));
    assert!(has("set_pin", "refused", &any));
    assert!(has("prompter_register", "refused", &any));
    assert!(has("set_pin", "ok", &any));
    assert!(has("set_pin", "failed", &any));
    assert!(has("exec", "refused", &|v| v["reason"].as_str().unwrap_or("").contains("not in memory")));
    assert!(has("exec_start", "started", &|v| v["profile"] == "echo"));
    assert!(has("exec_end", "ok", &|v| v["exit_code"] == 0 && v["duration_ms"].is_u64()));
    assert!(has("lock", "wiped", &|v| v["forget"] == false));
    assert!(has("lock", "wiped", &|v| v["forget"] == true));
    assert!(has("lock", "sealed", &any));
    assert!(has("prompter_register", "ok", &any));
    assert!(has("approval", "granted", &|v| v["method"] == "pin" && v["via"] == "dialog"));
    assert!(has("approval", "denied", &any));
    assert!(has("pin_wrong", "failed", &any));
    assert!(has("pin_lockout", "wiped", &any));
    assert!(has("fido2_enroll", "reported", &|v| v["name"] == "yubikey" && v["credential_id"] == "Y3JlZA=="));
    assert!(has("report", "refused", &any));
    // Caller details from the /proc helper.
    assert!(has("exec_end", "ok", &|v| {
        let c = &v["caller"];
        c["exe"].as_str().is_some_and(|e| !e.is_empty())
            && c["cwd"].as_str().is_some_and(|e| !e.is_empty())
            && c["parents"].as_array().is_some_and(|p| !p.is_empty())
            && c["verified"] == true
    }));
    // `secret-broker log` and `log verify` on it.
    let bin = env!("CARGO_BIN_EXE_secret-broker");
    let out = Command::new(bin).args(["log", "--dir"]).arg(&dir).args(["--event", "approval"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success() && text.contains("approval granted method=pin"), "{text}");
    assert!(!text.contains("exec_end"));
    let out = Command::new(bin).args(["log", "verify", "--dir"]).arg(&dir).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stdout));
    // Tampering is detected.
    let f = dir.join(audit::FILE);
    let t = std::fs::read_to_string(&f).unwrap();
    std::fs::write(&f, t.replacen("\"outcome\":\"denied\"", "\"outcome\":\"granted\"", 1)).unwrap();
    let out = Command::new(bin).args(["log", "verify", "--dir"]).arg(&dir).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn ttl_expiry_seals() {
    let Some(d) = start("ttl", serde_json::json!({})) else { return };
    let main = d.main_sock();
    set_pin(&d, b"1357");
    let key = data_key();
    let r = call(
        &main,
        &Request { op: "unlock".into(), ttl_seconds: Some(1), ..Default::default() },
        &[(proto::T_KEY, &key)],
    );
    assert!(r.ok);
    std::thread::sleep(Duration::from_millis(1600));
    assert_eq!(status(&main).state, "sealed");
}

fn write_script(path: &Path, body: &str) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(body.as_bytes()).unwrap();
    drop(f);
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn fido2_mock_touch() {
    let tools = std::env::temp_dir().join(format!("sb-fido2-mock-{}", std::process::id()));
    std::fs::create_dir_all(&tools).unwrap();
    let touch = tools.join("touch");
    let _ = std::fs::remove_file(&touch);
    write_script(
        &tools.join("fido2-token"),
        "#!/bin/sh\necho '/dev/hidraw-mock: vendor=0x1050, product=0x0407 (Mock)'\n",
    );
    // -G: wait for a "touch", echo the challenge and rp back with fake data.
    // -V: accept only if the input carries the mock signature.
    write_script(
        &tools.join("fido2-assert"),
        &format!(
            "#!/bin/sh\nif [ \"$1\" = -G ]; then read cdh; read rp; read cred\n\
             [ \"$cred\" = Y3JlZA== ] || exit 1\n\
             while [ ! -e '{t}' ]; do sleep 0.1; done\n\
             printf '%s\\n%s\\nQVVUSA==\\nTU9DS1NJRw==\\n' \"$cdh\" \"$rp\"; exit 0; fi\n\
             if [ \"$1\" = -V ]; then read a; read b; read c; read sig; [ \"$sig\" = TU9DS1NJRw== ]; exit $?; fi\nexit 2\n",
            t = touch.display()
        ),
    );
    let pk = tools.join("pk.pem");
    std::fs::write(&pk, "-----BEGIN PUBLIC KEY-----\nmock\n-----END PUBLIC KEY-----\n").unwrap();
    let Some(d) = start(
        "fido2",
        serde_json::json!({"fido2": {"tools_dir": tools, "credentials": [
            {"name": "mock", "id": "Y3JlZA==", "public_key_file": pk}
        ]}}),
    ) else {
        let _ = std::fs::remove_dir_all(&tools);
        return;
    };
    let (main, agent) = (d.main_sock(), d.agent_sock());
    let key = data_key();
    assert!(call(&main, &req("unlock"), &[(proto::T_KEY, &key)]).ok);
    assert!(call(&main, &req("lock"), &[]).ok);
    let st = status(&main);
    assert_eq!((st.state.as_str(), st.methods.clone()), ("sealed", vec!["fido2".to_string()]));

    let mut dlg = Dialog::register(&main);
    let t = std::thread::spawn(move || exec(&agent));
    let p = dlg.next();
    assert_eq!(p.methods, vec!["fido2"]);
    assert!(p.hints.iter().any(|h| h.contains("security key")));
    // FIDO2 is armed only after the UI is showing.
    dlg.ready(p.id);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(status(&main).state, "sealed", "approved before the touch");
    std::fs::write(&touch, "").unwrap();
    let done = loop {
        let m = dlg.next();
        if m.kind == "done" {
            break m;
        }
    };
    assert!(done.ok, "{}", done.message);
    assert!(done.message.contains("fido2"));
    assert_eq!(t.join().unwrap().unwrap(), "ran\n");
    let _ = std::fs::remove_dir_all(&tools);
}
