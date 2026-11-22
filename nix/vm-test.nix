# NixOS VM test. Generates a throwaway gpg key inside the VM.
{ self }:
{ pkgs, lib, ... }:
let
  secret = "s3cr3t-Value-0123456789";
  demoTool = pkgs.writeShellScript "demo-tool" ''
    case "$1" in
      hash)   printf '%s' "$DEMO_TOKEN" | sha256sum | cut -d' ' -f1 ;;
      leak)   echo "token=$DEMO_TOKEN" ;;
      whoami) id -un ;;
      cat)    cat ;;
      sleep)  exec sleep 120 ;;
      *)      exit 3 ;;
    esac
  '';
  sb = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
  dialog = self.packages.${pkgs.stdenv.hostPlatform.system}.secret-broker-dialog;

  # Stand-ins for libfido2's tools: a "key" that answers once
  # /run/fido2-mock/touch exists, and a verifier that accepts only its
  # signature. The broker still checks challenge and rp itself.
  fido2Mock = pkgs.symlinkJoin {
    name = "fido2-mock";
    paths = [
      (pkgs.writeShellScriptBin "fido2-token" "echo '/dev/hidraw-mock: vendor=0x1050, product=0x0407 (Mock)'")
      (pkgs.writeShellScriptBin "fido2-assert" ''
        if [ "$1" = -G ]; then
          read cdh; read rp; read cred
          [ "$cred" = Y3JlZA== ] || exit 1
          while [ ! -e /run/fido2-mock/touch ]; do sleep 0.1; done
          printf '%s\n%s\nQVVUSA==\nTU9DS1NJRw==\n' "$cdh" "$rp"
          exit 0
        fi
        if [ "$1" = -V ]; then
          read a; read b; read c; read sig
          [ "$sig" = TU9DS1NJRw== ]
          exit $?
        fi
        exit 2
      '')
    ];
  };
  pamMock = pkgs.writeShellScript "pam-mock" "test -e /run/pam-mock/ok";

  # Plays the approval dialog over the real socket:
  #   fake-dialog <log> pin 1111,2468 | deny | wait   [socket]
  fakeDialog = pkgs.writers.writePython3 "fake-dialog" { } ''
    import json
    import socket
    import struct
    import sys
    import time

    log, mode = sys.argv[1], sys.argv[2]
    arg = sys.argv[3] if len(sys.argv) > 3 else ""
    path = sys.argv[4] if len(sys.argv) > 4 else "/run/secret-broker/broker.sock"


    def wf(s, t, b):
        s.sendall(t + struct.pack(">I", len(b)) + b)


    def recvn(s, n):
        b = b""
        while len(b) < n:
            c = s.recv(n - len(b))
            if not c:
                raise SystemExit("eof")
            b += c
        return b


    def rf(s):
        h = recvn(s, 5)
        return h[:1], recvn(s, struct.unpack(">I", h[1:])[0])


    def note(x):
        with open(log, "a") as f:
            f.write(json.dumps(x) + "\n")


    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    wf(s, b"J", json.dumps({"op": "prompter"}).encode())
    t, p = rf(s)
    r = json.loads(p)
    note({"register": r})
    if not r.get("ok"):
        sys.exit(3)
    while True:
        t, p = rf(s)
        m = json.loads(p)
        note(m)
        if m["kind"] == "request":
            rid = m["id"]
            if mode == "pin":
                for i, pin in enumerate(arg.split(",")):
                    if i > 1:
                        time.sleep(2 ** (i - 1) + 0.3)
                    wf(s, b"J", json.dumps({"kind": "pin", "id": rid}).encode())
                    wf(s, b"P", pin.encode())
            elif mode == "deny":
                wf(s, b"J", json.dumps({"kind": "deny", "id": rid}).encode())
        elif m["kind"] == "done":
            sys.exit(0 if m["ok"] else 1)
  '';

  swayConfig = pkgs.writeText "sway-test.conf" ''
    output HEADLESS-1 resolution 1280x800 scale 1
    output * bg #0f1e19 solid_color
  '';
  font = "${pkgs.dejavu_fonts}/share/fonts/truetype/DejaVuSans.ttf";
  fontBold = "${pkgs.dejavu_fonts}/share/fonts/truetype/DejaVuSans-Bold.ttf";
  aiRunConfig = pkgs.writeText "ai-run.json" (builtins.toJSON {
    bwrap = "${pkgs.bubblewrap}/bin/bwrap";
    dbus_proxy = "${pkgs.xdg-dbus-proxy}/bin/xdg-dbus-proxy";
    mask = [ ".gnupg" ".config/gh" ".zsh_history" ".agent-login" "/run/docker.sock" "/run/secret-broker/broker.sock" ];
    env.SECRET_BROKER_SOCKET = "/run/secret-broker/agent.sock";
    writable = [ "dev" ];
    env_unset = [ "DISPLAY" ];
    env_deny = [ "*TOKEN*" ];
    profiles = {
      default = { };
      agent = { unmask = [ ".agent-login" ]; writable = [ ".agent-login" ]; };
      bus = { dbus = { talk = [ "org.example.Allowed" ]; }; };
    };
  });
  aiRun = pkgs.writeShellScriptBin "ai-run" ''
    exec ${sb}/bin/ai-run --config ${aiRunConfig} "$@"
  '';
  # Owns org.example.Allowed and org.freedesktop.secrets on a session bus.
  fakeServices = pkgs.writers.writePython3 "fake-services" {
    flakeIgnore = [ "F821" ]; # dbus-next signature annotations ("s")
    libraries = [ pkgs.python3Packages.dbus-next ];
  } ''
    import asyncio
    from dbus_next.aio import MessageBus
    from dbus_next.service import ServiceInterface, method


    class Svc(ServiceInterface):
        def __init__(self):
            super().__init__("org.example.I")

        @method()
        def Hello(self) -> "s":
            return "hi"


    async def main():
        bus = await MessageBus().connect()
        bus.export("/o", Svc())
        await bus.request_name("org.example.Allowed")
        await bus.request_name("org.freedesktop.secrets")
        print("ready", flush=True)
        await asyncio.get_event_loop().create_future()

    asyncio.run(main())
  '';
in
{
  name = "secret-broker";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    users.users.hadi = { isNormalUser = true; uid = 1000; };
    users.users.other = { isNormalUser = true; uid = 1001; };
    environment.systemPackages = [
      pkgs.sops pkgs.gnupg pkgs.strace pkgs.procps pkgs.glib.bin pkgs.dbus (lib.hiPrio aiRun)
      dialog pkgs.sway pkgs.wtype pkgs.grim
    ];
    virtualisation.memorySize = 2048;
    services.secret-broker = {
      enable = true;
      users = [ "hadi" ];
      secretsFile = "/etc/secret-broker/secrets.sops.json";
      profiles.demo = {
        command = "${demoTool}";
        env.DEMO_TOKEN = "demo.token";
        path = [ pkgs.coreutils ];
        allow = [ [ "hash" ] [ "leak" ] [ "whoami" ] [ "cat" ] [ "sleep" ] ];
        deny = [ [ "env" ] ];
      };
      approval = {
        timeout = 30;
        pin.minLength = 4;
        pin.maxAttempts = 4;
        fido2 = {
          package = fido2Mock;
          credentials = [ {
            name = "mock";
            id = "Y3JlZA==";
            publicKey = "-----BEGIN PUBLIC KEY-----\nmock\n-----END PUBLIC KEY-----\n";
          } ];
        };
        pam.mock = {
          label = "Mock sensor";
          retries = 2;
          text = ''
            auth    required pam_exec.so quiet ${pamMock}
            account required pam_permit.so
          '';
        };
      };
      profiles.disabled = {
        enable = false;
        command = "${pkgs.coreutils}/bin/env";
        allow = [ [ "**" ] ];
      };
    };
  };

  testScript = ''
    import hashlib, shlex
    SECRET = "${secret}"

    def h(cmd):
        return "su - hadi -c " + shlex.quote(cmd)

    machine.wait_for_unit("sockets.target")
    machine.wait_for_file("/run/secret-broker/broker.sock")

    with subtest("prepare a sops file encrypted to a test gpg key"):
        machine.succeed(h("gpg --batch --pinentry-mode loopback --passphrase ''' --quick-gen-key 'Test <t@example.org>' default default never"))
        fp = machine.succeed(h("gpg --with-colons --list-keys t@example.org | awk -F: '/^fpr/{print $10; exit}'")).strip()
        machine.succeed(h(f"""printf '%s' '{{"demo":{{"token":"{SECRET}"}},"other":"zz-other-value"}}' > /tmp/plain.json"""))
        machine.succeed(h(f"sops encrypt --pgp {fp} --input-type json --output-type json /tmp/plain.json > /tmp/enc.json && rm /tmp/plain.json"))
        machine.succeed("install -D -m0644 /tmp/enc.json /etc/secret-broker/secrets.sops.json")

    with subtest("locked by default"):
        st = machine.succeed(h("secret-broker status"))
        assert "locked (not in memory" in st, st
        assert "approval: fido2, mock" in st, st
        machine.fail(h("secret-run demo hash"))

    with subtest("only group members may connect"):
        machine.fail("su - other -c 'secret-broker status'")

    with subtest("a long gpg-agent passphrase cache is refused"):
        machine.succeed(h("printf 'default-cache-ttl 2592000\\nmax-cache-ttl 2592000\\n' > ~/.gnupg/gpg-agent.conf && gpgconf --kill gpg-agent"))
        st = machine.succeed(h("secret-broker status"))
        assert "WARNING: unlock will be refused" in st, st
        out = machine.fail(h("secret-broker unlock --ttl 1h 2>&1"))
        assert "too long" in out and "2592000" in out, out
        assert "locked" in machine.succeed(h("secret-broker status"))
        machine.succeed(h("rm ~/.gnupg/gpg-agent.conf && gpgconf --kill gpg-agent"))
        assert "WARNING" not in machine.succeed(h("secret-broker status"))

    with subtest("unlock (session approval) and use"):
        machine.succeed(h("secret-broker unlock --ttl 1h"))
        out = machine.succeed(h("secret-run demo hash")).strip()
        assert out == hashlib.sha256(SECRET.encode()).hexdigest(), out
        assert machine.succeed(h("secret-run demo whoami")).strip() == "agent-secrets"
        assert machine.succeed(h("echo hi | secret-run demo cat")).strip() == "hi"

    with subtest("no command returns the secret"):
        leak = machine.succeed(h("secret-run demo leak"))
        assert SECRET not in leak and "[REDACTED]" in leak, leak
        machine.fail(h("secret-run demo env"))
        machine.fail(h("secret-run demo printenv"))
        machine.fail(h("secret-run disabled"))
        for c in ["secret-broker status", "secret-broker status --json"]:
            assert SECRET not in machine.succeed(h(c))
        assert SECRET not in machine.succeed("journalctl -u secret-broker --no-pager")

    with subtest("caller cannot read the child's or the broker's memory/environment"):
        machine.succeed(h("nohup secret-run demo sleep >/dev/null 2>&1 &"))
        machine.wait_until_succeeds("pgrep -u agent-secrets -x sleep")
        pid = machine.succeed("pgrep -u agent-secrets -x sleep | head -1").strip()
        # sanity: the secret really is in the child's environment (root can see it)
        machine.succeed(f"tr '\\0' '\\n' < /proc/{pid}/environ | grep -q '^DEMO_TOKEN='")
        machine.fail(h(f"cat /proc/{pid}/environ"))
        machine.fail(h(f"exec 3< /proc/{pid}/mem"))
        machine.succeed(h(f"timeout 5 strace -p {pid} 2>&1 | grep -q 'Operation not permitted'"))
        bpid = machine.succeed("systemctl show -p MainPID --value secret-broker").strip()
        machine.fail(h(f"cat /proc/{bpid}/environ"))
        machine.fail(h(f"exec 3< /proc/{bpid}/mem"))
        machine.succeed(h(f"timeout 5 strace -p {bpid} 2>&1 | grep -q 'Operation not permitted'"))
        machine.succeed("pkill -u agent-secrets -x sleep || true")

    with subtest("ai-run: credentials masked, home read-only, broker reachable"):
        machine.succeed(h("mkdir -p ~/.config/gh ~/dev ~/.agent-login && chmod 700 ~/.gnupg"))
        machine.succeed(h("echo gh-token-SENTINEL > ~/.config/gh/hosts.yml && echo hist-SENTINEL > ~/.zsh_history && echo agent-SENTINEL > ~/.agent-login/auth"))
        machine.succeed("touch /run/docker.sock")
        # outside the sandbox, hadi can read them (that's the problem)
        machine.succeed(h("cat ~/.config/gh/hosts.yml >/dev/null && test -n \"$(ls -A ~/.gnupg)\""))
        out = machine.succeed(h("ai-run -- sh -c 'cat ~/.config/gh/hosts.yml ~/.zsh_history ~/.agent-login/auth 2>&1; ls -A ~/.gnupg ~/.config/gh; true'"))
        assert "SENTINEL" not in out and "trustdb" not in out, out
        machine.succeed(h("ai-run -- sh -c 'test -z \"$(ls -A ~/.gnupg)\"'"))
        assert "agent-SENTINEL" in machine.succeed(h("ai-run --profile agent -- cat ~/.agent-login/auth"))
        machine.succeed(h("ai-run -- touch ~/dev/ok"))
        machine.fail(h("ai-run -- touch ~/.bashrc"))
        machine.fail(h("ai-run -- touch ~/.config/x"))
        machine.fail(h("ai-run -- sh -c 'echo x > /run/docker.sock'"))
        assert "GH_TOKEN=leak" in machine.succeed(h("GH_TOKEN=leak env"))
        assert "GH_TOKEN" not in machine.succeed(h("GH_TOKEN=leak ai-run -- env"))
        bpid = machine.succeed("systemctl show -p MainPID --value secret-broker").strip()
        machine.fail(h(f"ai-run -- test -e /proc/{bpid}"))
        # the secret-broker socket stays usable from inside
        out = machine.succeed(h("ai-run -- secret-run demo hash")).strip()
        assert out == hashlib.sha256(SECRET.encode()).hexdigest(), out
        st = machine.succeed(h("ai-run -- secret-broker status"))
        assert "unlocked" in st and "restricted" in st, st
        # but unlock can't be triggered from inside (restricted socket, no ~/.gnupg)
        out = machine.fail(h("ai-run -- secret-broker unlock --ttl 1m 2>&1"))
        assert "sandbox" in out, out
        machine.fail(h("ai-run -- sh -c 'SECRET_BROKER_SOCKET=/run/secret-broker/broker.sock secret-broker status'"))

    with subtest("ai-run: no session bus by default; proxy only passes allowed names"):
        # su sessions come and go, so use a runtime dir of our own
        machine.succeed("install -d -o hadi -m 700 /var/tmp/rt")
        machine.succeed(h("dbus-daemon --session --address=unix:path=/var/tmp/rt/bus --fork --nopidfile"))
        bus = "DBUS_SESSION_BUS_ADDRESS=unix:path=/var/tmp/rt/bus XDG_RUNTIME_DIR=/var/tmp/rt"
        machine.succeed(h(f"{bus} nohup ${fakeServices} > /tmp/fake.log 2>&1 &"))
        machine.wait_until_succeeds("grep -q ready /tmp/fake.log")
        ping = "gdbus call --session --dest {} --object-path /o --method org.freedesktop.DBus.Peer.Ping"
        hello = "gdbus call --session --dest org.example.Allowed --object-path /o --method org.example.I.Hello"
        machine.succeed(h(f"{bus} {ping.format('org.freedesktop.secrets')}"))
        machine.succeed(h(f"{bus} {hello}"))
        machine.fail(h(f"{bus} ai-run -- {ping.format('org.freedesktop.secrets')}"))
        machine.fail(h(f"{bus} ai-run -- {hello}"))
        machine.fail(h(f"{bus} ai-run -- test -S /var/tmp/rt/bus"))
        assert "hi" in machine.succeed(h(f"{bus} ai-run --profile bus -- {hello}"))
        machine.fail(h(f"{bus} ai-run --profile bus -- {ping.format('org.freedesktop.secrets')}"))

    with subtest("lock seals (quick methods configured), lock --forget wipes"):
        machine.succeed(h("secret-broker lock"))
        assert "sealed" in machine.succeed(h("secret-broker status"))
        out = machine.fail(h("secret-run demo hash 2>&1"))
        assert "no approval dialog" in out, out
        machine.succeed(h("secret-broker lock --forget"))
        assert "locked (not in memory" in machine.succeed(h("secret-broker status"))

    with subtest("ttl expiry seals"):
        machine.succeed(h("secret-broker unlock --ttl 3s"))
        machine.succeed(h("secret-run demo hash"))
        machine.sleep(5)
        machine.fail(h("secret-run demo hash"))
        assert "sealed" in machine.succeed(h("secret-broker status"))

    HASH = hashlib.sha256(SECRET.encode()).hexdigest()

    def dialog(mode, arg="", log="/tmp/dialog.log"):
        machine.succeed(f"rm -f {log}")
        machine.succeed(h(f"nohup ${fakeDialog} {log} {mode} {arg} > /dev/null 2>&1 &"))
        machine.wait_until_succeeds(f"grep -q register {log}")

    def requests(log="/tmp/dialog.log"):
        import json as _j
        return [_j.loads(l) for l in machine.succeed(f"cat {log}").splitlines()]

    with subtest("set-pin needs gpg, then a sealed session opens with the PIN in the dialog"):
        machine.succeed(h("printf '2468\\n2468\\nblue otter\\n' | secret-broker set-pin"))
        machine.succeed("test \"$(stat -c %a:%U /var/lib/secret-broker/auth/pin)\" = 600:agent-secrets")
        st = machine.succeed(h("secret-broker status"))
        assert "approval: pin, fido2, mock" in st and "unlocked" in st, st
        machine.succeed(h("secret-broker lock"))
        dialog("pin", "1111,2468")
        assert machine.succeed(h("ai-run -- secret-run demo hash")).strip() == HASH
        r = requests()
        req = next(m for m in r if m.get("kind") == "request")
        assert req["phrase"] == "blue otter" and req["requester"]["sandboxed"], req
        assert "secret-run demo hash" in req["purpose"], req
        assert "pin" in req["methods"] and "fido2" in req["methods"], req
        assert any("Wrong PIN" in m.get("message", "") for m in r), r
        assert any(m.get("kind") == "done" and m["ok"] for m in r), r
        assert SECRET not in machine.succeed("journalctl -u secret-broker --no-pager")

    with subtest("deny in the dialog"):
        machine.succeed(h("secret-broker lock"))
        dialog("deny")
        out = machine.fail(h("ai-run -- secret-run demo hash 2>&1"))
        assert "denied" in out, out
        assert "sealed" in machine.succeed(h("secret-broker status"))

    with subtest("security key (mock FIDO2) touch"):
        machine.succeed("rm -rf /run/fido2-mock && install -d -m 755 /run/fido2-mock")
        dialog("wait")
        machine.succeed(h("(ai-run -- secret-run demo hash > /tmp/fido.out 2>&1; echo $? > /tmp/fido.rc) > /dev/null 2>&1 < /dev/null &"))
        machine.wait_until_succeeds("grep -q request /tmp/dialog.log")
        machine.sleep(1)
        assert "sealed" in machine.succeed(h("secret-broker status"))
        machine.succeed("install -m 644 /dev/null /run/fido2-mock/touch")
        machine.wait_until_succeeds("test -e /tmp/fido.rc")
        assert machine.succeed("cat /tmp/fido.rc").strip() == "0", machine.succeed("cat /tmp/fido.out; journalctl -u secret-broker --no-pager | tail -30; cat /tmp/dialog.log; ls -la /run/fido2-mock; systemctl show secret-broker -p DevicePolicy -p PrivateDevices")
        assert any("fido2" in m.get("message", "") for m in requests() if m.get("kind") == "done")
        machine.succeed("rm /run/fido2-mock/touch")

    with subtest("PAM method (mock sensor) in a helper process"):
        machine.succeed(h("secret-broker lock"))
        machine.succeed("install -d -m 755 /run/pam-mock && install -m 644 /dev/null /run/pam-mock/ok")
        dialog("wait")
        assert machine.succeed(h("ai-run -- secret-run demo hash")).strip() == HASH
        assert any("mock" in m.get("message", "") for m in requests() if m.get("kind") == "done")
        machine.succeed("rm /run/pam-mock/ok")

    with subtest("the restricted socket refuses dialog/approve/set-pin"):
        machine.succeed(h("secret-broker lock"))
        machine.fail(h("${fakeDialog} /tmp/r.log wait x /run/secret-broker/agent.sock"))
        assert "sandbox" in machine.succeed("cat /tmp/r.log")
        out = machine.fail(h("ai-run -- sh -c 'printf \"1\\n1\\n\\n\" | secret-broker set-pin' 2>&1"))
        assert "sealed" in machine.succeed(h("secret-broker status"))

    with subtest("terminal unlock of a sealed session uses the PIN"):
        machine.succeed(h("printf '2468\\n' | secret-broker unlock --ttl 10m"))
        assert "unlocked" in machine.succeed(h("secret-broker status"))

    with subtest("too many wrong PINs wipe the secrets; gpg again"):
        machine.succeed(h("secret-broker lock"))
        dialog("pin", "0000,0000,0000,0000")
        machine.fail(h("ai-run -- secret-run demo hash"))
        assert "locked (not in memory" in machine.succeed(h("secret-broker status"))
        machine.succeed(h("secret-broker unlock --ttl 1h"))
        assert machine.succeed(h("secret-run demo hash")).strip() == HASH

    with subtest("real dialog on headless sway: PIN typed with the keyboard"):
        machine.succeed(h("secret-broker lock"))
        machine.succeed("install -d -o hadi -m 700 /var/tmp/wl")
        env = "XDG_RUNTIME_DIR=/var/tmp/wl WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1"
        machine.succeed(h(f"{env} nohup sway -c ${swayConfig} > /tmp/sway.log 2>&1 &"))
        machine.wait_until_succeeds("ls /var/tmp/wl/wayland-1")
        wl = "XDG_RUNTIME_DIR=/var/tmp/wl WAYLAND_DISPLAY=wayland-1"
        machine.succeed(h(f"{wl} nohup secret-broker-dialog prompter --font ${font} --font-bold ${fontBold} > /tmp/dialog-real.log 2>&1 &"))
        machine.wait_until_succeeds("grep -q connected /tmp/dialog-real.log")
        machine.succeed(h("(ai-run -- secret-run demo hash > /tmp/real.out 2>&1; echo $? > /tmp/real.rc) > /dev/null 2>&1 < /dev/null &"))
        machine.sleep(2)
        machine.succeed(h(f"{wl} grim /tmp/dialog.png"))
        machine.copy_from_machine("/tmp/dialog.png", "")
        # (the first keys after wtype creates its virtual keyboard can race the
        # keyboard capability; Ctrl+U clears whatever arrived)
        machine.succeed(h(f"{wl} wtype -s 300 9999 -k Return"))
        machine.sleep(1)
        machine.succeed(h(f"{wl} wtype -s 400 -M ctrl u -m ctrl -s 100 2468 -k Return"))
        machine.wait_until_succeeds("test -e /tmp/real.rc")
        assert machine.succeed("cat /tmp/real.rc").strip() == "0", machine.succeed("cat /tmp/real.out /tmp/dialog-real.log")
        assert machine.succeed("cat /tmp/real.out").strip() == HASH

    with subtest("service restart wipes"):
        machine.succeed(h("secret-broker unlock --ttl 1h"))
        machine.succeed(h("secret-run demo hash"))
        machine.succeed("systemctl restart secret-broker")
        machine.fail(h("secret-run demo hash"))

    with subtest("a mutable, user-writable secrets file is refused"):
        machine.succeed("chown hadi /etc/secret-broker/secrets.sops.json")
        machine.fail(h("secret-broker unlock --ttl 1h"))
        machine.succeed("chown root /etc/secret-broker/secrets.sops.json")
  '';
}
