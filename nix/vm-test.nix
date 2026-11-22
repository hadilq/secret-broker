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
  aiRunConfig = pkgs.writeText "ai-run.json" (builtins.toJSON {
    bwrap = "${pkgs.bubblewrap}/bin/bwrap";
    dbus_proxy = "${pkgs.xdg-dbus-proxy}/bin/xdg-dbus-proxy";
    mask = [ ".gnupg" ".config/gh" ".zsh_history" ".agent-login" "/run/docker.sock" ];
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
    environment.systemPackages = [ pkgs.sops pkgs.gnupg pkgs.strace pkgs.procps pkgs.glib.bin pkgs.dbus (lib.hiPrio aiRun) ];
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
        assert "locked" in machine.succeed(h("secret-broker status"))
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
        assert "unlocked" in machine.succeed(h("ai-run -- secret-broker status"))
        # but unlock can't be triggered from inside (no gpg-agent, no ~/.gnupg)
        machine.fail(h("ai-run -- secret-broker unlock --ttl 1m"))

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

    with subtest("lock wipes"):
        machine.succeed(h("secret-broker lock"))
        machine.fail(h("secret-run demo hash"))

    with subtest("ttl expiry"):
        machine.succeed(h("secret-broker unlock --ttl 3s"))
        machine.succeed(h("secret-run demo hash"))
        machine.sleep(5)
        machine.fail(h("secret-run demo hash"))
        assert "locked" in machine.succeed(h("secret-broker status"))

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
