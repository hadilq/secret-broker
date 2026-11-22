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
in
{
  name = "secret-broker";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.default ];
    users.users.hadi = { isNormalUser = true; uid = 1000; };
    users.users.other = { isNormalUser = true; uid = 1001; };
    environment.systemPackages = [ pkgs.sops pkgs.gnupg pkgs.strace pkgs.procps ];
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
