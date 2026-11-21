# The throwaway root machine for the S4 auto-update proof (#211 S4).
#
# A NixOS microVM, built from the same nixpkgs the flake pins (read from
# flake.lock, so there is no second pin to keep in step). `scripts/update-proof-vm/run`
# builds it, boots it under KVM and deletes its disk afterwards.
#
# Why a VM: the proof runs the server as root under systemd with real terminal
# sessions, kills it and hard-resets the machine during an update trial. None of
# that is safe on a shared build host, whose /run holds other nodes' state.
#
# Shape:
# - 4 vCPUs and 4 GiB (the owner's cap for VMs inside compute01), an 8 GiB
#   throwaway disk, no network device at all (the proof uses loopback only);
# - the host's /nix/store is mounted read-only (qemu-vm.nix's default), so the
#   proof harness, a test executable built by `nix develop` on the host, runs
#   as is;
# - one writable shared folder (virtiofs), "$IPROOF_SHARE" on the host, at /share: the run script puts the
#   inputs there and reads the outputs back;
# - `infraternal-proof.service` is the server under test. It starts the boot
#   pointer the proof sets up, exactly as S6 will start production, and the
#   service manager restarts it whenever it stops, including at boot;
# - `proof-runner.service` runs /share/in-vm.sh once the machine is up.
let
  lock = builtins.fromJSON (builtins.readFile ../../flake.lock);
  locked = lock.nodes.nixpkgs.locked;
  nixpkgs = builtins.fetchTree {
    inherit (locked) type owner repo rev narHash;
  };
  system = import "${nixpkgs}/nixos/lib/eval-config.nix" {
    system = "x86_64-linux";
    modules = [
      "${nixpkgs}/nixos/modules/virtualisation/qemu-vm.nix"
      ({ pkgs, lib, ... }: {
        system.stateVersion = "25.11";
        networking.hostName = "iproof";
        virtualisation = {
          cores = 4;
          memorySize = 4096;
          diskSize = 8192;
          graphics = false;
          # No network device: nothing in the proof leaves loopback.
          qemu.networkingOptions = lib.mkForce [ ];
          sharedDirectories.share = {
            source = ''"$IPROOF_SHARE"'';
            target = "/share";
            # The runner writes its logs back here.
            writable = true;
          };
        };
        networking.useDHCP = false;
        networking.firewall.enable = false;
        documentation.enable = false;
        # The reboot case resets the machine with sysrq 'b' (no clean shutdown).
        boot.kernel.sysctl."kernel.sysrq" = 1;
        # Terminal sessions start the owner's login shell; the proof's profile is zsh.
        programs.zsh.enable = true;
        users.users.root.shell = pkgs.zsh;
        environment.systemPackages = [ pkgs.sqlite pkgs.procps ];
        services.getty.autologinUser = "root";

        systemd.services.infraternal-proof = {
          description = "infraternal server under the S4 update proof";
          wantedBy = [ "multi-user.target" ];
          unitConfig.ConditionPathExists = "/var/lib/infraternal-proof.env";
          serviceConfig = {
            EnvironmentFile = "/var/lib/infraternal-proof.env";
            ExecStart = "/var/lib/infraternal-proof/current/infraternal-x86_64-musl $INFRATERNAL_PROOF_ARGS";
            Restart = "always";
            RestartSec = "1s";
            LimitMEMLOCK = "infinity";
          };
        };

        systemd.services.proof-runner = {
          description = "the S4 update proof's runner";
          # Started at every boot, not waited for (a target orders itself after the
          # units it wants, so a oneshot here would hold up boot until the proof ends).
          wantedBy = [ "multi-user.target" ];
          path = with pkgs; [ bash coreutils systemd util-linux gnugrep gawk procps ];
          serviceConfig = {
            Type = "exec";
            ExecStart = "${pkgs.bash}/bin/bash /share/in-vm.sh";
            StandardOutput = "journal+console";
            StandardError = "journal+console";
          };
        };
      })
    ];
  };
in
system.config.system.build.vm
