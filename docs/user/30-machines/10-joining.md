<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Role: user guide for joining a Linux machine or Mac with `infraternal up` (passkey approval, installed files and services, Linux firewall unit). Published at /docs/machines/joining/. -->
# Joining a machine

Run `infraternal up` on a Linux machine or Mac to add it to your server with a single passkey approval in your browser.

> [!NOTE] What works today
> **Works:** joining Linux machines (systemd) and Macs (user mode by default, or `--system` root mode) with `infraternal up`.
> **Planned:** joining Windows machines as a Windows service.

## Running `infraternal up`

On the machine you want to join, pass your server's HTTPS origin (with no path, query or fragment):

```sh
infraternal up https://infra.example.org
```

The command requests a one-time approval from the server and prints:

- an **approval link** to open in a browser where you are signed in;
- a short **one-time code** and the **machine key** fingerprint so you can verify you are approving the right machine;
- a **QR code** you can scan with your phone.

Open the link and confirm with a fresh passkey tap before the code expires (10 minutes, one use). Once approved, `infraternal up` enrolls the machine over HTTPS, installs and starts the infraternal agent, and reports its status.

> [!TIP] Existing installations
> `infraternal up` is for fresh machines. It checks for existing infraternal files and services before requesting an approval, so a conflict never wastes a passkey tap. If an installation is interrupted, the next run rolls back only the paths created by the unfinished attempt.

## What gets installed on Linux

On Linux, `infraternal up` requires `systemd` (with `systemctl` at a root-owned system path) and asks for `sudo` once. It installs:

| Path | Purpose |
|---|---|
| `/var/lib/infraternal/bin/infraternal` | The binary run by the system service. |
| `/usr/local/bin/infraternal` | A symlink to the installed binary so `infraternal` is on your `PATH`. |
| `/var/lib/infraternal/agent` | The machine's enrollment data and host certificate. |
| `/etc/systemd/system/infraternal-agent.service` | The enabled systemd service that runs the infraternal agent. |
| `/etc/systemd/system/infraternal-firewall.service` | The boot firewall unit described below. |

### The firewall unit on Linux

`infraternal up` installs and enables `infraternal-firewall.service` for `network-pre.target`, so it runs before networking comes up at boot. It loads Infraternal's own nftables table (`inet infraternal_host`) from `/var/lib/infraternal/host-firewall-agent.json`.

- **Mesh-only mode (default for joined machines):** on a machine without a server role, `inet infraternal_host` uses `policy accept`. It explicitly admits traffic arriving on `infraternal0` and the mesh UDP port (default 10254), and blocks nothing else, so joining a machine cannot lock you out of SSH or existing services.
- **Other firewalls stay untouched:** Infraternal manages only tables named `infraternal_*` and never modifies your existing nftables or iptables tables. Note that an accept rule in `inet infraternal_host` does not override a drop rule in another table's base chain; see [New connections arriving through the tunnel](/docs/mesh/networking/#new-connections-arriving-through-the-tunnel) if your host has its own drop-by-default input chain.
- **Optional administrator allow rules:** you can pass `--host-firewall-allow INTERFACE,SOURCE,tcp|udp,PORT` (repeatable, `*` for any). `infraternal up` also records your current SSH port automatically. These saved rules only take effect if a server policy (which uses a default-drop input chain) is later installed on the same machine.

## What gets installed on macOS

### User mode (default)

On a Mac, `infraternal up https://infra.example.org` joins in **user mode** by default. Run it as your regular macOS user, without `sudo`:

1. It asks for your administrator password **once**, before showing the approval code, to install a small on-demand mesh helper (`kayg.infraternal.mesh-helper`). The helper runs only when the infraternal agent needs a privileged mesh action (creating the tunnel interface, adding routes, or writing `/etc/resolver` files) and then exits.
2. After you approve the machine with your passkey, it installs everything under your home Library:
   - `~/Library/Application Support/infraternal/bin/infraternal` — the binary (`up` prints the `PATH` line to add);
   - `~/Library/Application Support/infraternal/agent` — the enrollment data;
   - `~/Library/Application Support/infraternal/state` — mesh state and key;
   - `~/Library/Logs/infraternal/agent.log` — the infraternal agent's log;
   - `~/Library/LaunchAgents/kayg.infraternal.agent.plist` — the `LaunchAgent` that runs the infraternal agent in your login session.

Only one user account per Mac can use user mode, and user mode cannot be installed alongside root mode.

### Root mode (`--system`)

For a headless Mac that must stay on the mesh before anyone logs in, pass `--system`:

```sh
infraternal up --system https://infra.example.org
```

Root mode asks for `sudo` once and installs a system `LaunchDaemon` instead of a per-user `LaunchAgent`.

## Uninstall from this machine

```sh
infraternal uninstall
```

Review the service, files, and mesh settings the command lists. Type `Remove`
to uninstall, or press Enter to keep the installation. Run as the person who
installed it in user mode. Use `--system` to select the system installation.
Removing a system installation may ask for your administrator password.

Use `--keep-state` to save a private copy of the enrollment outside the old
installation directory. A new `infraternal up` asks for fresh enrollment.
Use `--json` to read the plan as JSON, or `--json --yes` to confirm in a script.

If the server still lists the host, use **Remove** in the machine list, then
**Forget** if the server reports that cleanup is pending.

---

Behind this page: D203 C2, D311, D384, D386, D395, #146, #263, #338, #483 and #580.
