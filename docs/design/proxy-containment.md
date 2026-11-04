# Containing the managed Traefik process

Status: **option 1 chosen (D336, "let's do it") and built in J164 (#281)**. Decisions
referenced: D316 (Traefik as a managed sidecar), D330 (rootless `--public`), D336.

## As built (J164)

- Each child gets a leaf `proxy-<lock dir device>-<inode>-<n>` under the infraternal agent's own cgroup.
  It joins the leaf in the shim's pre-exec hook, before it can exec or fork. Stopping it
  writes `cgroup.kill` and also kills the direct child (a rootless child may have left its
  leaf), reaps it, waits for `populated 0`, then removes any cgroups the child made inside the
  leaf, deepest first, and the leaf itself.
  No controller is enabled, so the agent stays where its init system put it.
- On start, while holding the supervisor lock, the agent kills and removes every leaf with its
  tag, both under its current cgroup and under the cgroup recorded at the last leaf creation.
  This also runs in fallback, so leaves from an earlier contained run (a unit that lost
  `Delegate=yes`) are still killed. The J159 lock-holder reaper stays as the second line.
- Rootful under systemd needs `Delegate=yes`, detected by the `trusted.delegate` /
  `user.delegate` xattr. Both generated units now carry it, next to `KillMode=process`.
  Rootless needs its own cgroup to be owned by the agent's user, which is true in a user
  service and false in a login session scope. An agent in the root cgroup falls back too. In
  every fallback the agent reaps as before, and `infraternal mesh status` and
  `infraternal publish` give the reason. Rootless status says that a compromised Traefik
  could still leave its cgroup (kind `cgroup-rootless`).
- Measured on #281 (perf VM): +37 µs per start and +36 µs per stop at p50, no steady-state CPU
  or RSS difference, and 5–10 KiB of kernel memory per leaf.
- **Correction to option 1 below:** rootless, the cgroup files belong to the agent's user, so
  a *compromised* rootless child can write itself into the parent cgroup and leave its leaf.
  Ordinary forks and the crash case are contained. Option 2 is still the fix for that.

## Why this note exists

Four review rounds of #281 hardened how the Traefik child is contained, and each round
added a mechanism that brought its own class of defect:

| Round | Mechanism | Defect it brought |
|---|---|---|
| 2 | child runs as root | the child ran as root |
| 3 | fixed 65532 identity, credential drop | directory modes, lost parent-death signal |
| 4 | created account, `/proc` identity scan, lock-holder killer | UID 999 shared with containers; killing an unrelated lock holder; a forked child escapes reaping |

The firewall and conntrack work has converged. This part has not, because nothing written
says what containment has to guarantee. This note writes that down and asks the owner to
choose one mechanism.

## What Traefik holds by design

Whatever we choose, Traefik keeps these, because serving HTTPS needs them:

- the DNS-01 provider token(s), readable through inherited descriptors;
- the ACME account key and every issued certificate's private key (`acme.json`, which it
  writes);
- the listening ports: 80/443 rootful (`CAP_NET_BIND_SERVICE` only), the 10080/10443 pair
  rootless (D330), and the Mesh pair on the Mesh address;
- network reach from the host's network namespace: loopback (the backends live there) and
  the Mesh as this node.

Today the rootful child also has the host's world-readable files and a host UID (now
60514–60999, see `identity.rs`). The rootless child runs as the infraternal agent's own
user, so it can read and write everything that user can, **including the infraternal agent's
state and keys**.

## Threat model (proposed)

**In scope: a Traefik that is compromised remotely**, for example through a parser bug in a
request from the public internet or the Mesh. It is the only component that accepts public
connections on the node, so it has to be in scope. Assume the attacker runs arbitrary code
as the child.

| Question | Proposed answer |
|---|---|
| May it read or abuse the DNS token, ACME keys and certificates? | **Accepted loss.** It needs them to work. Limit the damage outside the process: scope the DNS token to the zone (documented for the person), and keep ACME state per node. |
| May it keep serving 80/443 (or the rootless pair)? | Only while the infraternal agent wants it to. |
| May it outlive the infraternal agent, or survive an unpublish? | **No.** Every process it starts must be reaped when the agent stops it, crashes or restarts. This is the guarantee round 4 could not give (P3-4). |
| May it reach other processes (signal, trace) or host files? | Rootful: **no** other process; only world-readable files. Rootless: accepted for now, since it runs as the agent's user (see option 2). |
| May it reach loopback services and the Mesh? | **Accepted.** The backends are on loopback; a network namespace would need a forwarder, which is out of scope. Mesh peers still enforce their own policy against this node. |
| May it gain root, or the agent's secrets? | **No** when rootful. Rootless: only option 2 changes this. |

## Options

### 1. Explicit ID policy plus a cgroup per child

Keep the dedicated account from round 5 (explicit ID from 60514–60999, never the account
tools' allocation). Start every child in its own cgroup v2 leaf, for example
`<agent cgroup>/proxy-<generation>`. To stop it, write `1` to `cgroup.kill` (Linux 5.14 and
later), which kills every process in the cgroup, including ones it forked, atomically. A new
infraternal agent kills any leftover proxy cgroup before it starts a child. That replaces the
child lock, the `/proc` descriptor scan and the reaper's identity checks with one
kernel-enforced membership test. The child can't leave the cgroup, because the cgroup files
belong to root, or to the agent's user when rootless. `pids.max` and `memory.max` come
almost free, which helps the shared 12 GiB slice.

- **Cost:** about 150–250 lines in the proxy crate, plus `Delegate=yes` on the infraternal
  agent's unit. The unit keeps `KillMode=process`, so sessions survive agent restarts. A
  cgroup costs a few KiB in the kernel. Creating and killing one are expected to take well
  under a millisecond each. That is not measured yet; the follow-up job measures it on the
  child-start path. The parent-death signal stays as the first
  line of defence.
- **Rootful:** needs systemd delegation, or a writable cgroup v2 hierarchy when there is no
  systemd. Without one, fall back to today's mechanism and log that containment is
  degraded.
- **Rootless:** user systemd delegates `user@.service` to the user on current distributions,
  so a user-unit agent can create the leaf. An agent started outside a user unit falls back
  as above.
- **Does not change:** the host UID (file-ownership collisions are made less likely by the
  range, not ruled out), or what the rootless child can reach.
- **macOS later:** no cgroups. The closest is running the child as a launchd job, which
  launchd tears down with its process group, plus a dedicated `_infraternal-proxy` account
  with an explicit ID when rootful. A process that calls `setsid` can still escape, so on
  macOS this is weaker.

### 2. User and PID namespaces, Traefik as PID 1

Start the child in a new user namespace and a new PID namespace. In the user namespace, its
root maps to one host ID that no account uses, so no passwd entry is created. Traefik is
PID 1 of its PID namespace. When PID 1 exits, the kernel kills every process in the
namespace, so a fork can't outlive it. A mount namespace can then hide the host's files
apart from the proxy directory. That is the only option that cuts file reach.

- **Cost:** roughly 400–700 lines in the audited shim: `unshare`/`clone3`, writing
  `uid_map`/`gid_map`, PID-1 signal behaviour, and a pivot root. The test matrix is larger.
- **Ports:** a process that is root only in its own user namespace can't bind ports below
  1024 in the host network namespace. So the infraternal agent must bind 80/443 itself and
  pass the sockets in, and Traefik has to accept inherited listeners. That support **has to
  be verified** for the Traefik release we pin. If it isn't there, the option falls back to
  host-network binding with an ambient capability, which needs a host UID again.
- **Rootful:** full benefit: no host account, no escape, little file reach.
- **Rootless:** unprivileged user namespaces can map only the user's own ID (or subordinate
  ranges via `newuidmap`). Several distributions restrict them (Ubuntu 24.04's AppArmor
  restriction; RHEL's `user.max_user_namespaces`). Where they are allowed, this is the only
  option that keeps a compromised rootless Traefik away from the agent's state. Where they
  are not, it falls back to today.
- **macOS later:** no equivalent. The App Sandbox or `sandbox-exec` profiles are the nearest,
  and they are deprecated or need signing work (D321).

### 3. Declare compromise out of scope

Document that a compromised Traefik is treated like a compromised infraternal agent on that
node. Keep what serves the **crash** case: the parent-death signal, the child lock with the
pidfd-verified reaper, and the explicit ID band. Stop adding identity-scan mechanisms aimed
at a hostile child.

- **Cost:** close to none. A paragraph in the user docs and the security notes.
- **Rootful and rootless:** unchanged from round 5. The escape in P3-4 stays possible:
  a forked process keeps 80/443 and the ACME keys after an agent restart, and the next agent
  refuses to start rather than reclaim the ports.
- **macOS later:** nothing extra to design.
- **Risk:** Traefik is the node's only public listener, so this places the internet-facing
  parser inside the trust boundary of the whole node.

## Recommendation

**Option 1 now, with option 2 as later hardening for rootless.**

- Option 1 closes the one guarantee rounds 2–4 kept missing: a child, or anything it forks,
  never outlives the infraternal agent. It does that with one kernel mechanism instead of
  three heuristics, at negligible run-time cost. It also lets us delete the `/proc`
  descriptor scan.
- The explicit ID band from round 5 stays the identity policy. Together they meet every
  "No" in the threat model for rootful nodes.
- Option 2 is the only real fix for the rootless child's reach into the agent's own files.
  It depends on Traefik accepting pre-bound sockets and on distribution userns policy, so
  measure both before committing to it. Until then, the user docs say plainly that a rootless
  proxy runs with the person's own rights.
- Option 3 is not recommended: it leaves the escape in P3-4 open on the node's only
  internet-facing process.

The owner decides. If option 1 is chosen, the follow-up job measures cgroup creation and
kill latency on the child-start path, and confirms `Delegate=yes` against the existing
`KillMode=process` session contract, before anything is built.
