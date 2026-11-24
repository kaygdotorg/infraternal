//! The macOS user-mode mesh helper: a root process that runs for one request and exits
//! (#146, D203 C2 as amended 2026-11-20).
//!
//! In user mode the infraternal agent runs as the logged-in person. It cannot create a utun,
//! route, or write `/etc/resolver`, so it asks this helper. The helper is a `LaunchDaemon` that
//! launchd starts on demand, one process per connection, with the connection as standard
//! input ([`crate::macos_user_mode::helper_plist`]). It answers one request and exits. The
//! person approves it once, with one `sudo` prompt, when `infraternal up` installs it; after
//! that every agent start (including after a reboot or a new login) gets its utun without a
//! prompt. The rules it applies live in [`crate::macos_user_mode`], so the Linux gate tests
//! them; this module is the part that touches the system.
//!
//! # Threat notes
//!
//! **What it can do, as root:** create one utun and hand its descriptor to the caller; set a
//! utun's mesh addresses and MTU; add one IPv4 route (a private prefix that holds the node's
//! address) and one IPv6 `/48` (unique-local) to that utun; write and remove marked
//! `/etc/resolver` files for reserved private-use suffixes; remove its own registration. It
//! runs no shell, resolves no program through `PATH` (only fixed system tools, with an empty
//! environment), reads no file the caller names, and keeps no state between requests.
//!
//! **Who can ask:** launchd creates the socket owned by the one registered uid, mode 0600, so
//! only that person and root can connect. The helper then reads the kernel's peer credentials
//! (`LOCAL_PEERCRED`) and refuses any other uid. The registered uid comes from the helper's
//! root-owned property list, which only an administrator can change. Any process running as
//! that person can ask; that is the trust boundary on purpose, because the same processes can
//! already read the agent's mesh key and identity in that person's home. A code-signature
//! check of the caller can be added once the desktop helper's signing check exists (J992).
//!
//! **How input is checked:** one frame of at most 4 KiB of JSON, unknown fields refused, a
//! fixed protocol version, a 5 s read and write timeout, and every value checked by
//! [`crate::macos_user_mode::validate`] before anything runs. Requests that change a utun
//! must carry that utun's descriptor, and the helper reads the interface name from it, so a
//! caller can only change a utun it holds; a name is never taken from the request. Before a
//! route is added, the routing table and every interface network are read and any overlap is
//! refused by name ([`crate::macos_user_mode::plan_route`]), so the mesh never takes traffic
//! from a network the Mac already uses. Another utun with exactly the mesh prefix is replaced
//! only when the kernel shows it is held by the registered person's installed infraternal binary
//! ([`crate::macos_utun_holder`], review J1027 F1); otherwise it is another VPN and is refused.
//! A resolver request is honoured only when the mesh route leads to the caller's utun, and only
//! for `internal` or `home.arpa` names, so one person cannot redirect real domains for the
//! Mac's other accounts. The file names the
//! deployment's mesh resolver address (`fd<id>:ffff::53`, port 53), which sits on no interface:
//! the mesh `/48` route sends it into the caller's utun and the agent answers it from the packets
//! it reads there ([`crate::tunnel_dns`], J1027 F2). The helper writes it only when that route
//! leads to the caller's utun. No socket is bound, so no other account can answer in the
//! agent's place, before, during or after the agent runs. While no agent runs, the files stay
//! but the route is gone: the system then sends those queries to its default IPv6 route, if it
//! has one, where a unique-local address goes unanswered.
//!
//! **What it cannot do:** it cannot reach another person's utun, choose a public route, or
//! replace a resolver file it did not write (the existing marker check). It never writes to
//! standard output or error, so nothing but the reply reaches the socket.
//!
//! **Known gap:** on macOS a received descriptor is not close-on-exec until the receiver sets
//! the flag right after `recvmsg` (there is no `MSG_CMSG_CLOEXEC`). A child forked by another
//! thread in that window inherits the utun. The agent receives the utun only at startup and
//! on rebuilds, before it starts sessions on that path.

use crate::macos_user_mode::{
    self as rules, HELPER_BINARY, HELPER_DIRECTORY, HELPER_ENTRY, HELPER_LABEL, HELPER_PLIST,
    HELPER_SOCKET, MAX_MESSAGE_BYTES, Network, Reply, Request, Route,
};
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, getsockopt, recvmsg, sendmsg, setsockopt,
    sockopt::{LocalPeerCred, ReceiveTimeout, SendTimeout, UtunIfname},
};
use nix::sys::time::TimeVal;
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, IoSlice, IoSliceMut, Read, Write},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::Path,
    process::{Command, ExitCode, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

/// The entry `infraternal up` runs through `sudo` to install the helper for one uid.
pub const INSTALL_ENTRY: &str = "__mesh-helper-install";
/// The entry an administrator can run through `sudo` to remove the helper.
pub const REMOVE_ENTRY: &str = "__mesh-helper-remove";
/// The most descriptors accepted in one message; anything above one is refused, but room
/// for a few lets the helper own and close extras instead of leaking them.
const MAX_DESCRIPTORS: usize = 4;
/// How long either side waits for the other before giving up.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// The root-mode `LaunchDaemon`; user mode refuses to install beside it.
const ROOT_MODE_PLIST: &str = "/Library/LaunchDaemons/org.infraternal.mesh.plist";

/// Set once when this process runs the mesh node in user mode.
static USER_MODE: AtomicBool = AtomicBool::new(false);

/// Switch this process's mesh node to user mode before the node starts.
///
/// A process is in one mode for its whole life: the agent calls this once, when it is not root
/// and the helper is registered for its uid. From then on the node gets its utun from the
/// helper, adds no per-peer routes (the helper's prefix route covers them), and sends address,
/// MTU and resolver changes to the helper.
pub fn enter_user_mode() {
    USER_MODE.store(true, Ordering::SeqCst);
}

/// Whether [`enter_user_mode`] ran in this process.
pub(crate) fn user_mode() -> bool {
    USER_MODE.load(Ordering::SeqCst)
}

/// Whether the helper is registered for the current (non-root) user.
///
/// Reads only the root-owned property list.
///
/// `Ok(false)` means no helper, or one registered for another account. An `Err` means a helper
/// property list exists but could not be checked (for example one an older install left
/// unreadable under a restrictive `sudo` umask, J1027 / J1087), so callers can say so and
/// point at the administrator removal instead of silently skipping the mesh or the helper.
///
/// # Errors
/// Reports a property list that is not a root-owned regular file or cannot be read.
pub fn registration_for_current_user() -> io::Result<bool> {
    let uid = nix::unistd::Uid::effective().as_raw();
    if uid == 0 {
        return Ok(false);
    }
    Ok(registered_uid()? == Some(uid))
}

/// The uid the installed helper serves, if a helper property list this code wrote exists.
///
/// # Errors
/// Refuses a property list that is not a root-owned regular file.
pub fn registered_uid() -> io::Result<Option<u32>> {
    match fs::symlink_metadata(HELPER_PLIST) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            let mut contents = String::new();
            File::open(HELPER_PLIST)?
                .take(8192)
                .read_to_string(&mut contents)?;
            Ok(rules::helper_plist_uid(&contents))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Run a helper entry when the binary was started as one; `None` means a normal command.
///
/// `__mesh-helper <uid>` serves one connection (launchd starts it). `__mesh-helper-install
/// <uid>` and `__mesh-helper-remove` are run through `sudo`. Each refuses to run without root.
#[must_use]
pub fn run_if_requested() -> Option<ExitCode> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    let entry = arguments.first()?.to_str()?;
    if ![HELPER_ENTRY, INSTALL_ENTRY, REMOVE_ENTRY].contains(&entry) {
        return None;
    }
    let uid = arguments
        .get(1)
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u32>().ok());
    let result = match (entry, uid, arguments.len()) {
        (HELPER_ENTRY, Some(uid), 2) => {
            // Errors are already in the reply; the exit status only tells launchd.
            return Some(if serve(uid).is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            });
        }
        (INSTALL_ENTRY, Some(uid), 2) => install(uid),
        (REMOVE_ENTRY, None, 1) => remove_registration(None),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "this internal command takes different arguments",
        )),
    };
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("infraternal: the mesh helper could not be changed: {error}");
            ExitCode::FAILURE
        }
    })
}

/// Refuse to continue unless this process is root.
fn require_root() -> io::Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the mesh helper must run as root",
        ))
    }
}

// ---------------------------------------------------------------------------
// The root side: one connection, one request.
// ---------------------------------------------------------------------------

/// Serve the one connection launchd put on standard input, for registered `uid` only.
fn serve(uid: u32) -> io::Result<()> {
    require_root()?;
    let stdin = io::stdin();
    let socket = stdin.as_fd();
    let kind = nix::sys::stat::SFlag::from_bits_truncate(nix::sys::stat::fstat(socket)?.st_mode);
    if kind & nix::sys::stat::SFlag::S_IFMT != nix::sys::stat::SFlag::S_IFSOCK {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    setsockopt(&socket, ReceiveTimeout, &TimeVal::new(5, 0))?;
    setsockopt(&socket, SendTimeout, &TimeVal::new(5, 0))?;
    let peer = getsockopt(&socket, LocalPeerCred)?.uid();
    if peer != uid || uid == 0 {
        let _ = send_reply(
            socket,
            &Reply::refused("this account may not use the mesh helper"),
            None,
        );
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let Ok((body, mut descriptors)) = receive_frame(socket) else {
        let _ = send_reply(socket, &Reply::refused("the request is malformed"), None);
        return Err(io::ErrorKind::InvalidData.into());
    };
    let request = match rules::decode_request(&body) {
        Ok(request) => request,
        Err(refusal) => {
            send_reply(socket, &Reply::refused(refusal.to_string()), None)?;
            return Err(io::ErrorKind::InvalidData.into());
        }
    };
    let expected = usize::from(request.needs_utun());
    if descriptors.len() != expected {
        send_reply(
            socket,
            &Reply::refused("the request carried the wrong number of descriptors"),
            None,
        )?;
        return Err(io::ErrorKind::InvalidData.into());
    }
    let utun = descriptors.pop();
    let (reply, handed) = match handle(&request, utun.as_ref().map(AsFd::as_fd), uid) {
        Ok(answer) => answer,
        Err(error) => (Reply::refused(error.to_string()), None),
    };
    send_reply(socket, &reply, handed.as_ref().map(AsFd::as_fd))?;
    if reply.ok && request == Request::Remove {
        finish_removal();
    }
    Ok(())
}

/// Carry out one checked request. The returned descriptor goes back with the reply.
fn handle(
    request: &Request,
    utun: Option<BorrowedFd<'_>>,
    uid: u32,
) -> io::Result<(Reply, Option<OwnedFd>)> {
    let ok = Reply {
        ok: true,
        ..Reply::default()
    };
    match request {
        Request::Open => {
            let open = crate::macos_node::OpenUtun::open_kernel()?;
            ifconfig(&[&open.name, "mtu", &rules::MIN_MTU.to_string(), "up"])?;
            Ok((
                Reply {
                    interface: Some(open.name.clone()),
                    ..ok
                },
                Some(open.fd),
            ))
        }
        Request::Address {
            ipv4,
            ipv4_prefix,
            ipv6,
            mtu,
        } => {
            let interface = utun_name(utun)?;
            let routes = [
                rules::ipv4_route(*ipv4, *ipv4_prefix).map_err(invalid)?,
                rules::ipv6_route(*ipv6).map_err(invalid)?,
            ];
            // Plan both routes before changing anything, so a conflict leaves the Mac as it was.
            let mut plans = Vec::new();
            for wanted in routes {
                let table = routing_table(wanted.is_ipv4())?;
                let local = local_networks(wanted.is_ipv4())?;
                let ours = if rules::same_prefix_utuns(wanted, &interface, &table).is_empty() {
                    Vec::new()
                } else {
                    agent_utuns(uid)
                };
                let plan = rules::plan_route(wanted, &interface, &table, &local, &ours)
                    .map_err(invalid)?;
                let present = table
                    .iter()
                    .any(|row| row.interface == interface && row.network == wanted);
                plans.push((wanted, plan, present));
            }
            ifconfig(&[&interface, "mtu", &mtu.to_string(), "up"])?;
            let ipv4 = ipv4.to_string();
            ifconfig(&[
                &interface,
                "inet",
                &ipv4,
                &ipv4,
                "netmask",
                "255.255.255.255",
            ])?;
            ifconfig(&[
                &interface,
                "inet6",
                &ipv6.to_string(),
                "prefixlen",
                "128",
                "alias",
            ])?;
            for (wanted, plan, present) in plans {
                for earlier in &plan.replace {
                    route("delete", wanted, earlier)?;
                }
                if !present {
                    route("add", wanted, &interface)?;
                }
            }
            Ok((ok, None))
        }
        Request::Mtu { mtu } => {
            let interface = utun_name(utun)?;
            ifconfig(&[&interface, "mtu", &mtu.to_string()])?;
            Ok((ok, None))
        }
        Request::Resolver { suffixes } => resolver(utun, suffixes),
        Request::ClearResolver => {
            clear_resolver()?;
            Ok((ok, None))
        }
        Request::Remove => {
            remove_registration(Some(uid))?;
            Ok((ok, None))
        }
    }
}

/// The utuns held right now by the registered person's agent (review J1027 F1).
///
/// "The agent" is any process whose real and effective uid are `uid` and whose executable is
/// that person's installed infraternal binary, found from the password database, never from the
/// request. Any failure (no such account, no installed binary, a process walk that fails) gives
/// an empty list, so the helper then refuses to replace the other utun instead of guessing.
fn agent_utuns(uid: u32) -> Vec<String> {
    let Ok(Some(user)) = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)) else {
        return Vec::new();
    };
    let Ok(binary) = fs::canonicalize(rules::user_install_binary(&user.dir)) else {
        return Vec::new();
    };
    crate::macos_utun_holder::utuns_held_by(uid, &binary)
        .map(|held| held.into_iter().collect())
        .unwrap_or_default()
}

/// Turn a rule refusal into an I/O error carrying its sentence.
fn invalid(refusal: rules::Refusal) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, refusal)
}

/// Read the interface name from a utun descriptor the caller holds.
///
/// Only a connected utun control socket answers `UTUN_OPT_IFNAME`, so this both proves the
/// caller holds that utun and names it without trusting any text from the request.
fn utun_name(utun: Option<BorrowedFd<'_>>) -> io::Result<String> {
    let utun = utun.ok_or(io::ErrorKind::InvalidInput)?;
    let name = getsockopt(&utun, UtunIfname)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the attached descriptor is not a utun",
            )
        })?
        .into_string()
        .map_err(|_| io::ErrorKind::InvalidData)?;
    if crate::macos_node::valid_utun_name(&name) {
        Ok(name)
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

/// Point the resolver for the allowed suffixes at the mesh resolver address of the caller's
/// utun (#146, J1027 F2).
///
/// The address is derived here, never taken from the request: the utun's own unique-local
/// mesh address gives the deployment's `/48`, and the resolver is `fd<id>:ffff::53` in it. It
/// is written only when the routing table sends that `/48` into this very utun, so the files
/// can only ever point at the agent that holds it; when the utun closes, the route goes with it
/// and nothing on the Mac answers in the agent's place.
#[cfg(feature = "mesh-dns")]
fn resolver(
    utun: Option<BorrowedFd<'_>>,
    suffixes: &[String],
) -> io::Result<(Reply, Option<OwnedFd>)> {
    let interface = utun_name(utun)?;
    let own = nix::ifaddrs::getifaddrs()?
        .filter(|entry| entry.interface_name == interface)
        .filter_map(|entry| entry.address.and_then(|a| a.as_sockaddr_in6().map(|v6| v6.ip())))
        .find(|address| address.octets()[0] == 0xfd)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the caller's utun has no mesh address yet",
            )
        })?;
    let mesh = rules::ipv6_route(own).map_err(invalid)?;
    let routed = routing_table(false)?
        .iter()
        .any(|row| row.network == mesh && row.interface == interface);
    if !routed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the mesh route does not lead to the caller's utun",
        ));
    }
    let (allowed, refused): (Vec<String>, Vec<String>) = suffixes
        .iter()
        .cloned()
        .partition(|suffix| rules::allowed_suffix(suffix));
    if allowed.is_empty() {
        clear_resolver()?;
    } else {
        crate::dns_integration::write_user_mode_resolver(
            infraternal_mesh::address::resolver_address(own),
            &allowed,
        )?;
    }
    Ok((
        Reply {
            ok: true,
            refused_suffixes: refused,
            ..Reply::default()
        },
        None,
    ))
}

/// Builds without mesh DNS never point the system resolver at the agent.
#[cfg(not(feature = "mesh-dns"))]
fn resolver(
    _utun: Option<BorrowedFd<'_>>,
    _suffixes: &[String],
) -> io::Result<(Reply, Option<OwnedFd>)> {
    Err(io::ErrorKind::Unsupported.into())
}

/// Remove every resolver file carrying the infraternal marker.
fn clear_resolver() -> io::Result<()> {
    #[cfg(feature = "mesh-dns")]
    crate::dns_integration::DnsIntegration::default().remove()?;
    Ok(())
}

/// Run a fixed system tool with an empty environment and no inherited input.
fn system_tool(program: &str, arguments: &[&str]) -> io::Result<std::process::Output> {
    Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::null())
        .output()
}

/// Run `/sbin/ifconfig`; a failure is reported without its output.
fn ifconfig(arguments: &[&str]) -> io::Result<()> {
    let output = system_tool("/sbin/ifconfig", arguments)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other("the utun could not be configured"))
    }
}

/// Add or delete one network route through `interface`.
fn route(operation: &str, network: Network, interface: &str) -> io::Result<()> {
    let family = if network.is_ipv4() { "-inet" } else { "-inet6" };
    let destination = network.to_string();
    let output = system_tool(
        "/sbin/route",
        &[
            "-n",
            operation,
            family,
            "-net",
            &destination,
            "-interface",
            interface,
        ],
    )?;
    if output.status.success()
        || (operation == "delete"
            && String::from_utf8_lossy(&output.stderr)
                .to_ascii_lowercase()
                .contains("not in table"))
    {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "the mesh route {destination} could not be {}",
            if operation == "add" {
                "added"
            } else {
                "removed"
            }
        )))
    }
}

/// Read the routing table for one family through `netstat -rn`.
fn routing_table(ipv4: bool) -> io::Result<Vec<Route>> {
    let output = system_tool(
        "/usr/sbin/netstat",
        &["-rn", "-f", if ipv4 { "inet" } else { "inet6" }],
    )?;
    if !output.status.success() {
        return Err(io::Error::other("the routing table could not be read"));
    }
    rules::parse_routes(&String::from_utf8_lossy(&output.stdout), ipv4).map_err(invalid)
}

/// Every interface address of one family as a network, with its interface name.
fn local_networks(ipv4: bool) -> io::Result<Vec<Route>> {
    let mut networks = Vec::new();
    for entry in nix::ifaddrs::getifaddrs()? {
        let (Some(address), Some(netmask)) = (entry.address.as_ref(), entry.netmask.as_ref())
        else {
            continue;
        };
        let network = if ipv4 {
            match (address.as_sockaddr_in(), netmask.as_sockaddr_in()) {
                (Some(address), Some(mask)) => {
                    let prefix = u8::try_from(u32::from(mask.ip()).count_ones()).unwrap_or(32);
                    Network::v4(address.ip(), prefix)
                }
                _ => continue,
            }
        } else {
            match (address.as_sockaddr_in6(), netmask.as_sockaddr_in6()) {
                (Some(address), Some(mask)) => {
                    let prefix = u8::try_from(u128::from(mask.ip()).count_ones()).unwrap_or(128);
                    Network::v6(address.ip(), prefix)
                }
                _ => continue,
            }
        };
        networks.push(Route {
            network,
            interface: entry.interface_name,
        });
    }
    Ok(networks)
}

// ---------------------------------------------------------------------------
// Frames and descriptors, shared by both sides.
// ---------------------------------------------------------------------------

/// Send one framed body with at most one descriptor beside it.
fn send_frame(
    socket: BorrowedFd<'_>,
    framed: &[u8],
    descriptor: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let raw: Vec<RawFd> = descriptor.iter().map(AsRawFd::as_raw_fd).collect();
    let control: Vec<ControlMessage<'_>> = if raw.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(&raw)]
    };
    let sent = sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(framed)],
        &control,
        MsgFlags::empty(),
        None,
    )?;
    if sent == framed.len() {
        return Ok(());
    }
    // A local stream socket takes a 4 KiB frame at once; finish any short write plainly.
    let mut rest = &framed[sent..];
    while !rest.is_empty() {
        let written = nix::unistd::write(socket, rest)?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        rest = &rest[written..];
    }
    Ok(())
}

/// Send one reply, with the utun beside it for `open`.
fn send_reply(
    socket: BorrowedFd<'_>,
    reply: &Reply,
    descriptor: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    let body = serde_json::to_vec(reply).map_err(io::Error::other)?;
    let framed = rules::frame(&body).map_err(invalid)?;
    send_frame(socket, &framed, descriptor)
}

/// Receive one frame and any descriptors that came with its first bytes.
///
/// Every received descriptor is owned (and so closed) at once, even when the frame is then
/// refused. The 2-byte length is checked before the body is read.
#[allow(unsafe_code)]
fn receive_frame(socket: BorrowedFd<'_>) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut buffer = vec![0_u8; MAX_MESSAGE_BYTES + 2];
    let mut ancillary = nix::cmsg_space!([RawFd; MAX_DESCRIPTORS]);
    let (received, truncated, raw) = {
        let mut slices = [IoSliceMut::new(&mut buffer)];
        let message = recvmsg::<()>(
            socket.as_raw_fd(),
            &mut slices,
            Some(&mut ancillary),
            MsgFlags::empty(),
        )?;
        let mut raw = Vec::new();
        for control in message.cmsgs()? {
            if let ControlMessageOwned::ScmRights(descriptors) = control {
                raw.extend(descriptors);
            }
        }
        (
            message.bytes,
            message.flags.contains(MsgFlags::MSG_CTRUNC),
            raw,
        )
    };
    let mut descriptors = Vec::with_capacity(raw.len());
    for descriptor in raw {
        // SAFETY: a successful recvmsg installed each SCM_RIGHTS descriptor as a new entry
        // in this process's table that nothing else owns. Wrapping it at once means every
        // path below, refusals included, closes it exactly once.
        let owned = unsafe { OwnedFd::from_raw_fd(descriptor) };
        nix::fcntl::fcntl(
            &owned,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )?;
        descriptors.push(owned);
    }
    if truncated || descriptors.len() > 1 || received < 2 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let length = rules::frame_length([buffer[0], buffer[1]]).map_err(invalid)?;
    let mut filled = received;
    while filled < length + 2 {
        let read = nix::unistd::read(socket, &mut buffer[filled..length + 2])?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += read;
    }
    if filled != length + 2 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    buffer.truncate(length + 2);
    buffer.drain(..2);
    Ok((buffer, descriptors))
}

// ---------------------------------------------------------------------------
// The agent side.
// ---------------------------------------------------------------------------

/// Ask the helper for one thing, attaching `utun` when the request needs it.
///
/// The helper must be root: the connected peer's credentials are checked before anything is
/// sent. Returns the reply and, for [`Request::Open`], the new utun (already close-on-exec).
///
/// # Errors
/// Reports a missing helper, a peer that is not root, a timeout, and any refusal in the reply.
pub fn request(
    request: &Request,
    utun: Option<BorrowedFd<'_>>,
) -> io::Result<(Reply, Option<OwnedFd>)> {
    if request.needs_utun() != utun.is_some() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let stream = UnixStream::connect(HELPER_SOCKET).map_err(|error| {
        io::Error::new(
            error.kind(),
            "the mesh helper is not reachable; run infraternal up again to reinstall it",
        )
    })?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    if getsockopt(&stream, LocalPeerCred)?.uid() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the mesh helper socket is not served by root",
        ));
    }
    let framed = rules::encode_request(request).map_err(invalid)?;
    send_frame(stream.as_fd(), &framed, utun)?;
    let (body, mut descriptors) = receive_frame(stream.as_fd())?;
    let reply: Reply = serde_json::from_slice(&body).map_err(|_| io::ErrorKind::InvalidData)?;
    if !reply.ok {
        return Err(io::Error::other(reply.error.unwrap_or_else(|| {
            "the mesh helper refused the request".to_owned()
        })));
    }
    let wanted = usize::from(*request == Request::Open);
    if descriptors.len() != wanted {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((reply, descriptors.pop()))
}

/// Ask the helper for a fresh utun; returns its descriptor and interface name.
///
/// # Errors
/// Reports any helper failure, or a reply whose interface name is not a utun.
pub(crate) fn open_utun() -> io::Result<(OwnedFd, String)> {
    let (reply, descriptor) = request(&Request::Open, None)?;
    let descriptor = descriptor.ok_or(io::ErrorKind::InvalidData)?;
    // The name the helper reports must be the one the descriptor itself answers.
    let name = utun_name(Some(descriptor.as_fd()))?;
    if reply.interface.as_deref() != Some(name.as_str()) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((descriptor, name))
}

// ---------------------------------------------------------------------------
// Install and removal (root).
// ---------------------------------------------------------------------------

/// Install or refresh the helper for `uid` and load it into launchd.
///
/// Copies the running binary to [`HELPER_BINARY`] (root-owned, 0755), writes the property
/// list, and bootstraps it. Refuses a root-mode Mac, a helper registered for another account,
/// root itself, and an unknown uid. Running it again for the same uid refreshes the binary.
fn install(uid: u32) -> io::Result<()> {
    require_root()?;
    if uid == 0 || nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))?.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "user mode needs a real, non-root account",
        ));
    }
    if Path::new(ROOT_MODE_PLIST).exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "this Mac runs infraternal in root mode; remove that first",
        ));
    }
    match registered_uid()? {
        Some(registered) if registered != uid => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "the mesh helper is registered for another account on this Mac",
            ));
        }
        None if Path::new(HELPER_PLIST).exists() => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "an unrecognised mesh helper property list is in the way",
            ));
        }
        _ => {}
    }
    publish_binary(&std::env::current_exe()?)?;
    publish_file(
        Path::new(HELPER_PLIST),
        rules::helper_plist(uid).as_bytes(),
        0o644,
    )?;
    // A loaded older job keeps its old socket settings, so it is replaced, never reused.
    let _ = launchctl(&["bootout", &format!("system/{HELPER_LABEL}")]);
    launchctl_checked(&["bootstrap", "system", HELPER_PLIST])?;
    launchctl_checked(&["enable", &format!("system/{HELPER_LABEL}")])?;
    Ok(())
}

/// Remove resolver files, the property list and the binary; the launchd job goes last.
///
/// `uid` is the caller's registered uid when the helper removes itself on request; `None` is
/// an administrator's `sudo` removal, which also unloads the job directly.
fn remove_registration(uid: Option<u32>) -> io::Result<()> {
    require_root()?;
    let registered = registered_uid()?;
    if uid.is_some() && registered != uid {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    clear_resolver()?;
    if registered.is_some() {
        remove_root_file(Path::new(HELPER_PLIST))?;
    }
    remove_root_file(Path::new(HELPER_BINARY))?;
    if uid.is_none() {
        let _ = launchctl(&["bootout", &format!("system/{HELPER_LABEL}")]);
    }
    // launchd keeps its listening socket open until the job is unloaded but never unlinks
    // the path, so removal does: no new connection can arrive, and nothing is left behind
    // (found on the Mac VM). Only root can create entries in /var/run, so the path is ours.
    match fs::symlink_metadata(HELPER_SOCKET) {
        Ok(metadata) if std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()) => {
            fs::remove_file(HELPER_SOCKET)?;
        }
        Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

/// Unload the helper's launchd job after the removal reply was sent.
///
/// launchd stops a job's own process group when the job is unloaded, so the unload runs in a
/// new process group and outlives this helper.
fn finish_removal() {
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{HELPER_LABEL}")])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn();
}

/// Remove a root-owned file; an absent file is fine, a foreign one is refused.
fn remove_root_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && metadata.uid() == 0 => fs::remove_file(path),
        Ok(_) => Err(io::ErrorKind::PermissionDenied.into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Copy `source` to [`HELPER_BINARY`] as a root-owned 0755 file and check what dyld would load.
fn publish_binary(source: &Path) -> io::Result<()> {
    let directory = Path::new(HELPER_DIRECTORY);
    match fs::DirBuilder::new().mode(0o755).create(directory) {
        // sudo can pass on a restrictive umask; the folder must stay traversable for launchd.
        Ok(()) => fs::set_permissions(directory, fs::Permissions::from_mode(0o755))?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    for ancestor in directory.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the privileged helper folder is not root-owned",
            ));
        }
    }
    let mut bytes = Vec::new();
    File::open(source)?.read_to_end(&mut bytes)?;
    publish_file(Path::new(HELPER_BINARY), &bytes, 0o755)?;
    // A root-owned file can still make dyld load a user's library (J162 F2, #265).
    if let Err(error) = crate::macos_image::check_file(Path::new(HELPER_BINARY)) {
        let _ = fs::remove_file(HELPER_BINARY);
        return Err(error);
    }
    Ok(())
}

/// Write `contents` beside `path` with its final mode, sync, and rename it into place.
///
/// The mode is set explicitly on the open file, never left to the umask: `infraternal up`
/// runs the install through `sudo`, which can keep a person's `077` or `027` umask. A `0600`
/// property list would then be unreadable to the person's agent, which would skip the mesh
/// and leave the helper behind at uninstall (J1087, J1027).
fn publish_file(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (!metadata.is_file() || metadata.uid() != 0)
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(io::ErrorKind::InvalidInput)?;
    let temporary = path.with_file_name(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(path.parent().ok_or(io::ErrorKind::InvalidInput)?)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Run `/bin/launchctl` with an empty environment.
fn launchctl(arguments: &[&str]) -> io::Result<std::process::Output> {
    system_tool("/bin/launchctl", arguments)
}

/// Run `/bin/launchctl` and require success.
fn launchctl_checked(arguments: &[&str]) -> io::Result<()> {
    if launchctl(arguments)?.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "launchctl {} failed",
            arguments.first().copied().unwrap_or_default()
        )))
    }
}
