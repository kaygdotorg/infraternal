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
//! `/etc/resolver` files for reserved private-use suffixes; route up to 64 private IPv4 networks
//! (approved subnet routes, D197 M3) to that utun; remove its own registration. It
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
//! **How input is checked:** one frame of at most 16 KiB of JSON, unknown fields refused, a
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
//! **Subnet routes (#580):** a `networks` request routes approved networks behind router peers
//! into the caller's utun. The helper cannot check the server's approval itself (the server signs
//! nothing a root process could verify), so it holds the same line as for the mesh route: only
//! on the caller's own utun, and only while that utun already holds its mesh address and mesh
//! route; only private IPv4 networks (RFC 1918 and shared CGNAT), never the mesh's own range;
//! never a network that overlaps any route or interface network elsewhere on the Mac
//! ([`crate::macos_subnet_routes::plan_networks`]), so no other account loses a network it uses;
//! and it removes only routes on the caller's utun. A person's process could already route any
//! unused private range to a utun of its own through `open` and `address`; this request adds no
//! reach beyond that. The agent's packet filter still decides which flows may start.
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
/// The root-mode `LaunchDaemon`, under its current and its pre-#580 name; user mode refuses to
/// install beside either.
const ROOT_MODE_PLISTS: [&str; 2] = [rules::DAEMON_PLIST, rules::legacy::DAEMON_PLIST];

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
/// A helper installed by a build before the move to `kayg.infraternal` (#580) counts too, so
/// a Mac that updated its agent but has not run `infraternal up` again keeps its mesh.
///
/// # Errors
/// Refuses a property list that is not a root-owned regular file.
pub fn registered_uid() -> io::Result<Option<u32>> {
    Ok(registration()?.map(|registration| registration.uid))
}

/// A registered helper: the account it serves and whether it still has the pre-#580 names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Registration {
    /// The account the helper serves.
    uid: u32,
    /// The helper was installed by a build that used the `org.infraternal` names.
    legacy: bool,
}

impl Registration {
    /// The socket this helper listens on.
    fn socket(self) -> &'static str {
        if self.legacy {
            rules::legacy::HELPER_SOCKET
        } else {
            HELPER_SOCKET
        }
    }
}

/// Read the helper registration: the current property list first, then the old one.
///
/// A current property list that exists but is not ours is `None` and hides an old one, so the
/// refusal in [`install`] stays the single answer for a foreign file in the way.
fn registration() -> io::Result<Option<Registration>> {
    let read = |path: &str, parse: fn(&str) -> Option<u32>| -> io::Result<Option<Option<u32>>> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                let mut contents = String::new();
                File::open(path)?.take(8192).read_to_string(&mut contents)?;
                Ok(Some(parse(&contents)))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    };
    if let Some(parsed) = read(HELPER_PLIST, rules::helper_plist_uid)? {
        return Ok(parsed.map(|uid| Registration { uid, legacy: false }));
    }
    Ok(
        read(rules::legacy::HELPER_PLIST, rules::legacy::helper_plist_uid)?
            .flatten()
            .map(|uid| Registration { uid, legacy: true }),
    )
}

/// The binary an administrator runs through `sudo` to remove the registered helper: the old
/// path when the helper still has the pre-#580 names, otherwise the current one.
#[must_use]
pub fn installed_binary() -> &'static str {
    match registration() {
        Ok(Some(Registration { legacy: true, .. })) => rules::legacy::HELPER_BINARY,
        _ => HELPER_BINARY,
    }
}

/// Which pre-#580 helper files exist, for planning their removal. The `LaunchAgent` field is
/// left `false`: it is per person and the caller looks for it.
#[must_use]
pub fn legacy_helper_found() -> rules::legacy::Found {
    let present = |path: &str| fs::symlink_metadata(path).is_ok();
    rules::legacy::Found {
        agent_plist: false,
        helper: rules::legacy::HelperFiles {
            plist: present(rules::legacy::HELPER_PLIST),
            binary: present(rules::legacy::HELPER_BINARY),
            socket: present(rules::legacy::HELPER_SOCKET),
        },
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
        Request::Networks { networks } => route_networks(utun, networks, uid),
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
        .filter_map(|entry| {
            entry
                .address
                .and_then(|a| a.as_sockaddr_in6().map(nix::sys::socket::SockaddrIn6::ip))
        })
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

/// Make the subnet routes on the caller's utun exactly the requested networks, minus those the
/// plan leaves out (see the threat notes and [`crate::macos_subnet_routes`]).
///
/// The utun must already hold its mesh IPv4 address and a mesh prefix route holding it, so only
/// a configured mesh utun takes networks. A network on an earlier utun of this person's agent is
/// moved over; anything else that overlaps is left out and named in the reply. Removals run
/// before additions, so a network that moved between requests is never routed twice.
fn route_networks(
    utun: Option<BorrowedFd<'_>>,
    networks: &[infraternal_mesh::networks::Network],
    uid: u32,
) -> io::Result<(Reply, Option<OwnedFd>)> {
    use crate::macos_subnet_routes::{plan_networks, table_network};
    use rules::NetworkOutcome;
    let interface = utun_name(utun)?;
    let own = nix::ifaddrs::getifaddrs()?
        .filter(|entry| entry.interface_name == interface)
        .find_map(|entry| {
            entry
                .address
                .and_then(|a| a.as_sockaddr_in().map(nix::sys::socket::SockaddrIn::ip))
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the caller's utun has no mesh address yet",
            )
        })?;
    let table = routing_table(true)?;
    let meshed = table.iter().any(|row| {
        row.interface == interface
            && row.network.prefix < 32
            && row.network.contains(std::net::IpAddr::V4(own))
    });
    if !meshed {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the mesh route does not lead to the caller's utun",
        ));
    }
    let local = local_networks(true)?;
    let others: Vec<String> = table
        .iter()
        .filter(|row| row.interface != interface && row.interface.starts_with("utun"))
        .map(|row| row.interface.clone())
        .collect();
    let ours = if others.is_empty() {
        Vec::new()
    } else {
        agent_utuns(uid)
    };
    let installed = crate::macos_subnet_routes::routes_on(&interface, own, &table);
    let plan = plan_networks(
        networks,
        &interface,
        Some(own),
        &installed,
        &table,
        &local,
        &ours,
        &[],
        true,
    );
    for network in &plan.remove {
        route("delete", table_network(*network), &interface)?;
    }
    let mut outcomes: Vec<NetworkOutcome> = plan
        .skipped
        .iter()
        .map(|(network, skip)| NetworkOutcome {
            network: *network,
            installed: false,
            reason: Some(skip.sentence()),
        })
        .collect();
    for (network, earlier) in &plan.replace {
        route("delete", table_network(*network), earlier)?;
    }
    for network in &plan.keep {
        outcomes.push(NetworkOutcome {
            network: *network,
            installed: true,
            reason: None,
        });
    }
    for network in &plan.add {
        let outcome = match route("add", table_network(*network), &interface) {
            Ok(()) => NetworkOutcome {
                network: *network,
                installed: true,
                reason: None,
            },
            Err(error) => NetworkOutcome {
                network: *network,
                installed: false,
                reason: Some(error.to_string()),
            },
        };
        outcomes.push(outcome);
    }
    outcomes.sort_by_key(|outcome| outcome.network);
    Ok((
        Reply {
            ok: true,
            networks: outcomes,
            ..Reply::default()
        },
        None,
    ))
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

/// Read the routing table for one family through `netstat -rn`. Root mode's subnet routes read it
/// too ([`crate::macos_node`]).
pub(crate) fn routing_table(ipv4: bool) -> io::Result<Vec<Route>> {
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
pub(crate) fn local_networks(ipv4: bool) -> io::Result<Vec<Route>> {
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
    // A local stream socket usually takes a whole frame at once; finish any short write plainly.
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
    let socket = match registration() {
        Ok(Some(registration)) => registration.socket(),
        _ => HELPER_SOCKET,
    };
    let stream = UnixStream::connect(socket).map_err(|error| {
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
    if ROOT_MODE_PLISTS
        .iter()
        .any(|plist| Path::new(plist).exists())
    {
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
    // The new helper goes in before the old one goes out, so a failed install leaves the Mac
    // with a helper that still works. Both listen on their own sockets, so they never clash.
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
    retire_legacy_helper(Some(uid))
}

/// Remove a helper that a build before the move to `kayg.infraternal` installed (#580).
///
/// Runs inside [`install`], so it shares that run's one `sudo` prompt, and only after the new
/// helper is loaded. It carries out the root steps of [`rules::legacy::plan`]. With `uid`
/// set, an old property list must be one this code wrote for that account, or nothing is
/// touched; an administrator's removal passes `None`. Files that are not root-owned are never
/// removed (see [`remove_root_file`]). Removing the old files is idempotent.
fn retire_legacy_helper(uid: Option<u32>) -> io::Result<()> {
    use rules::legacy::{self, Step};
    if let Some(uid) = uid
        && let Some(old) = fs::read_to_string(legacy::HELPER_PLIST)
            .ok()
            .filter(|text| text.len() <= 8192)
        && legacy::helper_plist_uid(&old) != Some(uid)
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an unrecognised old mesh helper property list is in the way",
        ));
    }
    for step in legacy::plan(legacy_helper_found()) {
        match step {
            Step::UnloadHelper => {
                let _ = launchctl(&["bootout", &format!("system/{}", legacy::HELPER_LABEL)]);
            }
            Step::RemoveHelperSocket => match fs::symlink_metadata(legacy::HELPER_SOCKET) {
                Ok(metadata)
                    if std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type()) =>
                {
                    fs::remove_file(legacy::HELPER_SOCKET)?;
                }
                Ok(_) => return Err(io::ErrorKind::PermissionDenied.into()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            },
            Step::RemoveHelperPlist => remove_root_file(Path::new(legacy::HELPER_PLIST))?,
            Step::RemoveHelperBinary => remove_root_file(Path::new(legacy::HELPER_BINARY))?,
            Step::UnloadAgent | Step::RemoveAgentPlist => {}
        }
    }
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
        // An administrator's removal also takes the helper of a build before #580.
        retire_legacy_helper(None)?;
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

/// Live proofs against the installed helper on a Mac (#146, J1157). Each is ignored: it needs
/// the helper registered for the account that runs it, which no gate has.
#[cfg(test)]
mod mac_proofs {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs};
    use std::sync::Arc;
    use std::time::Instant;

    /// The test deployment: a node at `10.254.77.7` / `fd12:3456:789a::7`, peer `web` at `.9`.
    const OWN_V4: Ipv4Addr = Ipv4Addr::new(10, 254, 77, 7);
    /// The node's IPv6 address in the test `/48`.
    fn own_v6() -> Ipv6Addr {
        "fd12:3456:789a::7".parse().unwrap()
    }

    /// Ask the helper for a utun and give it the test addresses and the `/16` + `/48` routes.
    fn utun_with_routes() -> (OwnedFd, String) {
        let (utun, name) = open_utun().expect("the helper opens a utun");
        request(
            &Request::Address {
                ipv4: OWN_V4,
                ipv4_prefix: 16,
                ipv6: own_v6(),
                mtu: 1280,
            },
            Some(utun.as_fd()),
        )
        .expect("the helper routes the mesh into the utun");
        (utun, name)
    }

    /// Answer resolver queries read from `utun` until `stop` is set, as the agent's receive path
    /// does, using the same [`crate::tunnel_dns`] code. Returns how many it answered.
    fn serve(utun: Arc<OwnedFd>, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<usize> {
        std::thread::spawn(move || {
            use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
            let records =
                crate::dns::Records::for_tests(OWN_V4, &[("web", Ipv4Addr::new(10, 254, 77, 9))]);
            let resolver = infraternal_mesh::address::resolver_address(own_v6());
            let mut answered = 0;
            let mut frame = vec![0_u8; 2048];
            while !stop.load(Ordering::SeqCst) {
                let mut fds = [PollFd::new(utun.as_fd(), PollFlags::POLLIN)];
                if poll(&mut fds, PollTimeout::from(100_u16)).unwrap_or(0) == 0 {
                    continue;
                }
                let Ok(length) = nix::unistd::read(utun.as_fd(), &mut frame) else {
                    continue;
                };
                let packet = &frame[4.min(length)..length];
                if let Some(reply) = crate::tunnel_dns::answer(packet, resolver, &records, 1280) {
                    let mut out = 30_u32.to_be_bytes().to_vec();
                    out.extend_from_slice(&reply);
                    if nix::unistd::write(utun.as_fd(), &out).is_ok() {
                        answered += 1;
                    }
                }
            }
            answered
        })
    }

    /// J1027 F2: with the resolver files written by the helper, the system resolver's queries for
    /// `web.internal` reach the in-mesh resolver address through the utun and are answered from
    /// there. Nobody can bind that address, and once the utun is gone nothing answers.
    #[test]
    #[ignore = "Run on a Mac as the account the helper is registered for."]
    fn the_system_resolver_is_answered_from_the_tunnel() {
        let (utun, name) = utun_with_routes();
        request(
            &Request::Resolver {
                suffixes: vec!["internal".to_owned()],
            },
            Some(utun.as_fd()),
        )
        .expect("the helper writes the resolver files");
        let file = fs::read_to_string("/etc/resolver/internal").unwrap();
        println!("utun {name}; /etc/resolver/internal:\n{file}");
        assert!(
            file.contains("nameserver fd12:3456:789a:ffff::53\nport 53\n"),
            "{file}"
        );
        let resolver = infraternal_mesh::address::resolver_address(own_v6());
        let squat = std::net::UdpSocket::bind((resolver, 53));
        println!("binding [{resolver}]:53 as this account: {squat:?}");
        assert!(
            squat.is_err(),
            "no local program can hold the resolver address"
        );

        let utun = Arc::new(utun);
        let stop = Arc::new(AtomicBool::new(false));
        let server = serve(Arc::clone(&utun), Arc::clone(&stop));
        let started = Instant::now();
        let found: Vec<_> = ("web.internal", 0)
            .to_socket_addrs()
            .expect("the system resolver answers web.internal")
            .collect();
        let first = started.elapsed();
        println!("web.internal -> {found:?} in {first:?}");
        assert!(
            found
                .iter()
                .any(|a| a.ip() == std::net::IpAddr::V4(Ipv4Addr::new(10, 254, 77, 9)))
        );
        // Distinct absent names, so each lookup is a real round trip through the tunnel (the
        // NXDOMAIN path) rather than an answer from the system's cache.
        let mut times = Vec::new();
        for round in 0..40 {
            let started = Instant::now();
            let _ = (format!("absent{round}.internal"), 0).to_socket_addrs();
            times.push(started.elapsed());
        }
        times.sort();
        println!(
            "uncached lookups n=40: p50 {:?} p95 {:?} max {:?}",
            times[20], times[38], times[39]
        );
        stop.store(true, Ordering::SeqCst);
        let answered = server.join().unwrap();
        println!("answered from the tunnel: {answered}");
        assert!(answered >= 1);

        // Without the utun, its routes are gone and nothing on the Mac answers.
        drop(utun);
        let started = Instant::now();
        let gone = ("other.internal", 0).to_socket_addrs();
        println!(
            "after the utun closed: {:?} in {:?}",
            gone.as_ref().map(|a| a.clone().count()),
            started.elapsed()
        );
        assert!(gone.is_err() || gone.unwrap().count() == 0);
        request(&Request::ClearResolver, None).expect("clear the resolver files");
        assert!(!Path::new("/etc/resolver/internal").exists());
    }

    /// J1027 F1: a second utun asking for the same prefix takes the route over only when the
    /// first utun is held by the person's installed infraternal binary. Run it twice: from that
    /// path (`~/Library/Application Support/infraternal/bin/infraternal`), where it must take
    /// over; and from anywhere else, where the first utun counts as another VPN and is refused.
    #[test]
    #[ignore = "Run on a Mac as the account the helper is registered for, from two paths."]
    fn only_the_installed_binary_takes_its_own_route_over() {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .unwrap()
            .unwrap();
        let installed = fs::canonicalize(rules::user_install_binary(&user.dir)).ok();
        let me = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let ours = installed.as_deref() == Some(me.as_path());
        let (first, first_name) = utun_with_routes();
        let (second, second_name) = open_utun().unwrap();
        let started = Instant::now();
        let takeover = request(
            &Request::Address {
                ipv4: OWN_V4,
                ipv4_prefix: 16,
                ipv6: own_v6(),
                mtu: 1280,
            },
            Some(second.as_fd()),
        );
        let took = started.elapsed();
        let table = routing_table(true).unwrap();
        let holder = table
            .iter()
            .find(|row| row.network == Network::v4(Ipv4Addr::new(10, 254, 0, 0), 16))
            .map(|row| row.interface.clone());
        println!(
            "running from the installed binary: {ours}; first {first_name}, second {second_name}; \
             reply {:?} in {took:?}; 10.254/16 is on {holder:?}",
            takeover
                .as_ref()
                .map(|(reply, _)| reply.ok)
                .map_err(ToString::to_string)
        );
        if ours {
            assert!(takeover.is_ok());
            assert_eq!(holder.as_deref(), Some(second_name.as_str()));
        } else {
            let error = takeover.unwrap_err().to_string();
            assert!(error.contains(&format!("on {first_name}")), "{error}");
            assert_eq!(holder.as_deref(), Some(first_name.as_str()));
        }
        drop(second);
        drop(first);
    }
}

/// Real-Mac proof of the `networks` request (#580), carried out by the helper's own handler in
/// this process. It needs root and a utun, not a registered helper, so it runs on the Mac VM as
/// root under the Mac lock.
#[cfg(test)]
mod network_proofs {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use infraternal_mesh::networks::Network as MeshNetwork;
    use std::net::Ipv4Addr;

    /// The test node's mesh address; its `/16` is routed to the utun by `address`.
    const OWN_V4: Ipv4Addr = Ipv4Addr::new(10, 252, 78, 7);
    /// The approved network the proof routes.
    const ROUTED: &str = "10.78.0.0/24";

    /// The `networks` rows of `netstat -rn` that sit on `interface`.
    fn rows_on(interface: &str) -> Vec<String> {
        let output = system_tool("/usr/sbin/netstat", &["-rn", "-f", "inet"]).unwrap();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| line.split_whitespace().nth(3) == Some(interface))
            .map(str::to_owned)
            .collect()
    }

    /// The helper routes an approved private network onto the caller's utun only after that utun
    /// holds its mesh route, leaves out the Mac's own LAN with the reason, refuses public space
    /// before anything runs, and removes what the next request no longer names.
    #[test]
    #[ignore = "Run on the macOS VM with system service privileges under the Mac lock: it routes 10.78.0.0/24 into a utun."]
    fn the_helper_routes_networks_only_onto_the_callers_configured_utun() {
        let open = crate::macos_node::OpenUtun::open_kernel().expect("open a utun as root");
        ifconfig(&[&open.name, "mtu", "1280", "up"]).unwrap();
        let utun = Some(open.fd.as_fd());
        let routed: MeshNetwork = ROUTED.parse().unwrap();
        let lan = local_networks(true)
            .unwrap()
            .into_iter()
            .filter(|row| row.interface.starts_with("en") && row.network.prefix < 32)
            .find_map(|row| MeshNetwork::new(row.network.address, row.network.prefix).ok());

        let early = handle(
            &Request::Networks {
                networks: vec![routed],
            },
            utun,
            0,
        );
        eprintln!(
            "J1169 before address: {:?}",
            early.as_ref().map(|reply| &reply.0)
        );
        assert!(
            early.is_err(),
            "a utun without its mesh route takes no networks"
        );

        handle(
            &Request::Address {
                ipv4: OWN_V4,
                ipv4_prefix: 16,
                ipv6: "fd78:1:2::7".parse().unwrap(),
                mtu: 1280,
            },
            utun,
            0,
        )
        .expect("the helper addresses the utun");
        let mut asked = vec![routed];
        asked.extend(lan);
        let request = Request::Networks { networks: asked };
        rules::validate(&request).expect("private networks pass the request check");
        let (reply, _) = handle(&request, utun, 0).expect("the helper plans the networks");
        eprintln!("J1169 helper reply: {:?}", reply.networks);
        let installed = reply
            .networks
            .iter()
            .find(|outcome| outcome.network == routed)
            .unwrap();
        assert!(installed.installed, "{installed:?}");
        if let Some(lan) = lan {
            let skipped = reply
                .networks
                .iter()
                .find(|outcome| outcome.network == lan)
                .unwrap();
            assert!(!skipped.installed);
            assert!(
                skipped.reason.as_deref().unwrap().contains("through en"),
                "{skipped:?}"
            );
        }
        let rows = rows_on(&open.name);
        eprintln!("J1169 rows on {}: {rows:#?}", open.name);
        assert!(
            rows.iter()
                .any(|row| row.starts_with("10.78.0/24") || row.starts_with("10.78/24"))
        );

        // Public space is refused by the request check, before the handler runs.
        assert!(
            rules::validate(&Request::Networks {
                networks: vec!["8.8.8.0/24".parse().unwrap()],
            })
            .is_err()
        );

        // The next request names nothing: the helper takes its network off the utun again.
        let (reply, _) = handle(&Request::Networks { networks: vec![] }, utun, 0).unwrap();
        assert_eq!(
            reply.networks,
            [] as [crate::macos_user_mode::NetworkOutcome; 0]
        );
        let rows = rows_on(&open.name);
        eprintln!("J1169 rows after the empty request: {rows:#?}");
        assert!(!rows.iter().any(|row| row.starts_with("10.78")));
        drop(open);
    }
}
