/// Packet Tunnel provider for the Simulator device-join spike (#580).

import Foundation
import Darwin
import NetworkExtension

/// Owns the Rust join key and QUIC link for the lifetime of the extension.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    /// Rejects redirects so the one-time invitation stays on its approved origin.
    private let redirectDelegate = NoHTTPRedirects()
    /// Uses temporary networking state without inheriting app or browser cookies.
    private lazy var httpSession = URLSession(
        configuration: .ephemeral,
        delegate: redirectDelegate,
        delegateQueue: nil
    )
    /// Rust identity and link state scoped to this extension process.
    private var join: DeviceJoin?
    /// The readable device label sent to the server for owner approval.
    private var hostname = "iPhone Simulator"

    /// Starts a route-free tunnel fixture and creates the Simulator identity.
    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        hostname = (protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["hostname"] as? String ?? hostname
        do {
            join = try DeviceJoin(signer: DeviceIdentity())
        } catch {
            completionHandler(error)
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.7.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = []
        settings.ipv4Settings = ipv4
        setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }

    /// Closes the extension's QUIC endpoint when the app stops the tunnel.
    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        join = nil
        completionHandler()
    }

    /// Handles enrollment facts and a single URLSession-backed Rust join.
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        guard let completionHandler else { return }
        guard let message = try? JSONDecoder().decode(ProviderCommand.self, from: messageData),
              let join else {
            completionHandler(nil)
            return
        }

        if message.command == "enrolment" {
            do {
                completionHandler(try join.enrolmentRequest(hostname: hostname))
            } catch {
                completionHandler(errorReply())
            }
            return
        }
        if message.command == "memory" {
            let reply = JoinStatusReply(
                status: join.status().description,
                rttMilliseconds: nil,
                joinElapsedMilliseconds: nil,
                memorySamples: [MemorySample(phase: "idle", bytes: processFootprint())]
            )
            completionHandler(try? JSONEncoder().encode(reply))
            return
        }
        guard let invitation = message.invitation else {
            completionHandler(errorReply())
            return
        }
        Task {
            let startedAt = ProcessInfo.processInfo.systemUptime
            var samples = [MemorySample(phase: "join_start", bytes: processFootprint())]
            do {
                let request = try join.prepareJoin(invitationJson: invitation)
                samples.append(MemorySample(phase: "csr_ready", bytes: processFootprint()))
                guard let url = URL(string: request.url) else {
                    completionHandler(errorReply())
                    return
                }
                var urlRequest = URLRequest(url: url)
                urlRequest.httpMethod = "POST"
                urlRequest.setValue(request.contentType, forHTTPHeaderField: "Content-Type")
                urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
                urlRequest.httpBody = request.body
                urlRequest.httpShouldHandleCookies = false
                let (body, response) = try await httpSession.data(for: urlRequest)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                    completionHandler(errorReply())
                    return
                }
                samples.append(MemorySample(phase: "http_reply", bytes: processFootprint()))
                try join.finishJoin(response: body)
                samples.append(MemorySample(phase: "certificate_verified", bytes: processFootprint()))
                _ = try join.connect()
                samples.append(MemorySample(phase: "quic_connected", bytes: processFootprint()))
                let rtt = try join.pingMillis()
                let reply = JoinStatusReply(
                    status: "Connected",
                    rttMilliseconds: rtt,
                    joinElapsedMilliseconds: UInt64(max(0, (ProcessInfo.processInfo.systemUptime - startedAt) * 1000)),
                    memorySamples: samples
                )
                completionHandler(try JSONEncoder().encode(reply))
            } catch {
                completionHandler(errorReply())
            }
        }
    }

    /// Encodes a generic error without leaking response text or join bytes.
    private func errorReply() -> Data? {
        try? JSONEncoder().encode(JoinStatusReply(
            status: "Join failed",
            rttMilliseconds: nil,
            joinElapsedMilliseconds: nil,
            memorySamples: [MemorySample(phase: "join_failed", bytes: processFootprint())]
        ))
    }

    /// Reads the physical footprint the OS uses for its extension memory limit.
    private func processFootprint() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? info.phys_footprint : nil
    }
}

/// Gives the UniFFI link state a stable string for the app's status line.
private extension LinkStatus {
    /// Gives each Rust link state a stable label for the app's status line.
    var description: String {
        switch self {
        case .notJoined: "Not joined"
        case .joined: "Joined"
        case .connected: "Connected"
        }
    }
}

/// The app's one provider-message shape.
private struct ProviderCommand: Decodable {
    /// Optional control request, such as enrollment facts or an idle-memory sample.
    let command: String?
    /// Device invitation JSON to pass into the Rust join boundary.
    let invitation: String?
}

/// The provider's join result and Simulator memory measurement.
private struct JoinStatusReply: Encodable {
    /// Human-readable state for the app's status label.
    let status: String
    /// QUIC ping time after a successful Hello exchange.
    let rttMilliseconds: UInt64?
    /// Duration from join message receipt through the first link ping.
    let joinElapsedMilliseconds: UInt64?
    /// Extension physical-footprint samples taken across the join.
    let memorySamples: [MemorySample]
}

/// One sample of the memory number used by iOS to enforce the extension limit.
private struct MemorySample: Codable {
    /// The stage at which the extension reported its physical footprint.
    let phase: String
    /// Bytes in the extension's physical footprint, if the kernel reported it.
    let bytes: UInt64?
}

/// A URLSession delegate that never follows redirects carrying join capabilities.
private final class NoHTTPRedirects: NSObject, URLSessionTaskDelegate {
    /// Returns the redirect response to the caller without forwarding its request body.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}
