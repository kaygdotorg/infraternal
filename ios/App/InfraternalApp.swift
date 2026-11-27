/// A small iOS app for approving a device join and showing its live link status (#580).

import AuthenticationServices
import Foundation
import NetworkExtension
import SwiftUI
import UIKit
import os

@main
/// The application entry point and root scene for the join screen.
struct InfraternalApp: App {
    /// Owns the join flow while SwiftUI redraws its status.
    @StateObject private var model = JoinModel()

    /// Shows the app's single device-join screen.
    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}

/// Holds the URLSession approval flow and the extension's current link status.
@MainActor
final class JoinModel: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {
    /// Records only join timings and measured extension memory values.
    private let logger = Logger(subsystem: "org.kayg.infraternal.ios", category: "memory")
    /// Rejects redirects so an approval or join capability stays on its origin.
    private let redirectDelegate = NoHTTPRedirects()
    /// Uses in-memory networking state without carrying cookies between joins.
    private lazy var httpSession = URLSession(
        configuration: .ephemeral,
        delegate: redirectDelegate,
        delegateQueue: nil
    )
    /// The public HTTPS origin the user wants to join.
    @Published var server = "https://test.ssh.kayg.org"
    /// The device label the owner sees in the approval sheet.
    @Published var deviceName = "iPhone Simulator"
    /// The latest join or link state shown on screen.
    @Published var status = "Not joined"
    /// A short explanation of the current state.
    @Published var detail = "The device identity stays in the Packet Tunnel extension."
    /// Whether an approval and join operation is in progress.
    @Published var busy = false
    /// The extension's measured physical footprint, when available.
    @Published var memory = ""

    /// Whether this screen has a Simulator VPN profile it can stop.
    var hasManager: Bool { manager != nil }

    /// The app-owned VPN profile currently loaded from Network Extension.
    private var manager: NETunnelProviderManager?
    /// The server's approval sheet while an owner reviews the device request.
    private var authSession: ASWebAuthenticationSession?
    /// The current approval and join task, cancelled when the user stops the tunnel.
    private var joinTask: Task<Void, Never>?

    /// Starts the extension, obtains its device facts and asks the server for approval.
    func beginJoin() {
        guard !busy else { return }
        busy = true
        status = "Starting"
        detail = "Preparing a device identity in the extension."
        joinTask = Task { [weak self] in
            guard let self else { return }
            await self.runJoin()
            self.joinTask = nil
        }
    }

    /// Stops the Packet Tunnel and removes the Simulator VPN profile.
    func stop() {
        joinTask?.cancel()
        joinTask = nil
        authSession?.cancel()
        authSession = nil
        Task { await stopAndRemoveProfile() }
    }

    /// Loads this app's existing profile so the stop action also works after relaunch.
    func loadExistingProfile() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            manager = managers.first(where: { $0.localizedDescription == "Infraternal Simulator" })
            if manager?.connection.status == .connected {
                status = "Tunnel active"
                detail = "The Simulator Packet Tunnel is active and can be stopped below."
            }
        } catch {
            detail = "The Simulator tunnel profile could not be loaded."
        }
    }

    /// Provides the app's window for the server-owned passkey approval sheet.
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
    }

    /// Runs the complete approval and device-link exchange.
    private func runJoin() async {
        do {
            let origin = try serverOrigin(input: server)
            let tunnel = try await startExtension()
            let facts = try await sendProviderMessage(tunnel, command: "enrolment")
            if let bytes = try? await sendProviderMessage(tunnel, command: "memory"),
               let reading = try? JSONDecoder().decode(JoinResult.self, from: bytes),
               !reading.memorySamples.isEmpty {
                updateMemory(reading.memorySamples)
            }
            let join = try MachineJoin(server: origin, deviceName: deviceName, request: facts)

            let started = try await send(join.startRequest())
            let approval = try join.onStart(reply: started)
            status = "Waiting for approval"
            detail = "Approve this device in the server's passkey sheet."
            try openApprovalPage(approval.approvalUrl)

            let clock = ContinuousClock()
            let deadline = clock.now.advanced(by: .seconds(Int64(clamping: approval.expiresInSeconds)))
            while clock.now < deadline {
                let request = try join.redeemRequest()
                let response = try await send(request)
                switch try join.onRedeem(reply: response) {
                case .pending:
                    try await Task.sleep(for: .seconds(2))
                case let .retryAfter(seconds):
                    try await Task.sleep(for: .seconds(max(1, seconds ?? 2)))
                case let .invitation(json):
                    authSession?.cancel()
                    authSession = nil
                    status = "Joining"
                    detail = "Rust is verifying the invitation and opening the QUIC device link."
                    let result = try await sendProviderMessage(tunnel, invitation: json)
                    let payload = try JSONDecoder().decode(JoinResult.self, from: result)
                    updateMemory(payload.memorySamples)
                    status = payload.status
                    guard payload.status == "Connected" else {
                        throw JoinFlowError.provider("The Rust device link did not open.")
                    }
                    detail = "Rust join: \(payload.joinElapsedMilliseconds ?? 0) ms."
                    if let milliseconds = payload.rttMilliseconds {
                        detail += " Ping: \(milliseconds) ms."
                    }
                    logger.notice("J1312_JOIN elapsed_ms=\(payload.joinElapsedMilliseconds ?? 0, privacy: .public)")
                    busy = false
                    return
                }
            }
            throw JoinFlowError.approvalExpired
        } catch {
            authSession?.cancel()
            authSession = nil
            if Task.isCancelled {
                status = "Not joined"
                detail = "The Simulator tunnel has stopped."
            } else {
                status = "Join failed"
                detail = String(describing: error)
            }
            busy = false
        }
    }

    /// Shows the Q3 Simulator limit against the extension's measured footprint.
    private func updateMemory(_ samples: [MemorySample]) {
        let measured = samples.compactMap { sample -> (String, UInt64)? in
            guard let bytes = sample.bytes else { return nil }
            logger.notice("J1312_MEMORY phase=\(sample.phase, privacy: .public) bytes=\(bytes, privacy: .public)")
            return (sample.phase, bytes)
        }
        let idle = measured.first(where: { $0.0 == "idle" })?.1
        let active = measured.filter { $0.0 != "idle" }.map(\.1).max()
        let idleText = idle.map { String(format: "%.2f MiB", Double($0) / 1_048_576) } ?? "not measured"
        let activeText = active.map { String(format: "%.2f MiB", Double($0) / 1_048_576) } ?? "not measured"
        let required = ["idle", "join_start", "csr_ready", "http_reply", "certificate_verified", "quic_connected"]
        let phases = Set(samples.map(\.phase))
        let limit: String
        if !required.allSatisfy(phases.contains) {
            limit = "measurement incomplete"
        } else if max(idle ?? 0, active ?? 0) <= 20 * 1_048_576 {
            limit = "within limit"
        } else {
            limit = "over 20 MiB limit"
        }
        memory = "Extension phys_footprint: idle \(idleText), join peak \(activeText) (\(limit))"
    }

    /// Waits for the VPN interface to close before removing this app's profile.
    private func stopAndRemoveProfile() async {
        guard let manager else { return }
        if let session = manager.connection as? NETunnelProviderSession {
            session.stopVPNTunnel()
            for _ in 0..<50 {
                if session.status == .disconnected || session.status == .invalid { break }
                try? await Task.sleep(for: .milliseconds(100))
            }
        }
        do {
            try await manager.removeFromPreferences()
            self.manager = nil
            status = "Not joined"
            detail = "The Simulator tunnel has stopped."
            memory = ""
            busy = false
        } catch {
            detail = "The tunnel profile could not be removed."
            busy = false
        }
    }

    /// Creates and starts the Packet Tunnel provider with no included routes.
    private func startExtension() async throws -> NETunnelProviderSession {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        let manager = managers.first(where: { $0.localizedDescription == "Infraternal Simulator" })
            ?? NETunnelProviderManager()
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = "org.kayg.infraternal.ios.PacketTunnel"
        tunnelProtocol.serverAddress = "Infraternal device join"
        tunnelProtocol.providerConfiguration = ["hostname": deviceName]
        manager.protocolConfiguration = tunnelProtocol
        manager.localizedDescription = "Infraternal Simulator"
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw JoinFlowError.extensionUnavailable
        }
        try session.startVPNTunnel(options: nil)
        self.manager = manager
        try await waitUntilConnected(session)
        return session
    }

    /// Waits for the extension process to finish its Network Extension handshake.
    private func waitUntilConnected(_ session: NETunnelProviderSession) async throws {
        for _ in 0..<100 {
            if session.status == .connected { return }
            if session.status == .invalid || session.status == .disconnected {
                throw JoinFlowError.extensionUnavailable
            }
            try await Task.sleep(for: .milliseconds(200))
        }
        throw JoinFlowError.extensionUnavailable
    }

    /// Opens the server page in Apple's system authentication sheet.
    private func openApprovalPage(_ address: String) throws {
        guard let url = URL(string: address) else { throw JoinFlowError.badURL }
        let session = ASWebAuthenticationSession(url: url, callbackURLScheme: "infraternal") { [weak self] _, _ in
            Task { @MainActor in self?.authSession = nil }
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false
        authSession = session
        guard session.start() else {
            authSession = nil
            throw JoinFlowError.approvalPageUnavailable
        }
    }

    /// Sends one FFI-built request through the platform's ordinary HTTPS trust.
    private func send(_ request: HttpRequest) async throws -> HttpResponse {
        guard let url = URL(string: request.url) else { throw JoinFlowError.badURL }
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = request.method
        urlRequest.allHTTPHeaderFields = request.headers
        urlRequest.httpBody = request.body
        urlRequest.httpShouldHandleCookies = false
        let (body, response) = try await httpSession.data(for: urlRequest)
        guard let http = response as? HTTPURLResponse else { throw JoinFlowError.badResponse }
        let retry = http.value(forHTTPHeaderField: "Retry-After").flatMap(UInt64.init)
        return HttpResponse(status: UInt16(clamping: http.statusCode), body: body, retryAfterSeconds: retry)
    }

    /// Calls the extension and returns its bytes or final link status.
    private func sendProviderMessage(
        _ session: NETunnelProviderSession,
        command: String? = nil,
        invitation: String? = nil
    ) async throws -> Data {
        let message = ProviderMessage(command: command, invitation: invitation)
        let encoded = try JSONEncoder().encode(message)
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(encoded) { response in
                    guard let response else {
                        continuation.resume(throwing: JoinFlowError.badResponse)
                        return
                    }
                    if let envelope = try? JSONDecoder().decode(ProviderReply.self, from: response) {
                        if let error = envelope.error {
                            continuation.resume(throwing: JoinFlowError.provider(error))
                        } else if let data = envelope.data {
                            continuation.resume(returning: data)
                        } else if let result = envelope.result {
                            continuation.resume(returning: result)
                        } else {
                            continuation.resume(returning: response)
                        }
                    } else {
                        continuation.resume(returning: response)
                    }
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}

/// One command that the app sends to its packet tunnel provider.
private struct ProviderMessage: Encodable {
    /// A control request for enrollment facts or the extension's idle footprint.
    let command: String?
    /// The approved join invitation passed to Rust in the extension.
    let invitation: String?
}

/// A provider reply carrying enrollment bytes, link status, or a safe error.
private struct ProviderReply: Decodable {
    /// Enrollment or status bytes wrapped by some provider replies.
    let data: Data?
    /// Alternate provider payload field used by the simulator transport.
    let result: Data?
    /// Safe error text returned when an extension step cannot complete.
    let error: String?
}

/// The status and measured values returned after the Rust link opens.
private struct JoinResult: Decodable {
    /// Human-readable extension link state.
    let status: String
    /// Round-trip time of the Rust device-link ping.
    let rttMilliseconds: UInt64?
    /// Time from receiving the invitation to the first successful link ping.
    let joinElapsedMilliseconds: UInt64?
    /// Physical-footprint readings collected by the extension.
    let memorySamples: [MemorySample]
}

/// One phys_footprint sample returned from the Packet Tunnel extension.
private struct MemorySample: Decodable {
    /// Stage name that identifies when the extension was measured.
    let phase: String
    /// Physical-footprint byte count, absent if task_info did not return it.
    let bytes: UInt64?
}

/// Errors from the short Simulator join flow.
private enum JoinFlowError: Error, CustomStringConvertible {
    case extensionUnavailable
    case approvalExpired
    case approvalPageUnavailable
    case badURL
    case badResponse
    case provider(String)

    /// A short error message that never includes HTTP response data or tokens.
    var description: String {
        switch self {
        case .extensionUnavailable: "The Packet Tunnel extension could not start."
        case .approvalExpired: "The device approval expired before it was approved."
        case .approvalPageUnavailable: "The server's approval page could not be opened."
        case .badURL: "The server returned an invalid request URL."
        case .badResponse: "The server or extension returned an invalid response."
        case let .provider(reason): "The extension could not finish the device join: \(reason)"
        }
    }
}

/// The one screen for starting the join and reading the current extension state.
private struct ContentView: View {
    /// The join flow and display state owned by the root app scene.
    @ObservedObject var model: JoinModel

    /// Presents server, device, join and measured memory state in one form.
    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("https://server.example", text: $model.server)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
                        .autocorrectionDisabled()
                    TextField("Device name", text: $model.deviceName)
                }
                Section("Device link") {
                    Label(model.status, systemImage: model.status == "Connected" ? "checkmark.circle.fill" : "network")
                    Text(model.detail).font(.footnote).foregroundStyle(.secondary)
                    if !model.memory.isEmpty {
                        Text(model.memory).font(.footnote).monospacedDigit()
                    }
                }
                Section {
                    Button("Join device", action: model.beginJoin)
                        .disabled(model.busy)
                    Button("Stop and remove Simulator profile", role: .destructive, action: model.stop)
                        .disabled(!model.hasManager)
                }
            }
            .navigationTitle("Infraternal")
        }
        .task { await model.loadExistingProfile() }
    }
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
