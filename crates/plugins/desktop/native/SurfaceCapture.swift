/// Role: same-process ScreenCaptureKit IOSurface → hardware encoder capture; latest damage replaces queued surfaces [D204,D266].
import AppKit
import CoreMedia
import ScreenCaptureKit
import VideoToolbox

final class SurfaceCapture: NSObject, SCStreamOutput, SCStreamDelegate {
    private let mailbox = NSLock()
    private let measure = ProcessInfo.processInfo.environment["INFRATERNAL_DESKTOP_MEASURE"] != nil
    private let encodingQueue = DispatchQueue(label: "infraternal.desktop.surface.encode", qos: .userInteractive)
    private let callbacks = DispatchQueue(label: "infraternal.desktop.surface.capture", qos: .userInteractive)
    private let encoder = Encoder()
    private var stream: SCStream?
    // Only the serial callback queue touches this bounded diagnostic counter.
    private var diagnosticCallbacks = 0
    // Preserve the callback stamp with its exact buffer through newest-frame
    // replacement; retained refreshes must never acquire a newer callback stamp.
    private var latest: (CVPixelBuffer, UInt64, UInt64, CaptureFrameDamage)?
    private var retained: (CVPixelBuffer, UInt64, UInt64, CaptureFrameDamage)?
    private var active = false
    private var stopped = false
    private var repairing = false
    private var congested = false
    private var damageState = DamageEncodingState()
    private let pixels = FramePixels()
    private var bitrate: AdaptiveBitrate
    private var refresh: DispatchSourceTimer?
    private let size: CGSize
    private let rect: CGRect
    private let target: [String: Any]
    private let hevc: Bool
    private let fps: Int
    private let output: (UInt8, Data) throws -> Void

    init(target: [String: Any], rect: CGRect, size: CGSize, hevc: Bool, fps: Int, output: @escaping (UInt8, Data) throws -> Void) {
        self.target = target; self.rect = rect; self.size = size; self.hevc = hevc; self.fps = fps; self.output = output
        bitrate = AdaptiveBitrate(maximum: max(500_000, Int(size.width * size.height) * 3))
    }

    private func trace(_ stage: String) {
        if measure {
            FileHandle.standardError.write(Data("METRIC capture_lifecycle pid=\(getpid()) stage=\(stage) at_ns=\(nanos(mach_absolute_time()))\n".utf8))
        }
    }

    func start() async throws {
        trace("enumerate_begin")
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: false)
        trace("enumerate_end")
        let filter: SCContentFilter
        let sourceRect: CGRect?
        if target["type"] as? String == "screen" {
            guard let id = target["display_id"] as? UInt32, let display = content.displays.first(where: { $0.displayID == id }), display.frame == rect else { throw HelperFailure.unavailable }
            filter = SCContentFilter(display: display, excludingWindows: [])
            sourceRect = rect.offsetBy(dx: -display.frame.minX, dy: -display.frame.minY)
        } else if target["type"] as? String == "window" {
            guard let id = target["window_id"] as? UInt32, let pid = target["owner_pid"] as? Int32,
                  let window = content.windows.first(where: { $0.windowID == id && $0.owningApplication?.processID == pid }) else { throw HelperFailure.unavailable }
            // Each window gets a filter bound to its own WindowServer target.
            // ScreenCaptureKit captures the full window bounds, so no display crop applies here.
            filter = SCContentFilter(desktopIndependentWindow: window)
            sourceRect = nil
            if measure {
                FileHandle.standardError.write(Data("METRIC capture_window pid=\(getpid()) window_id=\(id) owner_pid=\(pid) on_screen=\(window.isOnScreen) width=\(window.frame.width) height=\(window.frame.height)\n".utf8))
            }
        } else {
            throw HelperFailure.invalid
        }
        let configuration = SCStreamConfiguration()
        configuration.width = Int(size.width); configuration.height = Int(size.height)
        // Normalize display-dependent pixels once on capture. The encoder's
        // transfer metadata must describe these same sRGB values end to end.
        configuration.colorSpaceName = CGColorSpace.sRGB
        configuration.pixelFormat = kCVPixelFormatType_32BGRA
        configuration.queueDepth = 3
        // Let the framework publish at its maximum source cadence. A numeric
        // floor delayed changed-frame delivery in the measured 120 Hz path [D266].
        configuration.minimumFrameInterval = .zero
        if let sourceRect { configuration.sourceRect = sourceRect }
        configuration.destinationRect = fittedContent(rect, size)
        configuration.scalesToFit = true; configuration.preservesAspectRatio = true
        configuration.showsCursor = true
        if measure {
            FileHandle.standardError.write(Data("METRIC source_capture_config pid=\(getpid()) fps=\(fps) queue_depth=\(configuration.queueDepth) interval_value=\(configuration.minimumFrameInterval.value) interval_scale=\(configuration.minimumFrameInterval.timescale) width=\(configuration.width) height=\(configuration.height)\n".utf8))
        }
        let candidate = SCStream(filter: filter, configuration: configuration, delegate: self)
        try candidate.addStreamOutput(self, type: .screen, sampleHandlerQueue: callbacks)
        // Enumeration and stream creation can finish after EOF/Stop. Never publish
        // that late stream into an already retired session.
        let cancelled = mailbox.withLock { if !stopped { stream = candidate }; return stopped }
        guard !cancelled else { return }
        trace("start_begin")
        do { try await candidate.startCapture() }
        catch {
            if measure {
                FileHandle.standardError.write(Data("METRIC capture_start_failed pid=\(getpid()) code=\((error as NSError).code)\n".utf8))
            }
            throw error
        }
        trace("start_end")
        let retired = mailbox.withLock { stopped }
        if retired { try await candidate.stopCapture() }
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        if measure {
            FileHandle.standardError.write(Data("METRIC capture_stopped pid=\(getpid()) code=\((error as NSError).code)\n".utf8))
        }
        if stop() {
            try? output(69, Data("{\"error\":\"Desktop capture is unavailable.\"}".utf8))
        }
    }

    func stream(_ stream: SCStream, didOutputSampleBuffer sample: CMSampleBuffer, of type: SCStreamOutputType) {
        let callback = measure ? nanos(mach_absolute_time()) : 0
        if measure && diagnosticCallbacks < 8 {
            diagnosticCallbacks += 1
            let entries = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: false) as? [[SCStreamFrameInfo: Any]]
            let status = entries?.first?[.status] as? Int ?? -1
            let pixel = CMSampleBufferGetImageBuffer(sample)
            FileHandle.standardError.write(Data("METRIC capture_callback pid=\(getpid()) index=\(diagnosticCallbacks) type=\(type.rawValue) ready=\(CMSampleBufferDataIsReady(sample)) status=\(status) has_pixel=\(pixel != nil) at_ns=\(callback)\n".utf8))
        }
        guard type == .screen, CMSampleBufferDataIsReady(sample),
              let attachments = CMSampleBufferGetSampleAttachmentsArray(sample, createIfNecessary: false) as? [[SCStreamFrameInfo: Any]],
              let info = attachments.first, info[.status] as? Int == SCFrameStatus.complete.rawValue,
              let pixel = CMSampleBufferGetImageBuffer(sample) else { return }
        let ticks = info[.displayTime] as? UInt64 ?? mach_absolute_time()
        receiveFrame(pixel, ticks: ticks, damage: info[.dirtyRects], callback: callback)
    }

    /// The framework validates readiness/status above. Real-buffer fixtures use
    /// this same handoff to exercise mailbox and hardware delivery without a GUI.
    func receiveFrame(_ pixel: CVPixelBuffer, ticks: UInt64, damage: Any?, callback: UInt64 = 0) {
        mailbox.lock()
        guard !stopped else { mailbox.unlock(); return }
        // Missing/unknown damage remains conservative. Empty sentinels do not
        // replace the retained picture, while content dominates a coalesced blink.
        let damageKind = captureFrameDamage(damage, initial: retained == nil)
        if damageKind != .unchanged {
            let mergedKind: CaptureFrameDamage = damageKind == .content || latest?.3 == .content ? .content : .caret
            latest = (pixel, ticks, callback, mergedKind)
        }
        let schedule = damageKind != .unchanged && !active
        if schedule { active = true }
        mailbox.unlock()
        if measure {
            let entries = (damage as? [Any])?.count ?? -1
            let geometry = captureFrameDamageDiagnostics(damage)
            FileHandle.standardError.write(Data("METRIC source_frame pid=\(getpid()) capture_ns=\(nanos(ticks)) callback_ns=\(callback) damaged=\(damageKind != .unchanged) damage_kind=\(damageKind.rawValue) damage_entries=\(entries) damage_rects=\(geometry)\n".utf8))
        }
        if schedule { encodingQueue.async { [weak self] in self?.drain() } }
    }

    private func drain() {
        var retryDroppedFrame = false
        do {
            try encoder.configure(width: Int(size.width), height: Int(size.height), hevc: hevc, fps: fps)
            while true {
                mailbox.lock()
                let frame = latest; latest = nil
                let repair = repairing; repairing = false
                let pressure = congested; congested = false
                let retired = stopped
                if let frame { retained = frame }
                let current = retained
                mailbox.unlock()
                if retired { break }
                if pressure { _ = bitrate.feedback(at:ProcessInfo.processInfo.systemUptime, congested:true) }
                let dequeued = measure ? nanos(mach_absolute_time()) : 0
                let deferHistoryUntilAfterPaint = !pixels.hasDeliveredHistory
                if deferHistoryUntilAfterPaint, current != nil {
                    // The initial picture is full content; keep its full BGRA history copy after keyframe output.
                    damageState.changed(at: ProcessInfo.processInfo.systemUptime, caret: false)
                } else if let frame, pixels.prepare(frame.0) {
                    if measure {
                        let bounds = pixels.damageBounds.map { "\($0.x),\($0.y),\($0.width),\($0.height)" } ?? "none"
                        FileHandle.standardError.write(Data("METRIC pixel_damage capture_ns=\(nanos(frame.1)) kind=\(pixels.damageKind) bounds=\(bounds) pixels=\(pixels.changedPixels) complete=\(pixels.damageBoundsComplete)\n".utf8))
                    }
                    // Framework dirty rectangles can cover an entire window even
                    // when only its insertion caret changed. The retained BGRA
                    // history is the authoritative area for scheduling sharp refresh.
                    damageState.changed(at: ProcessInfo.processInfo.systemUptime, caret: pixels.damageKind == .caret)
                }
                if repair { damageState.repair() }
                guard let current, let decision = damageState.next(at: ProcessInfo.processInfo.systemUptime) else { break }
                if frame == nil, !deferHistoryUntilAfterPaint { _ = pixels.prepare(current.0) }
                let prepared = measure ? nanos(mach_absolute_time()) : 0
                let budget = decision == .refresh ? min(bitrate.maximum * 4, bitrate.current * 4) : bitrate.current
                guard let body = try encoder.encodeSurface(current.0, ticks: current.1, force: decision.keyframe, bitrate: budget) else {
                    pixels.dropped()
                    retryDroppedFrame = damageState.encoderDropped(decision)
                    break
                }
                let outputBegan = measure ? nanos(mach_absolute_time()) : 0
                let began = ProcessInfo.processInfo.systemUptime
                try output(70, body)
                if measure {
                    // One write preserves frame identity across concurrent control
                    // receipts; all stamps use the same native monotonic clock.
                    let sent = nanos(mach_absolute_time())
                    FileHandle.standardError.write(Data("METRIC surface_delivery pid=\(getpid()) capture_ns=\(nanos(current.1)) callback_ns=\(current.2) dequeued_ns=\(dequeued) prepared_ns=\(prepared) output_begin_ns=\(outputBegan) output_end_ns=\(sent) fresh=\(frame != nil)\n".utf8))
                }
                if deferHistoryUntilAfterPaint {
                    pixels.seedAfterFirstPaint(current.0)
                } else {
                    pixels.delivered()
                }
                damageState.completed(delivered: true)
                _ = bitrate.feedback(at: ProcessInfo.processInfo.systemUptime, congested: ProcessInfo.processInfo.systemUptime - began > 0.1)
            }
            // Ordinary raw drops need no reference repair. Retry only an explicit
            // IDR/refresh that was dropped, including on a now-static window. Reuse
            // the existing one-shot timer at source cadence, never a hot loop.
            let deadline = retryDroppedFrame ? ProcessInfo.processInfo.systemUptime + 1 / Double(fps) : damageState.refreshDeadline
            if let deadline {
                if refresh == nil {
                    let timer = DispatchSource.makeTimerSource(queue: encodingQueue)
                    timer.setEventHandler { [weak self] in
                        guard let self else { return }
                        self.refresh?.schedule(deadline: .distantFuture)
                        self.drain()
                    }
                    refresh = timer; timer.resume()
                }
                refresh?.schedule(deadline: .now() + max(0, deadline - ProcessInfo.processInfo.systemUptime))
            }
        } catch {
            // Configuration/submission failure is terminal. Retire the pending
            // surface before reporting it, or drain would immediately retry the
            // same failed frame forever and saturate the control pipe.
            if stop() { try? output(69, Data("{\"error\":\"Desktop encoding is unavailable.\"}".utf8)) }
        }
        mailbox.lock(); active = false; let queued = latest != nil || repairing; let retired = stopped
        if queued && !retired { active = true }; mailbox.unlock()
        if queued && !retired { encodingQueue.async { [weak self] in self?.drain() } }
    }

    func congestion() { mailbox.lock(); congested = true; mailbox.unlock() }

    func repair() {
        mailbox.lock(); repairing = true; let schedule = !active && !stopped
        if schedule { active = true }; mailbox.unlock()
        if schedule { encodingQueue.async { [weak self] in self?.drain() } }
    }

    @discardableResult func stop() -> Bool {
        mailbox.lock()
        // Capture, encoder and Start completion can fail concurrently. Only the
        // caller that retires the live stream may publish its terminal error.
        guard !stopped else { mailbox.unlock(); return false }
        stopped = true; latest = nil; retained = nil; let captured = stream; stream = nil; mailbox.unlock()
        if let captured { Task { try? await captured.stopCapture() } }
        // Stop does not block the GUI behind an output write. The private process
        // owner closes the pipes and joins it at retirement; callbacks cannot restart.
        encodingQueue.async { [weak self] in self?.refresh?.cancel(); self?.refresh = nil; self?.pixels.reset(); self?.encoder.stop() }
        return true
    }
}
