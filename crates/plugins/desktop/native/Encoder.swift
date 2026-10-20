/// Role: hardware VideoToolbox encoding from owned BGRA or retained IOSurface buffers [D200 V2,D204].
import CoreMedia
import CoreVideo
import Foundation
import IOSurface
import VideoToolbox

func nanos(_ ticks: UInt64) -> UInt64 {
    var info = mach_timebase_info_data_t(); mach_timebase_info(&info)
    return UInt64(Double(ticks) * Double(info.numer) / Double(info.denom))
}

private func annexB(_ sample: CMSampleBuffer, parameters: LowDelayParameterSets) throws -> (Data, Bool) {
    guard let block = CMSampleBufferGetDataBuffer(sample), let format = CMSampleBufferGetFormatDescription(sample) else { throw HelperFailure.unavailable }
    let size = CMBlockBufferGetDataLength(block)
    guard size > 0, size <= 4 * 1024 * 1024 - 4096 else { throw HelperFailure.invalid }
    var avc = Data(count:size)
    let status = avc.withUnsafeMutableBytes { ptr in CMBlockBufferCopyDataBytes(block, atOffset:0,dataLength:size,destination:ptr.baseAddress!) }
    guard status == noErr else { throw HelperFailure.unavailable }
    let attachments = CMSampleBufferGetSampleAttachmentsArray(sample,createIfNecessary:false) as? [[CFString: Any]]
    let key = attachments?.first?[kCMSampleAttachmentKey_NotSync] as? Bool != true
    var result = Data()
    let startCode = Data([0,0,0,1])
    var nalLength: Int32 = 0
    var parameterCount = 0
    var pointer: UnsafePointer<UInt8>?
    var parameterSize = 0
    let hevc = CMFormatDescriptionGetMediaSubType(format) == kCMVideoCodecType_HEVC
    func parameter(_ index: Int, count: UnsafeMutablePointer<Int>?, length: UnsafeMutablePointer<Int32>?) -> OSStatus {
        if hevc { return CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(format, parameterSetIndex:index, parameterSetPointerOut:&pointer, parameterSetSizeOut:&parameterSize, parameterSetCountOut:count, nalUnitHeaderLengthOut:length) }
        return CMVideoFormatDescriptionGetH264ParameterSetAtIndex(format, parameterSetIndex:index, parameterSetPointerOut:&pointer, parameterSetSizeOut:&parameterSize, parameterSetCountOut:count, nalUnitHeaderLengthOut:length)
    }
    guard parameter(0, count:&parameterCount, length:&nalLength) == noErr, nalLength == 4 else { throw HelperFailure.unavailable }
    if key {
        guard parameterCount > 0, parameterCount <= 8 else { throw HelperFailure.invalid }
        for index in 0..<parameterCount {
            guard parameter(index, count:nil, length:nil) == noErr,
                  let pointer, parameterSize > 0, parameterSize <= 1024 else { throw HelperFailure.unavailable }
            let nal = Data(bytes:pointer,count:parameterSize)
            do { result.append(try parameters.packet(nal)) }
            catch {
                // Parameter bytes describe the codec, never desktop picture data.
                let prefix = nal.prefix(64).map { String(format:"%02x",$0) }.joined()
                fputs("ENCODER parameter_rejected bytes=\(nal.count) prefix=\(prefix)\n",stderr)
                throw error
            }
        }
    }
    var offset = 0
    while offset < avc.count {
        guard avc.count-offset >= 4 else { throw HelperFailure.invalid }
        let count = avc[offset..<offset+4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        offset += 4
        guard count > 0, Int(count) <= avc.count-offset else { throw HelperFailure.invalid }
        result.append(startCode); result.append(avc[offset..<offset+Int(count)]); offset += Int(count)
    }
    // Metadata and parameter sets share the same frozen access-unit budget as pictures.
    guard result.count <= 4 * 1024 * 1024 - 42 else { throw HelperFailure.invalid }
    return (result,key)
}

final class EncodeResult {
    let done = DispatchSemaphore(value:0)
    let parameters: LowDelayParameterSets
    let measure: Bool
    var callbackBegan: UInt64 = 0
    var callbackFinished: UInt64 = 0
    init(parameters: LowDelayParameterSets, measure: Bool = false) {
        self.parameters = parameters; self.measure = measure
    }
    var payload: Data?
    var dropped = false
    func completedPayload(timeout: DispatchTime) throws -> Data? {
        guard done.wait(timeout: timeout) == .success else {
            fputs("ENCODER callback_timeout\n",stderr); throw HelperFailure.unavailable
        }
        // A successful dropped-frame callback owns no sample. It still completes
        // the submission and releases its input; it does not invalidate the session.
        if dropped { return nil }
        guard let payload else { fputs("ENCODER payload_missing\n",stderr); throw HelperFailure.unavailable }
        return payload
    }
}

let encodedCallback: VTCompressionOutputCallback = { _, context, status, flags, sample in
    guard let context else { return }
    // The submitter retains this object until completion or invalidation.
    let result = Unmanaged<EncodeResult>.fromOpaque(context).takeUnretainedValue()
    if result.measure { result.callbackBegan = mach_absolute_time() }
    defer {
        if result.measure { result.callbackFinished = mach_absolute_time() }
        // The semaphore publishes callback fields and output together. These
        // stamps never assume that an asynchronous submit returned first.
        result.done.signal()
    }
    guard status == noErr else { fputs("ENCODER callback_status=\(status)\n",stderr); return }
    if flags.contains(.frameDropped) { result.dropped = true; return }
    guard let sample else { fputs("ENCODER callback_no_sample flags=\(flags.rawValue)\n",stderr); return }
    guard CMSampleBufferDataIsReady(sample) else { fputs("ENCODER callback_not_ready\n",stderr); return }
    do {
        let (bytes,key) = try annexB(sample, parameters:result.parameters)
        result.payload = Data([key ? 1 : 0]) + bytes
    } catch { fputs("ENCODER conversion_error=\(error)\n",stderr) }
}

final class Encoder {
    private let measure = ProcessInfo.processInfo.environment["INFRATERNAL_DESKTOP_MEASURE"] != nil
    private let parameters = LowDelayParameterSets()
    private var session: VTCompressionSession?
    private(set) var width = 0
    private(set) var height = 0

    private var codec: CMVideoCodecType = kCMVideoCodecType_H264
    private var frameRate = 120
    private var lastBitrate = 0
    private var adaptation = AdaptiveBitrate(maximum: 500_000)

    func configure(width: Int, height: Int, hevc: Bool = false, fps: Int = 120) throws {
        guard width >= 2, height >= 2, width <= 4096, height <= 4096, width*height <= 4*1024*1024 else { throw HelperFailure.invalid }
        guard (1...240).contains(fps) else { throw HelperFailure.invalid }
        let requestedCodec = hevc ? kCMVideoCodecType_HEVC : kCMVideoCodecType_H264
        if session != nil && self.width == width && self.height == height && codec == requestedCodec && frameRate == fps { return }
        stop(); self.width = width; self.height = height; codec = requestedCodec; frameRate = fps
        adaptation = AdaptiveBitrate(maximum: max(500_000, width * height * 3))
        let spec = [kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder as String:true,
                    kVTVideoEncoderSpecification_EnableLowLatencyRateControl as String:true] as CFDictionary
        let creation = VTCompressionSessionCreate(allocator:kCFAllocatorDefault,width:Int32(width),height:Int32(height),codecType:codec,
            encoderSpecification:spec,imageBufferAttributes:nil,compressedDataAllocator:nil,outputCallback:encodedCallback,refcon:nil,compressionSessionOut:&session)
        fputs("ENCODER creation_status=\(creation)\n",stderr)
        guard creation == noErr, let session else { throw HelperFailure.unavailable }
        do {
            try set(kVTCompressionPropertyKey_RealTime,kCFBooleanTrue)
            try set(kVTCompressionPropertyKey_AllowFrameReordering,kCFBooleanFalse)
            // Capture normalizes the display into sRGB. Preserve its transfer
            // curve instead of asking browsers to reinterpret it as video gamma.
            try set(kVTCompressionPropertyKey_ColorPrimaries,kCVImageBufferColorPrimaries_ITU_R_709_2)
            try set(kVTCompressionPropertyKey_TransferFunction,kCVImageBufferTransferFunction_sRGB)
            try set(kVTCompressionPropertyKey_YCbCrMatrix,kCVImageBufferYCbCrMatrix_ITU_R_709_2)
            // Only startup, repair, resize and the settled sharp refresh require IDRs.
            // Periodic keyframes waste bandwidth on a static desktop.
            try set(kVTCompressionPropertyKey_MaxKeyFrameInterval,NSNumber(value:Int32.max))
            try set(kVTCompressionPropertyKey_ExpectedFrameRate,NSNumber(value:fps))
            try set(kVTCompressionPropertyKey_AverageBitRate,NSNumber(value:max(500_000,width*height*3)))
            guard VTCompressionSessionPrepareToEncodeFrames(session) == noErr else { throw HelperFailure.unavailable }
            let property = UnsafeMutablePointer<Unmanaged<CFTypeRef>?>.allocate(capacity:1)
            property.initialize(to:nil)
            defer { property.deinitialize(count:1); property.deallocate() }
            let status = VTSessionCopyProperty(session, key:kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder, allocator:nil, valueOut:property)
            let reportedHardware = property.pointee?.takeRetainedValue() as? Bool == true
            // Low-latency sessions may not expose this optional property. Creation
            // with RequireHardwareAcceleratedVideoEncoder already fails if hardware
            // is unavailable. Accept only that specific unsupported-property error;
            // an explicit false or any other query error remains a refusal.
            let hardware = status == noErr ? reportedHardware : status == kVTPropertyNotSupportedErr
            let proof = status == noErr ? "property" : "required_spec"
            fputs("METRIC hardware=\(hardware) hardware_status=\(status) hardware_proof=\(proof) fps=\(fps) codec=\(hevc ? "hevc" : "h264")\n",stderr)
            guard hardware else { throw HelperFailure.unavailable }
        } catch { stop(); throw error }
    }

    private func set(_ key: CFString, _ value: CFTypeRef) throws {
        guard let session else { throw HelperFailure.unavailable }
        let status = VTSessionSetProperty(session,key:key,value:value)
        if status != noErr { fputs("ENCODER property=\(key) status=\(status)\n",stderr); throw HelperFailure.unavailable }
    }

    private var pixel: CVPixelBuffer?
    func encode(_ command: [String: Any], pixels: Data) throws -> Data {
        guard let ticks = command["capture_ticks"] as? UInt64, let sharp = command["sharp"] as? Bool,
              let w = command["width"] as? Int, let h = command["height"] as? Int,
              w == width, h == height, pixels.count == w*h*4, session != nil else { throw HelperFailure.invalid }
        if pixel == nil || CVPixelBufferGetWidth(pixel!) != w || CVPixelBufferGetHeight(pixel!) != h {
            let attrs = [kCVPixelBufferIOSurfacePropertiesKey as String: [:]] as CFDictionary
            guard CVPixelBufferCreate(kCFAllocatorDefault,w,h,kCVPixelFormatType_32BGRA,attrs,&pixel) == kCVReturnSuccess else { throw HelperFailure.unavailable }
        }
        guard let pixel, CVPixelBufferLockBaseAddress(pixel,[]) == kCVReturnSuccess else { throw HelperFailure.unavailable }
        guard let base = CVPixelBufferGetBaseAddress(pixel) else { CVPixelBufferUnlockBaseAddress(pixel,[]); throw HelperFailure.unavailable }
        let stride = CVPixelBufferGetBytesPerRow(pixel)
        pixels.withUnsafeBytes { source in
            for row in 0..<h { base.advanced(by:row*stride).copyMemory(from:source.baseAddress!.advanced(by:row*w*4),byteCount:w*4) }
        }
        CVPixelBufferUnlockBaseAddress(pixel,[])
        let budget = sharp ? min(adaptation.maximum * 4, adaptation.current * 4) : adaptation.current
        // The owned-pixel request owes its caller one bounded reply. A rate-control
        // drop gets one forced-keyframe retry with the same captured pixels/timestamp;
        // repeated drops refuse the request rather than spinning or extending its deadline.
        let first = try encodeSurface(pixel, ticks:ticks, force:sharp, bitrate:budget)
        let recovered = try first ?? encodeSurface(pixel, ticks:ticks, force:true, bitrate:budget)
        guard let body = recovered else { throw HelperFailure.unavailable }
        _ = adaptation.feedback(at:ProcessInfo.processInfo.systemUptime, congested:false)
        return body
    }

    // The caller retains the framework buffer until callback completion. There is
    // no IOSurface ID lookup, base-address lock, pixel copy or cross-process handoff.
    func encodeSurface(_ pixel: CVPixelBuffer, ticks: UInt64, force: Bool, bitrate: Int) throws -> Data? {
        guard CVPixelBufferGetWidth(pixel) == width, CVPixelBufferGetHeight(pixel) == height, let session else { throw HelperFailure.invalid }
        let begin = mach_absolute_time()
        let rateChanged = lastBitrate != bitrate
        // A settled refresh gets a larger intra-frame budget; restore the motion
        // budget on the next submission instead of queueing quality work.
        if lastBitrate != bitrate {
            try set(kVTCompressionPropertyKey_AverageBitRate,NSNumber(value:bitrate)); lastBitrate = bitrate
        }
        let configured = measure ? mach_absolute_time() : 0
        let result = EncodeResult(parameters:parameters, measure:measure)
        // The C callback owns only an unretained pointer. ARC may otherwise end
        // this local's lifetime after the throwing wait, before catch invalidates
        // a timed-out session. Keep it alive through every completion/error path.
        defer { withExtendedLifetime(result) {} }
        let pointer = Unmanaged.passUnretained(result).toOpaque()
        // One reusable input buffer is in flight; it is not overwritten until completion.
        let options = force ? [kVTEncodeFrameOptionKey_ForceKeyFrame as String:true] as CFDictionary : nil
        let time = CMTime(value:Int64(nanos(mach_absolute_time())),timescale:1_000_000_000)
        let submitting = measure ? mach_absolute_time() : 0
        let status = VTCompressionSessionEncodeFrame(session,imageBuffer:pixel,presentationTimeStamp:time,duration:CMTime(value:1,timescale:Int32(frameRate)),frameProperties:options,sourceFrameRefcon:pointer,infoFlagsOut:nil)
        let submitted = measure ? mach_absolute_time() : 0
        guard status == noErr else { fputs("ENCODER submit_status=\(status)\n",stderr); stop(); throw HelperFailure.unavailable }
        let payload: Data
        do {
            guard let completed = try result.completedPayload(timeout:.now()+2) else {
                if measure { fputs("METRIC encoder_drop=1 drop_ns=\(nanos(mach_absolute_time()-begin)) requested_keyframe=\(force ? 1 : 0) bitrate=\(bitrate) width=\(width) height=\(height) capture_ns=\(nanos(ticks))\n",stderr) }
                return nil
            }
            payload = completed
        } catch {
            // Invalidate synchronizes callbacks before result and source are released.
            stop(); throw error
        }
        if measure {
            let finished = mach_absolute_time()
            // Submit and callback can overlap. Configuration plus callback delay
            // plus conversion describe the critical path; submit is separate.
            FileHandle.standardError.write(Data("METRIC encode_ns=\(nanos(finished-begin)) encode_finished_ns=\(nanos(finished)) encode_config_ns=\(nanos(configured-begin)) encode_submit_ns=\(nanos(submitted-submitting)) encode_callback_delay_ns=\(nanos(result.callbackBegan-submitting)) encode_conversion_ns=\(nanos(result.callbackFinished-result.callbackBegan)) encode_return_ns=\(nanos(finished-max(submitted,result.callbackFinished))) encode_rate_changed=\(rateChanged ? 1 : 0) requested_keyframe=\(force ? 1 : 0) encoded_keyframe=\(payload.first == 1 ? 1 : 0) bitrate=\(bitrate) width=\(width) height=\(height) bytes=\(payload.count-1) capture_ns=\(nanos(ticks)) codec=\(codec == kCMVideoCodecType_HEVC ? "hevc" : "h264")\n".utf8))
        }
        var stamp = nanos(ticks).bigEndian
        return withUnsafeBytes(of:&stamp) { Data($0) } + payload
    }

    func congestion() { _ = adaptation.feedback(at:ProcessInfo.processInfo.systemUptime, congested:true) }

    func stop() {
        if let session { VTCompressionSessionInvalidate(session) }
        session = nil; pixel = nil; lastBitrate = 0; parameters.reset()
    }
}
