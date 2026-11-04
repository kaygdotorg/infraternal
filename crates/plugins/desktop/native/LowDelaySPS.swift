/// Role: constrain bounded progressive H.264 capture SPS values while preserving valid no-reorder bytes exactly (#146).
/// A browser decoder may hold back several pictures before showing one unless the stream's SPS (the
/// sequence parameter set, a small header NAL unit) says it never reorders. The hardware encoder
/// does not always say so, so this file rewrites that one header field. Everything else in the SPS
/// is copied bit for bit.
/// This is not a general media transformer: callers must have disabled encoder frame reordering.
import Foundation

/// Thrown when an SPS is malformed, too large or uses a feature this encoder never produces.
enum SPSFailure: Error { case invalid }

/// Reads bits, most significant first, from an SPS payload with emulation-prevention bytes removed.
private struct SPSBits {
    /// The payload being read.
    let bytes: [UInt8]
    /// Index of the next unread bit.
    var position = 0
    /// Reads `count` bits (0 to 32) as a number. Throws `SPSFailure.invalid` past the end.
    mutating func read(_ count: Int = 1) throws -> UInt32 {
        guard count >= 0, count <= 32, position + count <= bytes.count * 8 else { throw SPSFailure.invalid }
        var value: UInt32 = 0
        for _ in 0..<count {
            value = (value << 1) | UInt32((bytes[position / 8] >> (7 - position % 8)) & 1)
            position += 1
        }
        return value
    }
    /// Reads an unsigned Exp-Golomb number, the variable-length code H.264 uses for most fields.
    /// Throws `SPSFailure.invalid` for codes longer than 31 bits or past the end.
    mutating func ue() throws -> UInt32 {
        var zeros = 0
        while try read() == 0 {
            zeros += 1
            guard zeros < 31 else { throw SPSFailure.invalid }
        }
        return ((UInt32(1) << zeros) - 1) + (try read(zeros))
    }
    /// Skips over an HRD (hypothetical decoder timing) block, validating that it fits.
    mutating func hrd() throws {
        let entries = try ue()
        guard entries <= 31 else { throw SPSFailure.invalid }
        _ = try read(8)
        for _ in 0...entries { _ = try ue(); _ = try ue(); _ = try read() }
        _ = try read(20)
    }
}

/// Builds the rewritten SPS payload bit by bit, most significant first.
private struct SPSWriter {
    /// The bits written so far, packed.
    var bytes: [UInt8] = []
    /// Number of bits written.
    var count = 0
    /// Appends the lowest bit of `value`.
    mutating func bit(_ value: UInt32) {
        if count % 8 == 0 { bytes.append(0) }
        bytes[bytes.count - 1] |= UInt8(value & 1) << (7 - count % 8)
        count += 1
    }
    /// Appends `value` as an unsigned Exp-Golomb number.
    mutating func ue(_ value: UInt32) {
        let code = value + 1
        let width = 32 - code.leadingZeroBitCount
        for _ in 1..<width { bit(0) }
        for shift in (0..<width).reversed() { bit(code >> shift) }
    }
    /// Appends the first `end` bits of `bytes` unchanged.
    mutating func copy(_ bytes: [UInt8], through end: Int) {
        for position in 0..<end { bit(UInt32(bytes[position / 8] >> (7 - position % 8))) }
    }
}

/// Rebuild one bounded SPS NAL, preserving profile, dimensions, VUI metadata and all picture data.
/// Refuse unsupported encoder output instead of announcing an untrue one-buffer invariant.
/// Returns an SPS NAL unit that declares no picture reordering.
///
/// `nal` is one complete SPS NAL unit without a start code (header byte first, at most 1024
/// bytes). It is returned untouched when it already states zero reordered frames. Otherwise the
/// VUI bitstream-restriction fields are rewritten (or added) with zero reordering and a buffer
/// big enough for the reference frames, then byte-escaped again.
///
/// Only profiles 66, 77 and 100 are accepted. Throws `SPSFailure.invalid` for anything else or
/// for a malformed SPS.
func lowDelaySPS(_ nal: Data) throws -> Data {
    // Bound the borrowed input before making the parser's owned copy.
    guard nal.count >= 5, nal.count <= 1024 else { throw SPSFailure.invalid }
    let source = [UInt8](nal)
    guard source[0] & 0x80 == 0, source[0] & 0x60 != 0, source[0] & 0x1f == 7 else { throw SPSFailure.invalid }
    var rbsp: [UInt8] = []
    var zeros = 0
    var index = 1
    while index < source.count {
        let byte = source[index]
        if zeros == 2 {
            if byte == 3 {
                guard index + 1 < source.count, source[index + 1] <= 3 else { throw SPSFailure.invalid }
                index += 1; zeros = 0; continue
            }
            guard byte > 2 else { throw SPSFailure.invalid }
        }
        rbsp.append(byte); zeros = byte == 0 ? zeros + 1 : 0; index += 1
    }
    var reader = SPSBits(bytes: rbsp)
    let profile = try reader.read(8)
    guard try reader.read(8) & 3 == 0 else { throw SPSFailure.invalid } // Reserved constraint bits stay zero.
    _ = try reader.read(8)
    guard try reader.ue() <= 31 else { throw SPSFailure.invalid }
    guard [66,77,100].contains(profile) else { throw SPSFailure.invalid }
    if profile == 100 {
        guard try reader.ue() == 1, try reader.ue() == 0, try reader.ue() == 0 else { throw SPSFailure.invalid }
        _ = try reader.read()
        guard try reader.read() == 0 else { throw SPSFailure.invalid } // No custom scaling lists from this encoder.
    }
    guard try reader.ue() <= 12 else { throw SPSFailure.invalid }
    let order = try reader.ue()
    if order == 0 { guard try reader.ue() <= 12 else { throw SPSFailure.invalid } }
    else if order != 2 { throw SPSFailure.invalid }
    let maxNumRefFrames = try reader.ue()
    guard maxNumRefFrames <= 16 else { throw SPSFailure.invalid }
    _ = try reader.read()
    guard try reader.ue() <= 255, try reader.ue() <= 255, try reader.read() == 1 else { throw SPSFailure.invalid }
    _ = try reader.read()
    if try reader.read() == 1 { for _ in 0..<4 { _ = try reader.ue() } }
    let vuiFlag = reader.position
    let hasVUI = try reader.read() == 1
    if hasVUI {
        if try reader.read() == 1 { if try reader.read(8) == 255 { _ = try reader.read(32) } }
        if try reader.read() == 1 { _ = try reader.read() }
        if try reader.read() == 1 {
            _ = try reader.read(4)
            if try reader.read() == 1 { _ = try reader.read(24) }
        }
        if try reader.read() == 1 { _ = try reader.ue(); _ = try reader.ue() }
        if try reader.read() == 1 { _ = try reader.read(32); _ = try reader.read(32); _ = try reader.read() }
        let nalHRD = try reader.read() == 1
        if nalHRD { try reader.hrd() }
        let vclHRD = try reader.read() == 1
        if vclHRD { try reader.hrd() }
        if nalHRD || vclHRD { _ = try reader.read() }
        _ = try reader.read()
    }
    let restrictionFlag = reader.position
    var retained: [UInt32] = [1,2,1,16,16]
    var sourceReorderFrames: UInt32?
    var sourceFrameBuffer: UInt32?
    if hasVUI, try reader.read() == 1 {
        retained = [try reader.read(),try reader.ue(),try reader.ue(),try reader.ue(),try reader.ue()]
        sourceReorderFrames = try reader.ue()
        sourceFrameBuffer = try reader.ue()
        guard let reorder = sourceReorderFrames, let buffer = sourceFrameBuffer,
              reorder <= 16, buffer <= 16, reorder <= buffer, buffer >= maxNumRefFrames else { throw SPSFailure.invalid }
    }
    guard try reader.read() == 1 else { throw SPSFailure.invalid }
    // rbsp_stop_one_bit must be followed only by byte-alignment zeros, never hidden syntax.
    guard reader.bytes.count * 8 - reader.position < 8 else { throw SPSFailure.invalid }
    while reader.position < reader.bytes.count * 8 { guard try reader.read() == 0 else { throw SPSFailure.invalid } }
    // A valid explicit no-reorder restriction already states the desired decoder contract; keep every source bit.
    if sourceReorderFrames == 0 { return nal }
    var writer = SPSWriter()
    if hasVUI { writer.copy(rbsp,through:restrictionFlag) }
    else {
        writer.copy(rbsp,through:vuiFlag); writer.bit(1)
        for _ in 0..<8 { writer.bit(0) }
    }
    writer.bit(1); writer.bit(retained[0])
    for value in retained.dropFirst() { writer.ue(value) }
    let decoderBuffer = max(1, max(maxNumRefFrames, sourceFrameBuffer ?? 0))
    writer.ue(0); writer.ue(decoderBuffer); writer.bit(1)
    while writer.count % 8 != 0 { writer.bit(0) }
    var result = Data([source[0]])
    zeros = 0
    for byte in writer.bytes {
        if zeros == 2, byte <= 3 { result.append(3); zeros = 0 }
        result.append(byte); zeros = byte == 0 ? zeros + 1 : 0
    }
    guard result.count <= 1024 else { throw SPSFailure.invalid }
    return result
}

/// One encoder-owned cache; callbacks are serialized by the one-in-flight submission invariant.
/// Preserve the original in standard SEI so each viewer can select metadata without encoding again.
/// Turns parameter-set NAL units from the encoder into Annex B packets, rewriting each SPS once.
///
/// The cache keeps the eight most recent distinct SPS values. Use from one thread. `reset` when
/// the encoder session ends.
final class LowDelayParameterSets {
    /// Cached pairs of (original SPS, finished packet).
    private var entries: [(Data, Data)] = []
    /// How many SPS values have been rewritten, counting each distinct one once; useful in tests.
    private(set) var rewrites = 0
    /// Returns the bytes to send for one parameter-set NAL unit (no start code).
    ///
    /// Non-SPS NAL units just get a 00 00 00 01 start code. An SPS goes through `lowDelaySPS`; if it
    /// changed, a standard SEI message holding the original SPS (marked `infraternal-sps1`) follows
    /// it, so a viewer can still recover the encoder's exact original. Throws `SPSFailure.invalid`
    /// for empty, oversized or unsupported input.
    func packet(_ nal: Data) throws -> Data {
        guard nal.count > 0, nal.count <= 1024 else { throw SPSFailure.invalid }
        if nal[nal.startIndex] & 31 != 7 { return Data([0,0,0,1]) + nal }
        if let entry = entries.first(where: { $0.0 == nal }) { return entry.1 }
        let restricted = try lowDelaySPS(nal)
        var packet = Data([0,0,0,1]) + restricted
        if restricted != nal {
            let payload = Data("infraternal-sps1".utf8) + nal
            var rbsp = Data([5]); var size = payload.count
            while size >= 255 { rbsp.append(255); size -= 255 }
            rbsp.append(UInt8(size)); rbsp.append(payload); rbsp.append(0x80)
            packet.append(contentsOf: [0,0,0,1,6])
            var zeros = 0
            for byte in rbsp {
                if zeros == 2 && byte <= 3 { packet.append(3); zeros = 0 }
                packet.append(byte); zeros = byte == 0 ? zeros + 1 : 0
            }
        }
        if entries.count == 8 { entries.removeFirst() }
        entries.append((nal,packet)); rewrites += 1
        return packet
    }
    /// Empties the cache.
    func reset() { entries.removeAll(keepingCapacity: true) }
}
