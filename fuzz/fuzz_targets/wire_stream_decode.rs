//! Compares chunked raw/mux output to direct decoding, including valid concatenations.
#![no_main]
#![forbid(unsafe_code)]
use infraternal_protocol::{Frame, FrameStreamDecoder, MuxStreamDecoder, decode_frame, decode_muxed_frame, encode_frame_into, encode_muxed_frame_into};
use libfuzzer_sys::fuzz_target;

fn check(bytes: &[u8], schedule: &[u8], mux: bool) {
    let mut expected = Vec::new();
    let mut consumed = 0;
    let direct_error = loop {
        if consumed == bytes.len() { break None; }
        let result = if mux {
            decode_muxed_frame(&bytes[consumed..]).map(|d| (d.stream_id, d.frame, d.wire_len))
        } else {
            decode_frame(&bytes[consumed..]).map(|d| (0, d.frame, d.wire_len))
        };
        match result {
            Ok((id, frame, length)) => {
                let mut wire = Vec::new();
                if mux { encode_muxed_frame_into(id, &frame, &mut wire).unwrap(); }
                else { encode_frame_into(&frame, &mut wire).unwrap(); }
                expected.push(wire);
                consumed += length;
            }
            Err(error) => break Some(error),
        }
    };
    let mut raw = FrameStreamDecoder::new();
    let mut muxed = MuxStreamDecoder::new();
    let mut actual = Vec::new();
    let mut offset = 0;
    let mut index = 0;
    let mut stream_error = None;
    while offset < bytes.len() {
        // Always exercise empty feeds; selectors cover tiny and large refills.
        let selector = schedule.get(index % schedule.len().max(1)).copied().unwrap_or(1);
        let size = match selector % 4 { 0 => 1, 1 => 2, 2 => usize::from(selector) + 1, _ => 65536 };
        let end = bytes.len().min(offset + size);
        let result = if mux {
            muxed.feed(&[], |_, _| {}).unwrap();
            muxed.feed(&bytes[offset..end], |id, frame| {
                let mut wire = Vec::new();
                encode_muxed_frame_into(id, &frame, &mut wire).unwrap();
                actual.push(wire);
            })
        } else {
            raw.feed(&[], |_| {}).unwrap();
            raw.feed(&bytes[offset..end], |frame| {
                let mut wire = Vec::new();
                encode_frame_into(&frame, &mut wire).unwrap();
                actual.push(wire);
            })
        };
        if let Err(error) = result { stream_error = Some(error); break; }
        offset = end;
        index += 1;
    }
    assert_eq!(actual, expected);
    // Direct decoding reports Incomplete for an unfinished final frame; feed
    // intentionally retains it instead of treating a network fragment as error.
    let expected_error = direct_error.filter(|e| *e != infraternal_protocol::DecodeError::Incomplete);
    assert_eq!(stream_error, expected_error);
    if stream_error.is_none() {
        let buffered = if mux { muxed.buffered_len() } else { raw.buffered_len() };
        assert_eq!(buffered, bytes.len() - consumed);
    }
}

fuzz_target!(|data: &[u8]| {
    check(data, data, false);
    check(data, data, true);
    // Valid concatenations prevent mutations from spending all their time in
    // rejected prefixes. They also turn silent missing callbacks into crashes.
    let id = data.iter().take(4).fold(0_u32, |id, b| (id << 8) | u32::from(*b));
    let frames = [Frame::Close { code: 0, reason: "" }, Frame::Credit { bytes: id },
        Frame::Output { out_seq: u64::MAX, bytes: data }, Frame::Close { code: 1, reason: "end" }];
    for mux in [false, true] {
        let mut bytes = Vec::new();
        for frame in &frames {
            let mut wire = Vec::new();
            if mux { encode_muxed_frame_into(id, frame, &mut wire).unwrap(); }
            else { encode_frame_into(frame, &mut wire).unwrap(); }
            bytes.extend_from_slice(&wire);
        }
        check(&bytes, data, mux);
    }
});
