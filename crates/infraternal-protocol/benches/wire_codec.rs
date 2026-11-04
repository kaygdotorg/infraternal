//! Criterion baselines for the terminal keystroke and PTY-output hot paths.

use std::{hint::black_box, time::Duration};

use criterion::{Criterion, criterion_group, criterion_main};
use infraternal_protocol::{
    DecodeError, Frame, MuxStreamDecoder, decode_frame, decode_muxed_frame, encode_frame_into,
    encode_muxed_frame_into,
};

/// Benchmarks encode and decode of the two hot frames, a 1-byte keystroke (`Input`) and 64 bytes
/// of PTY output (`Output`), plus the multiplexed decoder for the smallest and largest stream ids.
/// The `decode` cases do the minimum work needed to read the payload; `decode_full` builds the
/// complete frame.
fn wire_codec(c: &mut Criterion) {
    let keystroke = *b"k";
    let keystroke_frame = Frame::Input {
        in_seq: 42,
        bytes: &keystroke,
    };
    let pty_output = [b'x'; 64];
    let output_frame = Frame::Output {
        out_seq: 65_535,
        bytes: &pty_output,
    };

    let mut encoded_keystroke = Vec::with_capacity(32);
    if let Err(error) = encode_frame_into(&keystroke_frame, &mut encoded_keystroke) {
        panic!("keystroke fixture encoding failed: {error:?}");
    }
    let mut encoded_output = Vec::with_capacity(96);
    if let Err(error) = encode_frame_into(&output_frame, &mut encoded_output) {
        panic!("PTY output fixture encoding failed: {error:?}");
    }

    c.bench_function("wire/encode/input_1b", |b| {
        let mut buffer = Vec::with_capacity(32);
        b.iter(|| {
            let written = match encode_frame_into(black_box(&keystroke_frame), &mut buffer) {
                Ok(length) => length,
                Err(error) => panic!("encode failed: {error:?}"),
            };
            black_box(written);
        });
    });
    c.bench_function("wire/decode/input_1b", |b| {
        b.iter(|| black_box(decode_summary(black_box(&encoded_keystroke))));
    });
    c.bench_function("wire/decode_full/input_1b", |b| {
        b.iter(|| black_box(decode_frame(black_box(&encoded_keystroke))));
    });
    c.bench_function("wire/encode/output_64b", |b| {
        let mut buffer = Vec::with_capacity(96);
        b.iter(|| {
            let written = match encode_frame_into(black_box(&output_frame), &mut buffer) {
                Ok(length) => length,
                Err(error) => panic!("encode failed: {error:?}"),
            };
            black_box(written);
        });
    });
    c.bench_function("wire/decode/output_64b", |b| {
        b.iter(|| black_box(decode_summary(black_box(&encoded_output))));
    });
    c.bench_function("wire/decode_full/output_64b", |b| {
        b.iter(|| black_box(decode_frame(black_box(&encoded_output))));
    });
    for id in [0, u32::MAX] {
        let mut mux = Vec::new();
        if let Err(error) = encode_muxed_frame_into(id, &output_frame, &mut mux) {
            panic!("mux fixture failed: {error:?}");
        }
        c.bench_function(&format!("wire/mux/direct/{id}"), |b| {
            b.iter(|| black_box(decode_muxed_frame(black_box(&mux))));
        });
        c.bench_function(&format!("wire/mux/split_header/{id}"), |b| {
            // Reuse capacity as a live connection does after its first frame.
            let mut decoder = MuxStreamDecoder::new();
            b.iter(|| {
                for chunk in [&mux[..1], &mux[1..]] {
                    if let Err(error) = decoder.feed(black_box(chunk), |stream, frame| {
                        black_box((stream, frame));
                    }) {
                        panic!("mux decode failed: {error:?}");
                    }
                }
            });
        });
    }
}

/// Decodes a terminal data frame and returns just its sequence number and payload length.
/// Only `Input` and `Output` frames are expected here, since those are all the fixtures hold.
fn decode_summary(input: &[u8]) -> Result<(u64, usize), DecodeError> {
    let decoded = decode_frame(input)?;
    match decoded.frame {
        Frame::Input { in_seq, bytes } => Ok((in_seq, bytes.len())),
        Frame::Output { out_seq, bytes } => Ok((out_seq, bytes.len())),
        _ => unreachable!("benchmark fixtures contain only terminal data frames"),
    }
}

/// Short Criterion settings: 20 samples with brief warm-up and measurement, enough to compare
/// runs of these very fast operations without a long wait.
fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(200))
        .measurement_time(Duration::from_millis(500))
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = wire_codec
}
criterion_main!(benches);
