//! Bounded numeric stage receipts for diagnostic shared-host builds only [D270].
//!
//! No terminal bytes, environment or paths enter these records. Diagnostics
//! change scheduling and are never performance admission evidence.
use std::{
    cell::RefCell,
    io::{self, Write},
};

const LIMIT: usize = 65_536;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub(crate) enum Stage {
    PeerRead = 1,
    InputQueued = 2,
    PtyWriteStart = 3,
    PtyWriteDone = 4,
    PtyRead = 5,
    ParseDone = 6,
    FrameBuilt = 7,
    SocketWriteStart = 8,
    SocketWriteDone = 9,
    SnapshotStart = 10,
    SnapshotDone = 11,
    ResizeStart = 12,
    ResizeDone = 13,
    FrameBuildStart = 14,
}
#[derive(Clone, Copy)]
struct Record {
    ns: u64,
    session: [u8; 16],
    offset: u64,
    fd: i32,
    bytes: usize,
    // Encoded queue bytes for FrameBuilt/SocketWriteDone; writer identity
    // for InputQueued/PtyWriteDone. Other stages set this to zero.
    extra: usize,
    stage: Stage,
}
#[derive(Default)]
struct Trace {
    enabled: bool,
    context: Option<([u8; 16], i32)>,
    records: Vec<Record>,
    dropped: u64,
}
impl Trace {
    fn push(&mut self, record: Record) {
        if self.records.len() < LIMIT {
            self.records.push(record);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
    }
    fn dump(&mut self, writer: &mut impl Write) -> io::Result<()> {
        writeln!(
            writer,
            "{{\"kind\":\"stages\",\"records\":{},\"dropped\":{}}}",
            self.records.len(),
            self.dropped
        )?;
        for r in &self.records {
            writeln!(
                writer,
                "{{\"kind\":\"stage\",\"ns\":{},\"session\":{},\"offset\":{},\"fd\":{},\"bytes\":{},\"stage\":{},\"extra\":{}}}",
                r.ns,
                u128::from_be_bytes(r.session),
                r.offset,
                r.fd,
                r.bytes,
                r.stage as u8,
                r.extra
            )?;
        }
        self.records.clear();
        self.dropped = 0;
        Ok(())
    }
}
thread_local! { static TRACE: RefCell<Trace> = const { RefCell::new(Trace { enabled: false, context: None, records: Vec::new(), dropped: 0 }) }; }

/// Publish the private diagnostic format before any PTY is admitted. A driver
/// must validate this header before requesting the diagnostic-only signal.
pub(crate) fn initialize(file: Option<&mut std::fs::File>) -> io::Result<()> {
    enable(file.is_some())?;
    if let Some(file) = file {
        writeln!(
            file,
            "{{\"kind\":\"stage-format\",\"version\":1,\"capacity\":{LIMIT},\"record_bytes\":{}}}",
            std::mem::size_of::<Record>()
        )?;
    }
    Ok(())
}

pub(crate) fn enable(enabled: bool) -> io::Result<()> {
    TRACE.with_borrow_mut(|trace| {
        if enabled {
            trace
                .records
                .try_reserve_exact(LIMIT)
                .map_err(io::Error::other)?;
        }
        if !enabled {
            trace.records = Vec::new();
            trace.context = None;
            trace.dropped = 0;
        }
        trace.enabled = enabled;
        Ok(())
    })
}
/// The reactor sets this before every session visit. Credit is emitted inside
/// `Inputs::advance`, where each partial write's actual writer is authoritative.
pub(crate) fn context(session: [u8; 16], fd: i32) {
    TRACE.with_borrow_mut(|trace| trace.context = trace.enabled.then_some((session, fd)));
}
pub(crate) fn credit(writer: u32, offset: u64, bytes: usize) {
    let context = TRACE.with_borrow(|trace| trace.context);
    if let Some((session, fd)) = context {
        record(
            Stage::PtyWriteDone,
            session,
            fd,
            offset,
            bytes,
            writer as usize,
        );
    }
}
pub(crate) fn record(
    stage: Stage,
    session: [u8; 16],
    fd: i32,
    offset: u64,
    bytes: usize,
    extra: usize,
) {
    TRACE.with_borrow_mut(|trace| {
        if trace.enabled {
            if let Ok(ns) = crate::pty::monotonic_ns() {
                trace.push(Record {
                    ns,
                    session,
                    offset,
                    fd,
                    bytes,
                    extra,
                    stage,
                });
            } else {
                trace.dropped = trace.dropped.saturating_add(1);
                trace.enabled = false;
            }
        }
    });
}
pub(crate) fn dump(writer: &mut impl Write) -> io::Result<()> {
    TRACE.with_borrow_mut(|trace| trace.dump(writer))
}

/// Mark the recorder's own synchronous I/O so diagnostic stalls cannot be
/// mistaken for uninstrumented reactor work. The final tiny marker is flushed
/// separately; these spans are descriptive and never subtracted from a gate.
pub(crate) fn flush(file: &mut std::fs::File) -> io::Result<()> {
    let start = crate::pty::monotonic_ns()?;
    let mut writer = io::BufWriter::new(file);
    dump(&mut writer)?;
    writer.flush()?;
    let end = crate::pty::monotonic_ns()?;
    writeln!(
        writer,
        "{{\"kind\":\"stage-dump\",\"start_ns\":{start},\"end_ns\":{end}}}"
    )?;
    writer.flush()
}

#[cfg(test)]
pub(crate) fn credited_ranges() -> Vec<(usize, u64, usize)> {
    TRACE.with_borrow(|trace| {
        trace
            .records
            .iter()
            .filter(|record| matches!(record.stage, Stage::PtyWriteDone))
            .map(|record| (record.extra, record.offset, record.bytes))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    //! Validate hard diagnostic bounds and numeric-only serialization.
    use super::*;
    #[test]
    fn full_trace_counts_dropped_records_without_growing_storage() {
        let mut trace = Trace::default();
        let record = Record {
            ns: 11,
            session: [0; 16],
            offset: 12,
            fd: 3,
            bytes: 4,
            extra: 0,
            stage: Stage::PtyRead,
        };
        for _ in 0..LIMIT + 9 {
            trace.push(record);
        }
        assert_eq!(trace.records.len(), LIMIT);
        assert_eq!(trace.dropped, 9);
        let capacity = trace.records.capacity();
        trace.dump(&mut io::sink()).unwrap();
        assert_eq!(trace.records.capacity(), capacity);
        assert_eq!(trace.dropped, 0);
        assert!(trace.records.is_empty());
    }
    #[test]
    fn serialization_contains_only_the_numeric_stage_fields() {
        let mut trace = Trace::default();
        trace.push(Record {
            ns: 11,
            session: [0; 16],
            offset: 12,
            fd: 3,
            bytes: 4,
            extra: 0,
            stage: Stage::PtyRead,
        });
        let mut output = Vec::new();
        trace.dump(&mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "{\"kind\":\"stages\",\"records\":1,\"dropped\":0}\n{\"kind\":\"stage\",\"ns\":11,\"session\":0,\"offset\":12,\"fd\":3,\"bytes\":4,\"stage\":5,\"extra\":0}\n"
        );
    }
}
