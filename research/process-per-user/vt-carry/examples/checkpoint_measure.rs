//! Perf-VM-only component measurements for the isolated carry checkpoint candidate [D270].
use infraternal_vt_carry as candidate;
use std::{hint::black_box, io, time::Instant};
use vte as existing;

#[derive(Default)]
struct Count(u64);
macro_rules! count {
    ($api:ident) => {
        impl $api::Perform for Count {
            fn print(&mut self, value: char) {
                self.0 = self.0.wrapping_add(u64::from(u32::from(value)));
            }
            fn execute(&mut self, value: u8) {
                self.0 = self.0.wrapping_add(u64::from(value));
            }
        }
    };
}
count!(candidate);
count!(existing);

enum Cohort {
    Existing(Vec<existing::Parser>),
    Candidate(Vec<candidate::Parser>),
}
impl Cohort {
    fn make(backend: &str, count: usize, prefix: &[u8]) -> Self {
        let mut output = Count::default();
        if backend == "existing" {
            let mut parsers: Vec<_> = (0..count).map(|_| existing::Parser::new()).collect();
            for parser in &mut parsers {
                parser.advance(&mut output, prefix);
            }
            Self::Existing(parsers)
        } else {
            let mut parsers: Vec<_> = (0..count).map(|_| candidate::Parser::new()).collect();
            for parser in &mut parsers {
                parser.advance(&mut output, prefix);
            }
            Self::Candidate(parsers)
        }
    }
    fn parse(&mut self, input: &[u8], rounds: usize) -> (u128, u64) {
        let mut output = Count::default();
        let started = Instant::now();
        for _ in 0..rounds {
            match self {
                Self::Existing(parsers) => {
                    for parser in parsers {
                        parser.advance(&mut output, black_box(input));
                    }
                }
                Self::Candidate(parsers) => {
                    for parser in parsers {
                        parser.advance(&mut output, black_box(input));
                    }
                }
            }
        }
        (started.elapsed().as_nanos(), black_box(output.0))
    }
}
fn pss() -> io::Result<u64> {
    let data = std::fs::read_to_string("/proc/self/smaps_rollup")?;
    data.lines()
        .find_map(|line| line.strip_prefix("Pss:"))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| io::Error::other("PSS unavailable"))?
        .parse()
        .map_err(io::Error::other)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let machine = std::fs::read_to_string("/proc/sys/kernel/hostname")?;
    assert_eq!(
        machine.trim(),
        "infraternal-perf-test",
        "measure only on the authorized perf VM"
    );
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3
        || !matches!(args[0].as_str(), "existing" | "candidate")
        || !matches!(args[2].as_str(), "idle" | "osc")
    {
        return Err("usage: checkpoint_measure {existing|candidate} COUNT {idle|osc}".into());
    }
    let count: usize = args[1].parse()?;
    if !(1..=1000).contains(&count) {
        return Err("COUNT must be between 1 and 1000".into());
    }
    let mut prefix = Vec::new();
    if args[2] == "osc" {
        prefix.extend_from_slice(b"\x1b]");
        prefix.extend_from_slice(&[b'x'; 4096]);
    }
    let before_pss = pss()?;
    let mut cohort = Cohort::make(&args[0], count, &prefix);
    black_box(&cohort);
    let cohort_pss = pss()?;
    let mut encoded = Vec::new();
    let mut export_ns = None;
    let mut import_ns = None;
    let mut checkpoint_bytes = None;
    let mut restored = None;
    if let Cohort::Candidate(parsers) = &cohort {
        let started = Instant::now();
        for parser in parsers {
            encoded.push(parser.export_checkpoint(4096)?);
        }
        export_ns = Some(started.elapsed().as_nanos());
        checkpoint_bytes = Some(encoded.iter().map(Vec::len).sum::<usize>());
    }
    black_box(&encoded);
    let with_checkpoint_pss = pss()?;
    if !encoded.is_empty() {
        let started = Instant::now();
        let result: Result<Vec<candidate::Parser>, _> = encoded
            .iter()
            .map(|state| candidate::Parser::import_checkpoint(state, 4096))
            .collect();
        restored = Some(result?);
        import_ns = Some(started.elapsed().as_nanos());
    }
    black_box(&restored);
    let with_restored_pss = pss()?;
    // Finish an OSC before the common parsing comparison: its existing caller
    // bounds payloads, so a component probe must never append bulk text to it.
    let _ = cohort.parse(b"\x07", 1);
    let input = b"plain numbered terminal output 0123456789\r\n";
    let rounds = (20_000_000 / (count * input.len())).max(1);
    let (parse_ns, checksum) = cohort.parse(input, rounds);
    fn number<T: ToString>(value: Option<T>) -> String {
        value.map_or_else(|| "null".to_owned(), |value| value.to_string())
    }
    println!(
        "{{\"component_only\":true,\"backend\":\"{}\",\"case\":\"{}\",\"count\":{},\"existing_struct_bytes\":{},\"candidate_struct_bytes\":{},\"before_pss_kib\":{},\"cohort_pss_kib\":{},\"with_checkpoint_pss_kib\":{},\"with_restored_pss_kib\":{},\"checkpoint_bytes\":{},\"export_ns\":{},\"import_ns\":{},\"parse_bytes\":{},\"parse_ns\":{},\"checksum\":{}}}",
        args[0],
        args[2],
        count,
        std::mem::size_of::<existing::Parser>(),
        std::mem::size_of::<candidate::Parser>(),
        before_pss,
        cohort_pss,
        with_checkpoint_pss,
        with_restored_pss,
        number(checkpoint_bytes),
        number(export_ns),
        number(import_ns),
        count * rounds * input.len(),
        parse_ns,
        checksum
    );
    Ok(())
}
