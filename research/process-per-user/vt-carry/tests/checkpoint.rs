//! Compare resumed callbacks with the selected parser and reject incomplete state [D270].
#![cfg(feature = "std")]
use infraternal_vt_carry as candidate;
use vte as existing;

#[derive(Debug, PartialEq, Eq)]
enum Event {
    Print(char),
    Execute(u8),
    Csi(Vec<Vec<u16>>, Vec<u8>, bool, char),
    Esc(Vec<u8>, bool, u8),
    Osc(Vec<Vec<u8>>, bool),
    Hook(Vec<Vec<u16>>, Vec<u8>, bool, char),
    Put(u8),
    Unhook,
}
#[derive(Default)]
struct Recorder(Vec<Event>);
macro_rules! record {
    ($api:ident) => {
        impl $api::Perform for Recorder {
            fn print(&mut self, point: char) {
                self.0.push(Event::Print(point));
            }
            fn execute(&mut self, byte: u8) {
                self.0.push(Event::Execute(byte));
            }
            fn csi_dispatch(
                &mut self,
                params: &$api::Params,
                middle: &[u8],
                ignored: bool,
                action: char,
            ) {
                self.0.push(Event::Csi(
                    params.iter().map(<[u16]>::to_vec).collect(),
                    middle.to_vec(),
                    ignored,
                    action,
                ));
            }
            fn esc_dispatch(&mut self, middle: &[u8], ignored: bool, action: u8) {
                self.0.push(Event::Esc(middle.to_vec(), ignored, action));
            }
            fn osc_dispatch(&mut self, params: &[&[u8]], bell: bool) {
                self.0.push(Event::Osc(
                    params.iter().map(|bytes| bytes.to_vec()).collect(),
                    bell,
                ));
            }
            fn hook(&mut self, params: &$api::Params, middle: &[u8], ignored: bool, action: char) {
                self.0.push(Event::Hook(
                    params.iter().map(<[u16]>::to_vec).collect(),
                    middle.to_vec(),
                    ignored,
                    action,
                ));
            }
            fn put(&mut self, byte: u8) {
                self.0.push(Event::Put(byte));
            }
            fn unhook(&mut self) {
                self.0.push(Event::Unhook);
            }
        }
    };
}
record!(candidate);
record!(existing);

fn resume_at(bytes: &[u8], at: usize) {
    let mut old = existing::Parser::new();
    let mut new = candidate::Parser::new();
    let mut expected = Recorder::default();
    let mut actual = Recorder::default();
    old.advance(&mut expected, &bytes[..at]);
    new.advance(&mut actual, &bytes[..at]);
    assert_eq!(expected.0, actual.0, "prefix at {at}");
    let state = new.export_checkpoint(8192).unwrap();
    let mut restored = candidate::Parser::<1024>::import_checkpoint(&state, 8192).unwrap();
    assert_eq!(restored.export_checkpoint(8192).unwrap(), state);
    old.advance(&mut expected, &bytes[at..]);
    restored.advance(&mut actual, &bytes[at..]);
    assert_eq!(expected.0, actual.0, "suffix at {at}");
    // Exercise future transitions even when the original input ended midway
    // through ignored syntax or a partial scalar.
    let continuation = b"\x18\x1b[1:2;3mZ\x1b]2;next\x07\xf0\x9f\x99\x82";
    old.advance(&mut expected, continuation);
    restored.advance(&mut actual, continuation);
    assert_eq!(expected.0, actual.0, "continuation at {at}");
}

#[test]
fn every_sample_split_matches_existing_callbacks() {
    let mut cases = vec![
        b"plain text\r\n".to_vec(),
        "text λ界🙂 suffix".as_bytes().to_vec(),
        b"\xf0\x9f\x80x\xc0\xaf\xed\xa0\x80\xff\x1b[31mZ".to_vec(),
        b"\x1b[38:2:1:2:3;48;5;27mZ\x1b[0m".to_vec(),
        b"\x1b[1\n;2mZ\x1b(\x0eA\x1b)B".to_vec(),
        b"\x1bP1;2$qpayload\x1b\\Z\x1b^ignore\x1b\\".to_vec(),
        b"\x1b[??????mZ\x1bP:::::::::qtext\x18".to_vec(),
        b"\x1b]0;older title\x07\x1b]2;new".to_vec(),
    ];
    let mut many = b"\x1b[".to_vec();
    many.extend_from_slice(&b"1:".repeat(40));
    many.extend_from_slice(b"mZ");
    cases.push(many);
    let mut osc = b"\x1b]0;".to_vec();
    osc.extend_from_slice(&b"part;".repeat(300));
    osc.extend_from_slice(b"\x1b\\\x1b]2;small");
    cases.push(osc);
    let mut csi = b"\x1b[".to_vec();
    csi.extend_from_slice(&vec![b'1'; 12_000]);
    csi.extend_from_slice(b";2mZ");
    cases.push(csi);
    for bytes in cases {
        let positions: Vec<usize> = if bytes.len() <= 2048 {
            (0..=bytes.len()).collect()
        } else {
            vec![
                0,
                1,
                2,
                3,
                31,
                32,
                255,
                4095,
                4096,
                5000,
                bytes.len() - 1,
                bytes.len(),
            ]
        };
        for at in positions {
            resume_at(&bytes, at);
        }
    }
}

#[test]
fn every_truncation_and_trailing_bytes_are_refused() {
    let mut parser = candidate::Parser::new();
    parser.advance(&mut Recorder::default(), b"\x1b]2;unfinished title");
    let state = parser.export_checkpoint(4096).unwrap();
    for end in 0..state.len() {
        assert!(candidate::Parser::<1024>::import_checkpoint(&state[..end], 4096).is_err());
    }
    let mut trailing = state;
    trailing.push(0);
    assert!(candidate::Parser::<1024>::import_checkpoint(&trailing, 4096).is_err());
}

#[test]
fn caller_budget_applies_to_export_and_import() {
    let mut parser = candidate::Parser::new();
    parser.advance(&mut Recorder::default(), b"\x1b]");
    parser.advance(&mut Recorder::default(), &[b'x'; 4096]);
    assert_eq!(
        parser.export_checkpoint(4095),
        Err(candidate::checkpoint::CheckpointError::TooLarge)
    );
    let state = parser.export_checkpoint(4096).unwrap();
    assert!(state.len() <= candidate::checkpoint::FIXED_CAPACITY + 4096);
    assert!(candidate::Parser::<1024>::import_checkpoint(&state, 4095).is_err());
    assert!(candidate::Parser::<1024>::import_checkpoint(&state, 4096).is_ok());
}

#[test]
fn changed_records_are_either_refused_or_safe_to_continue() {
    let mut parser = candidate::Parser::new();
    parser.advance(&mut Recorder::default(), b"\x1b[1:2;3:");
    let original = parser.export_checkpoint(4096).unwrap();
    let mut seed = 270205_u64;
    for _ in 0..20_000 {
        let mut state = original.clone();
        for _ in 0..3 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let at = seed as usize % state.len();
            state[at] = (seed >> 32) as u8;
        }
        if let Ok(mut restored) = candidate::Parser::<1024>::import_checkpoint(&state, 4096) {
            restored.advance(
                &mut Recorder::default(),
                b"mZ\x18\x1b]2;next\x07\x1bP$qtext\x1b\\",
            );
            let next = restored.export_checkpoint(4096).unwrap();
            assert!(candidate::Parser::<1024>::import_checkpoint(&next, 4096).is_ok());
        }
    }
}
