//! Compares healthy predecessor FIFO coordination with fenced credit accumulation; excludes transport and heap-state sizing, #78.
use super::*;
use std::time::Instant;

const CREDIT_CYCLES: u64 = 100_000;
const INPUT_CYCLES: u64 = 10_000;

async fn credit_cost(accumulate: bool) -> u128 {
    if accumulate {
        let (mut sender, mut receiver) = channel();
        let started = Instant::now();
        for _ in 0..CREDIT_CYCLES {
            for _ in 0..8 {
                assert!(sender.try_send(Command::Credit(4096)).is_ok());
            }
            assert!(matches!(
                receiver.next().await,
                Some(Command::Credit(32768))
            ));
        }
        started.elapsed().as_nanos() / u128::from(CREDIT_CYCLES * 8)
    } else {
        let (sender, mut receiver) = mpsc::channel(8);
        let started = Instant::now();
        for _ in 0..CREDIT_CYCLES {
            for _ in 0..8 {
                assert!(sender.try_send(Command::Credit(4096)).is_ok());
            }
            for _ in 0..8 {
                assert!(matches!(receiver.recv().await, Some(Command::Credit(4096))));
            }
        }
        started.elapsed().as_nanos() / u128::from(CREDIT_CYCLES * 8)
    }
}
async fn input_cost(fenced: bool) -> u128 {
    if fenced {
        let (mut sender, mut receiver) = channel();
        let started = Instant::now();
        for _ in 0..INPUT_CYCLES {
            for seq in 0..8 {
                assert!(sender.try_send(Command::Input(seq, vec![b'x'])).is_ok());
            }
            for seq in 0..8 {
                assert!(
                    matches!(receiver.next().await, Some(Command::Input(actual_seq, _)) if actual_seq == seq)
                );
            }
        }
        started.elapsed().as_nanos() / u128::from(INPUT_CYCLES * 8)
    } else {
        let (sender, mut receiver) = mpsc::channel(8);
        let started = Instant::now();
        for _ in 0..INPUT_CYCLES {
            for seq in 0..8 {
                assert!(sender.try_send(Command::Input(seq, vec![b'x'])).is_ok());
            }
            for seq in 0..8 {
                assert!(
                    matches!(receiver.recv().await, Some(Command::Input(actual_seq, _)) if actual_seq == seq)
                );
            }
        }
        started.elapsed().as_nanos() / u128::from(INPUT_CYCLES * 8)
    }
}
#[tokio::test]
#[ignore = "release command coordination diagnostic, not end-to-end throughput; run without own build overlap"]
async fn command_coordination_cost_against_existing_fifo() {
    let mut accumulated = Vec::new();
    let mut credit_fifo = Vec::new();
    let mut fenced_input = Vec::new();
    let mut input_fifo = Vec::new();
    for sample in 0..25 {
        // Alternate the baseline order to avoid always charging one side for
        // the first warm-up or for a changing external host load.
        let order = if sample % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        };
        for updated in order {
            let credit = credit_cost(updated).await;
            let input = input_cost(updated).await;
            if updated {
                accumulated.push(credit);
                fenced_input.push(input);
            } else {
                credit_fifo.push(credit);
                input_fifo.push(input);
            }
        }
    }
    for samples in [
        &mut accumulated,
        &mut credit_fifo,
        &mut fenced_input,
        &mut input_fifo,
    ] {
        samples.sort_unstable();
    }
    println!(
        "command_coordination samples=25 burst=8 credit_commands_per_sample={} input_commands_per_sample={} accumulated_credit_p50_ns={} accumulated_credit_p99_ns={} predecessor_credit_p50_ns={} predecessor_credit_p99_ns={} fenced_input_p50_ns={} fenced_input_p99_ns={} predecessor_input_p50_ns={} predecessor_input_p99_ns={} input_includes_one_byte_payload_allocation=true sender_inline_bytes={} receiver_inline_bytes={} excludes_heap_state_and_transport=true cores={} load={}",
        CREDIT_CYCLES * 8,
        INPUT_CYCLES * 8,
        accumulated[12],
        accumulated[24],
        credit_fifo[12],
        credit_fifo[24],
        fenced_input[12],
        fenced_input[24],
        input_fifo[12],
        input_fifo[24],
        std::mem::size_of::<Sender>(),
        std::mem::size_of::<Receiver>(),
        std::thread::available_parallelism().unwrap(),
        std::fs::read_to_string("/proc/loadavg").unwrap().trim()
    );
}
