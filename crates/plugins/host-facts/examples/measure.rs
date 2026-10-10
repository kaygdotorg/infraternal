//! Measures host-facts collection latency and encoded control-frame sizes on the current machine.
use infraternal_plugin_api::AgentPlugin;
use infraternal_plugin_host_facts::{
    AgentMode, HostFactsPlugin, collect_static_facts, refresh_live_facts,
};
use infraternal_protocol::{Frame, encode_muxed_frame_into};
use std::{
    error::Error,
    hint::black_box,
    io,
    time::{Duration, Instant},
};

const SAMPLES: usize = 1_000;

fn report_samples(label: &str, mut sample: impl FnMut() -> u64) {
    let mut elapsed = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let started = Instant::now();
        black_box(sample());
        elapsed.push(started.elapsed());
    }
    elapsed.sort_unstable();
    let median = micros(elapsed[SAMPLES / 2]);
    let p95 = micros(elapsed[SAMPLES * 95 / 100]);
    println!("{label}_p50_us={median:.2} {label}_p95_us={p95:.2}");
}

fn micros(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

fn wire_bytes(call_id: u32, input: &[u8], result: &[u8]) -> Result<(usize, usize), Box<dyn Error>> {
    let mut request = Vec::with_capacity(256);
    encode_muxed_frame_into(
        0,
        &Frame::Call {
            call_id,
            action_id: "host.facts.read",
            input_json: input,
        },
        &mut request,
    )?;
    let mut response = Vec::with_capacity(result.len() + 64);
    encode_muxed_frame_into(
        0,
        &Frame::Result {
            call_id,
            ok: true,
            json: result,
        },
        &mut response,
    )?;
    Ok((request.len(), response.len()))
}

fn action(plugin: &mut HostFactsPlugin, input: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    plugin
        .call("host.facts.read", input)
        .map_err(|error| io::Error::other(format!("plugin action failed: {error:?}")))
        .map_err(Into::into)
}

fn main() -> Result<(), Box<dyn Error>> {
    report_samples("static_collection", || {
        u64::from(collect_static_facts(AgentMode::Embedded).cpus)
    });
    let mut live_facts = collect_static_facts(AgentMode::Embedded);
    report_samples("live_collection", || {
        refresh_live_facts(&mut live_facts);
        live_facts.load_average.unwrap_or_default()[0].to_bits()
    });

    let mut plugin = HostFactsPlugin::new(AgentMode::Embedded);
    let static_result = action(&mut plugin, b"{}")?;
    let live_result = action(&mut plugin, br#"{"includeLive":true}"#)?;
    let (static_request, static_response) = wire_bytes(1, b"{}", &static_result)?;
    let (live_request, live_response) = wire_bytes(2, br#"{"includeLive":true}"#, &live_result)?;
    println!(
        "static_json_bytes={} static_wire_request_bytes={} static_wire_response_bytes={} static_wire_total_one_muxed_leg_bytes={} static_wire_total_two_leg_bytes={}",
        static_result.len(),
        static_request,
        static_response,
        static_request + static_response,
        2 * (static_request + static_response),
    );
    println!(
        "popover_live_json_bytes={} popover_wire_request_bytes={} popover_wire_response_bytes={} popover_wire_total_one_muxed_leg_bytes={} popover_wire_total_two_leg_bytes={}",
        live_result.len(),
        live_request,
        live_response,
        live_request + live_response,
        2 * (live_request + live_response),
    );
    Ok(())
}
