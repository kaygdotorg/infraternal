//! Fuzzes bounded helper-owned SPS metadata selection, idempotence and output size without decoding pictures [D12,D204], #146.
#![no_main]
use infraternal_plugin_desktop::parameter_sets::{self, Parameters};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() > infraternal_protocol::desktop::MAX_VIDEO_BYTES {
        return;
    }
    let packet = data.to_vec().into();
    for mode in [Parameters::Encoder, Parameters::LowDelay] {
        if let Ok(selected) = parameter_sets::select(&packet, mode) {
            assert!(selected.len() <= data.len());
            assert!(parameter_sets::select(&selected, mode).is_ok_and(|next| next == selected));
        }
    }
});
