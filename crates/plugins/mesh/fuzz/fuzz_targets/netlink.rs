//! Exercises the same checked message/attribute parser used for kernel replies [169], #129.
#![no_main]
#[allow(dead_code)]
#[path = "../../src/netlink.rs"]
mod netlink;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = netlink::messages(data);
    if let Ok(attributes) = netlink::attributes(data) {
        for attribute in attributes {
            if attribute.nested {
                let _ = netlink::attributes(attribute.payload);
            }
        }
    }
    if let Ok(messages) = netlink::messages(data) {
        for message in messages {
            let _ = netlink::attributes(message.payload);
            let _ = netlink::u32_at(message.payload, 0);
        }
    }
});
