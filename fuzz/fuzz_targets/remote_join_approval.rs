//! Fuzzes machine join bodies, owner-approved join requests and invitation secrets; parsing grants no authority [D168], #78, #263, #561.
#![no_main]
#![forbid(unsafe_code)]
use infraternal_plugin_remote::{agent_link, enrollment};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 16_384 {
        return;
    }
    infraternal_server::verify_remote_join_sample(data);
    // What the joining machine itself reads: the invitation from stdin and
    // the server's link challenge. Accepted invitations re-encode stably.
    if let Ok(invitation) = serde_json::from_slice::<enrollment::JoinInvitation>(data) {
        let once = serde_json::to_vec(&invitation).unwrap();
        let again: enrollment::JoinInvitation = serde_json::from_slice(&once).unwrap();
        assert_eq!(serde_json::to_vec(&again).unwrap(), once);
    }
    let _ = serde_json::from_slice::<agent_link::AgentLinkChallenge>(data);
    let _ = serde_json::from_slice::<agent_link::AgentLinkProofV2>(data);
});
