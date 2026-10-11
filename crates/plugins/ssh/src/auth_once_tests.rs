//! Checks one-attempt consumption, input bounds and expiry without creating credential helpers.
use super::*;
struct Empty;
impl AuthProvider for Empty {
    fn network(&self) -> Option<NetworkProvider> {
        None
    }
    fn server_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { Ok(None) })
    }
    fn user_key(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { Ok(None) })
    }
    fn password(&self) -> Operation<'_, Option<Credentials>> {
        Box::pin(async { Ok(None) })
    }
}
fn decode(value: &str) -> OneUseAuth {
    serde_json::from_str(value).unwrap()
}
#[tokio::test]
async fn each_method_consumes_once_and_expiry_erases_both_methods() {
    let once = decode(r#"{"key":"synthetic-key","password":"synthetic-password"}"#);
    once.validate().unwrap();
    let provider = once.layer(Arc::new(Empty));
    assert!(matches!(
        provider.user_key().await.unwrap(),
        Some(Credentials::PrivateKey { .. })
    ));
    assert!(provider.user_key().await.unwrap().is_none());
    assert!(matches!(
        provider.password().await.unwrap(),
        Some(Credentials::Password(_))
    ));
    assert!(provider.password().await.unwrap().is_none());
    let mut expired = decode(r#"{"key":"synthetic-key","password":"synthetic-password"}"#);
    expired.received -= std::time::Duration::from_secs(61);
    assert!(expired.remaining().is_zero());
    let provider = expired.layer(Arc::new(Empty));
    assert!(provider.user_key().await.unwrap().is_none());
    assert!(provider.password().await.unwrap().is_none());
}
#[test]
fn invalid_material_is_refused_before_any_helper_or_scheduling() {
    for value in [
        r"{}",
        r#"{"passphrase":"synthetic"}"#,
        r#"{"key":""}"#,
        r#"{"key":"\u0000"}"#,
        r#"{"password":"line\nbreak"}"#,
        r#"{"password":"line\rbreak"}"#,
    ] {
        assert!(decode(value).validate().is_err());
    }
    assert!(
        serde_json::from_str::<OneUseAuth>(r#"{"password":"synthetic","saved":true}"#).is_err()
    );
    let excessive = format!(r#"{{"key":"{}"}}"#, "x".repeat(24577));
    assert!(serde_json::from_str::<OneUseAuth>(&excessive).is_err());
    let excessive = format!(r#"{{"password":"{}"}}"#, "x".repeat(16385));
    assert!(decode(&excessive).validate().is_err());
}

#[test]
fn caller_cannot_choose_or_extend_the_expiry_clock() {
    assert!(
        serde_json::from_str::<OneUseAuth>(r#"{"password":"synthetic","received":999999999}"#)
            .is_err()
    );
    assert!(
        serde_json::from_str::<TargetAuth>(
            r#"{"target":"host","auth":{"key":"synthetic"},"saved":true}"#
        )
        .is_err()
    );
}
