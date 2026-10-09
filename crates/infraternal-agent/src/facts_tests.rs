//! Guards the cheap facts boundary against discovery parameters, non-object JSON and oversized inputs.
#[test]
fn request_is_only_a_bounded_empty_object() {
    assert!(super::accepts_request(b"{}"));
    assert!(super::accepts_request(b" { } "));
    for input in [
        b"[]".as_slice(),
        b"null",
        b"true",
        b"0",
        b"{\"scan\":true}",
        b"{\"nested\":{}}",
        b"{}{}",
    ] {
        assert!(
            !super::accepts_request(input),
            "non-object or discovery input must be refused"
        );
    }
    let mut at_bound = vec![b' '; 254];
    at_bound.extend_from_slice(b"{}");
    assert!(super::accepts_request(&at_bound));
    at_bound.push(b' ');
    assert!(!super::accepts_request(&at_bound));
}
