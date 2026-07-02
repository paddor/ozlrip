use ozlrip::{ErrorKind, Limits};

#[test]
fn inspect_rejects_non_openzl_input() {
    let err = ozlrip::inspect(b"not-openzl").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
}

#[test]
fn decode_into_preserves_destination_on_unsupported_header() {
    let mut dst = vec![1, 2, 3];
    let err = ozlrip::decode_into(b"not-openzl", &mut dst, Limits::default()).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(dst, [1, 2, 3]);
}
