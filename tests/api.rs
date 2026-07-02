use ozlrip::{ErrorKind, Limits};

const MAGIC_BASE: u32 = 0xd7b1_a5c0;

fn magic(version: u32) -> [u8; 4] {
    (MAGIC_BASE + version).to_le_bytes()
}

fn stored_serial_frame(bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(u8::try_from(bytes.len() + 1).unwrap());
    input.push(1);
    input.push(1);
    input.push(u8::try_from(bytes.len()).unwrap());
    input.extend_from_slice(bytes);
    input.push(0);
    input
}

fn transform_graph_frame() -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    input.push(4);
    input.push(2);
    input.push(1);
    input.push(0);
    input.push(22);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(3);
    input.extend_from_slice(&[1, 2, 3]);
    input.push(0);
    input
}

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

#[test]
fn decode_into_preserves_destination_on_unsupported_graph() {
    let frame = transform_graph_frame();
    let mut dst = vec![1, 2, 3];

    let err = ozlrip::decode_into(&frame, &mut dst, Limits::default()).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(dst, [1, 2, 3]);
}

#[test]
fn decode_returns_stored_serial_output() {
    let frame = stored_serial_frame(&[7, 8, 9]);

    let decoded = ozlrip::decode(&frame).unwrap();

    assert_eq!(decoded, [7, 8, 9]);
}

#[test]
fn decode_into_appends_stored_serial_output() {
    let frame = stored_serial_frame(&[7, 8, 9]);
    let mut dst = vec![1, 2];

    let written = ozlrip::decode_into(&frame, &mut dst, Limits::default()).unwrap();

    assert_eq!(written, 3);
    assert_eq!(dst, [1, 2, 7, 8, 9]);
}

#[test]
fn inspect_reports_stored_serial_metadata() {
    let frame = stored_serial_frame(&[7, 8, 9]);

    let info = ozlrip::inspect(&frame).unwrap();

    assert_eq!(info.header_bytes, 7);
    assert_eq!(info.decoded_bytes, Some(3));
    assert_eq!(info.chunks, 1);
    assert_eq!(info.stored_streams, 1);
    assert_eq!(info.transforms, 0);
}

#[test]
fn inspect_enforces_stored_stream_limit() {
    let frame = stored_serial_frame(&[7, 8, 9]);
    let limits = Limits {
        max_stored_stream_bytes: 2,
        ..Limits::default()
    };

    let err = ozlrip::decode_into(&frame, &mut Vec::new(), limits).unwrap_err();

    assert_eq!(err.kind(), ErrorKind::LimitExceeded);
}
