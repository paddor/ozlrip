//! Frames written by upstream OpenZL C through the C API, decoded by ozlrip.
//!
//! `zli` cannot pick format versions or typed inputs, so these tests call
//! the library through `openzl-shim`.

use openzl_shim::{CompressOptions, Graph, Input, compress};
use ozlrip_core::{ErrorKind, FrameValueType};

fn text_input() -> Vec<u8> {
    b"ozlrip interop through the OpenZL C API, repeated for entropy. "
        .iter()
        .copied()
        .cycle()
        .take(16 * 1024)
        .collect()
}

#[test]
fn format_version_range_is_known() {
    let min = openzl_shim::min_format_version();
    let max = openzl_shim::max_format_version();
    let default = openzl_shim::default_format_version();
    assert!(
        min <= default && default <= max,
        "{min} <= {default} <= {max}"
    );
}

#[test]
fn serial_graphs_roundtrip_at_default_version() {
    let input = text_input();
    for graph in [
        Graph::Generic,
        Graph::Store,
        Graph::Zstd,
        Graph::Lz4,
        Graph::Huffman,
        Graph::Fse,
        Graph::Entropy,
    ] {
        let frame = compress(
            &[Input::Serial(&input)],
            CompressOptions {
                graph,
                ..CompressOptions::default()
            },
        )
        .unwrap_or_else(|err| panic!("{graph:?} compress failed: {err}"));
        let decoded =
            ozlrip::decode(&frame).unwrap_or_else(|err| panic!("{graph:?} decode failed: {err}"));
        assert_eq!(decoded, input, "{graph:?} roundtrip mismatch");
    }
}

#[test]
fn numeric_frame_reports_numeric_output() {
    let values = (0u32..4096)
        .flat_map(|value| (value * 3 + 7).to_le_bytes())
        .collect::<Vec<u8>>();
    let frame = compress(
        &[Input::Numeric {
            width: 4,
            bytes: &values,
        }],
        CompressOptions::default(),
    )
    .unwrap();

    let info = ozlrip::inspect(&frame).unwrap();
    assert_eq!(info.output_types, [FrameValueType::Numeric]);

    // Typed outputs are not decodable through the serial API yet.
    let err = ozlrip::decode(&frame).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
}
