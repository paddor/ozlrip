//! Frames written by upstream OpenZL C through the C API, decoded by ozlrip.
//!
//! `zli` cannot pick format versions or typed inputs, so these tests call
//! the library through `openzl-shim`.

use openzl_shim::{CompressOptions, Decompressor, Graph, Input, compress};
use ozlrip::{ErrorKind, FrameValueType, Output};

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
        assert_header_matches_frame(&frame);
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

    // The serial API rejects typed frames; decode_outputs returns them.
    let err = ozlrip::decode(&frame).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Unsupported);
    assert_eq!(
        ozlrip::decode_outputs(&frame).unwrap(),
        [Output::Numeric {
            width: 4,
            bytes: values,
        }]
    );
}

/// Typed inputs of every type, alone and together in one frame, through
/// every starting graph that accepts them and every format version from the
/// first that writes several typed outputs.
#[test]
fn typed_frames_decode_like_their_inputs() {
    let serial = text_input();
    let records = (0u8..=255).cycle().take(3 * 700).collect::<Vec<u8>>();
    let numbers = |width: usize| {
        (0u64..900)
            .flat_map(|value| (value * 7919 % 1000).to_le_bytes()[..width].to_vec())
            .collect::<Vec<u8>>()
    };
    let numeric = [1, 2, 4, 8].map(|width| (width, numbers(width)));
    let strings = ["alpha", "", "beta", "gamma", "delta"]
        .iter()
        .cycle()
        .take(400)
        .copied()
        .collect::<Vec<_>>();
    let string_bytes = strings.concat().into_bytes();
    let string_lengths = strings
        .iter()
        .map(|string| u32::try_from(string.len()).unwrap())
        .collect::<Vec<_>>();

    let mut inputs = vec![
        (Input::Serial(&serial), Output::Serial(serial.clone())),
        (
            Input::Struct {
                width: 3,
                bytes: &records,
            },
            Output::Struct {
                width: 3,
                bytes: records.clone(),
            },
        ),
        (
            Input::String {
                bytes: &string_bytes,
                lengths: &string_lengths,
            },
            Output::String {
                bytes: string_bytes.clone(),
                lengths: string_lengths.clone(),
            },
        ),
    ];
    for (width, bytes) in &numeric {
        inputs.push((
            Input::Numeric {
                width: *width,
                bytes,
            },
            Output::Numeric {
                width: *width,
                bytes: bytes.clone(),
            },
        ));
    }

    let mut frames = 0;
    for version in 15..=openzl_shim::max_format_version() {
        let mut cases = inputs
            .iter()
            .map(|(input, output)| (vec![*input], vec![output.clone()]))
            .collect::<Vec<_>>();
        cases.push((
            inputs.iter().map(|(input, _)| *input).collect(),
            inputs.iter().map(|(_, output)| output.clone()).collect(),
        ));
        for (case_inputs, expected) in cases {
            for graph in [Graph::Generic, Graph::Store, Graph::Zstd] {
                let options = CompressOptions {
                    graph,
                    format_version: version,
                    ..CompressOptions::default()
                };
                // Some graphs only accept some input types.
                let Ok(frame) = compress(&case_inputs, options) else {
                    continue;
                };
                let decoded = ozlrip::decode_outputs(&frame).unwrap_or_else(|err| {
                    panic!("v{version} {graph:?} {} inputs: {err}", case_inputs.len())
                });
                assert_eq!(
                    decoded,
                    expected,
                    "v{version} {graph:?} {} inputs",
                    case_inputs.len()
                );
                assert_header_matches_frame(&frame);
                frames += 1;
            }
        }
    }
    assert!(frames > 100, "{frames} frames");
}

/// Every prefix of an upstream frame, in every format version, is accepted
/// by ozlrip exactly when upstream accepts it. Before v21 this covers the
/// trailing checksums.
#[test]
fn frame_prefixes_are_accepted_like_upstream() {
    for version in openzl_shim::min_format_version()..=openzl_shim::max_format_version() {
        for input in [&b""[..], b"abc"] {
            let frame = compress(
                &[Input::Serial(input)],
                CompressOptions {
                    graph: Graph::Store,
                    format_version: version,
                    ..CompressOptions::default()
                },
            )
            .unwrap();
            for len in 0..=frame.len() {
                let prefix = &frame[..len];
                let mut dst = [0u8; 16];
                let upstream = Decompressor::new()
                    .decompress_serial(prefix, &mut dst)
                    .is_ok();
                let ours = ozlrip::decode(prefix).is_ok();
                assert_eq!(
                    ours,
                    upstream,
                    "v{version} input {} bytes, prefix {len} of {}",
                    input.len(),
                    frame.len()
                );
            }
        }
    }
}

/// `frame_size` agrees with upstream `ZL_getCompressedSize` on every prefix
/// of upstream frames, with and without bytes after the frame.
#[test]
fn frame_size_matches_upstream() {
    let text = text_input();
    for version in openzl_shim::min_format_version()..=openzl_shim::max_format_version() {
        for input in [&b""[..], b"abc", &text[..300]] {
            for graph in [Graph::Store, Graph::Zstd] {
                let options = CompressOptions {
                    graph,
                    format_version: version,
                    ..CompressOptions::default()
                };
                let Ok(frame) = compress(&[Input::Serial(input)], options) else {
                    continue;
                };
                for tail in [&b""[..], b"\0\x07tail"] {
                    let data = [frame.as_slice(), tail].concat();
                    for len in 0..=data.len() {
                        let prefix = &data[..len];
                        let upstream = openzl_shim::compressed_size(prefix).ok();
                        let ours = ozlrip::frame_size(prefix).ok();
                        assert_eq!(
                            ours,
                            upstream,
                            "v{version} {graph:?} input {} tail {} prefix {len}",
                            input.len(),
                            tail.len()
                        );
                    }
                    assert_eq!(ozlrip::frame_size(&data).unwrap(), frame.len());
                }
            }
        }
    }
}

/// The header alone gives what `inspect` reports for the whole frame, no
/// shorter prefix parses, and every longer one does.
fn assert_header_matches_frame(frame: &[u8]) {
    let info = ozlrip::inspect(frame).unwrap();
    let header = ozlrip::inspect_header(&frame[..info.header_bytes]).unwrap();
    assert_eq!(header.format_version, info.format_version);
    assert_eq!(header.header_bytes, info.header_bytes);
    assert_eq!(header.outputs, info.outputs);
    assert_eq!(header.output_types, info.output_types);
    assert_eq!(header.output_sizes, info.output_sizes);
    assert_eq!(header.output_elements, info.output_elements);
    for len in 0..info.header_bytes {
        assert!(
            ozlrip::inspect_header(&frame[..len]).is_err(),
            "prefix {len}"
        );
    }
    for len in info.header_bytes..=frame.len() {
        assert_eq!(
            ozlrip::inspect_header(&frame[..len]).unwrap(),
            header,
            "prefix {len}"
        );
    }
}

/// `decode_chunks` passes each chunk of upstream's segmented frames on its
/// own, and together they are the input.
#[test]
fn decode_chunks_matches_segmented_frames() {
    const CHUNK: usize = 64 * 1024;
    // Letters from a fixed LCG: compressible, but far below the default
    // expansion limit.
    let mut state = 0x2545_f491_u32;
    let input = (0..5 * CHUNK + 123)
        .map(|_| {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            b'a' + (state >> 27) as u8 % 16
        })
        .collect::<Vec<_>>();
    let mut decoder = ozlrip::Decoder::new();
    let mut frames = 0;
    for version in 21..=openzl_shim::max_format_version() {
        for graph in [Graph::Generic, Graph::Store, Graph::Zstd, Graph::Lz4] {
            let options = CompressOptions {
                graph,
                format_version: version,
                chunk_size: CHUNK,
                ..CompressOptions::default()
            };
            let Ok(frame) = compress(&[Input::Serial(&input)], options) else {
                continue;
            };
            let info = ozlrip::inspect(&frame).unwrap();
            let mut chunks = Vec::new();

            let written = decoder
                .decode_chunks(&frame, |chunk| {
                    chunks.push(chunk.to_vec());
                    Ok(())
                })
                .unwrap_or_else(|err| panic!("v{version} {graph:?}: {err}"));

            assert_eq!(written, input.len(), "v{version} {graph:?}");
            assert_eq!(chunks.len(), info.chunks, "v{version} {graph:?}");
            assert_eq!(chunks.len(), 6, "v{version} {graph:?}");
            assert!(chunks.concat() == input, "v{version} {graph:?}");
            frames += 1;
        }
    }
    assert!(frames >= 3 * 7, "{frames} frames");
}
