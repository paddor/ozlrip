//! Upstream compresses a spread of inputs at every format version it writes,
//! with every standard graph and with chains of numeric nodes. ozlrip decodes
//! every frame to its input.

use openzl_shim::{CompressOptions, Graph, Input, Node, compress_pipeline};
use ozlrip::Output;

const GRAPHS: [Graph; 12] = [
    Graph::Generic,
    Graph::Store,
    Graph::Zstd,
    Graph::Lz4,
    Graph::Fse,
    Graph::Huffman,
    Graph::Entropy,
    Graph::FieldLz,
    Graph::Bitpack,
    Graph::Flatpack,
    Graph::Constant,
    Graph::Numeric,
];

/// Node chains for numeric data, each ending in its own graph.
const NUMERIC_CHAINS: [&[Node]; 4] = [
    &[Node::DeltaInt],
    &[Node::Zigzag],
    &[Node::RangePack],
    &[Node::DeltaInt, Node::Zigzag, Node::RangePack],
];

const BITUNPACK_WIDTHS: [u8; 16] = [1, 3, 7, 8, 9, 12, 15, 16, 17, 24, 31, 32, 33, 48, 63, 64];

/// Upstream's private deprecated nodes for serial data, which it still writes
/// in the format versions that know them.
const DEPRECATED_SERIAL_NODES: [Node; 4] = [
    Node::Named(c"zl.private.rolz_deprecated"),
    Node::Named(c"zl.private.fast_lz_deprecated"),
    Node::Named(c"zl.private.fse_deprecated"),
    Node::Named(c"zl.private.huffman_deprecated"),
];

/// Upstream's private deprecated nodes for fixed-width records.
const DEPRECATED_STRUCT_NODES: [Node; 3] = [
    Node::Named(c"zl.private.huffman_fixed_deprecated"),
    Node::Named(c"zl.private.zstd_fixed_deprecated"),
    Node::Named(c"zl.private.transpose_deprecated"),
];

fn random(seed: u64) -> impl Iterator<Item = u64> {
    let mut state = seed;
    std::iter::repeat_with(move || {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state >> 11
    })
}

fn cases() -> Vec<(String, Output)> {
    let mut cases = Vec::new();
    let text = b"ozlrip format version sweep through the OpenZL C API. "
        .iter()
        .copied()
        .cycle()
        .take(16 * 1024)
        .collect::<Vec<u8>>();
    let serial = [
        ("empty", Vec::new()),
        ("3", b"abc".to_vec()),
        (
            "1000",
            random(8).take(1000).map(|v| (v % 61) as u8).collect(),
        ),
        ("text", text),
        ("noise", random(1).take(8 * 1024).map(|v| v as u8).collect()),
        (
            "skewed",
            random(2)
                .take(16 * 1024)
                .map(|v| b"aaaabbc"[(v % 7) as usize])
                .collect(),
        ),
        ("constant", vec![7; 4096]),
    ];
    for (name, bytes) in serial {
        cases.push((format!("serial-{name}"), Output::Serial(bytes)));
    }

    for width in [1usize, 2, 4, 8] {
        let patterns: [(&str, Vec<u64>); 6] = [
            ("small", random(3).take(3000).map(|v| v % 100).collect()),
            (
                "range",
                random(4).take(3000).map(|v| 1000 + v % 5000).collect(),
            ),
            ("wide", random(5).take(3000).collect()),
            ("sorted", (0..3000u64).map(|v| v * 3 + 17).collect()),
            ("constant", vec![0x1234_5678_9abc_def0; 3000]),
            (
                "few",
                random(6)
                    .take(3000)
                    .map(|v| [3, 99, 12345, 7][(v % 4) as usize])
                    .collect(),
            ),
        ];
        for (name, values) in patterns {
            let bytes = values
                .iter()
                .flat_map(|value| value.to_le_bytes()[..width].to_vec())
                .collect();
            cases.push((
                format!("numeric{}-{name}", width * 8),
                Output::Numeric { width, bytes },
            ));
        }
    }

    for width in [3usize, 4, 12] {
        let bytes = random(7)
            .take(2000 * width)
            .enumerate()
            .map(|(i, v)| {
                if i % width == 0 {
                    v as u8
                } else {
                    (i % width) as u8
                }
            })
            .collect();
        cases.push((format!("struct{width}"), Output::Struct { width, bytes }));
    }

    let strings = ["alpha", "", "beta", "gamma", "delta", "123", "45678"]
        .iter()
        .cycle()
        .take(1500)
        .copied()
        .collect::<Vec<_>>();
    cases.push((
        "string".into(),
        Output::String {
            bytes: strings.concat().into_bytes(),
            lengths: strings.iter().map(|s| s.len() as u32).collect(),
        },
    ));
    cases
}

fn input(output: &Output) -> Input<'_> {
    match output {
        Output::Serial(bytes) => Input::Serial(bytes),
        Output::Struct { width, bytes } => Input::Struct {
            width: *width,
            bytes,
        },
        Output::Numeric { width, bytes } => Input::Numeric {
            width: *width,
            bytes,
        },
        Output::String { bytes, lengths } => Input::String { bytes, lengths },
        _ => unreachable!("the sweep builds no other outputs"),
    }
}

/// Every standard graph, then node chains that fit the input type. Serial
/// input reaches numeric nodes through a conversion, which works in every
/// format version, where typed inputs need v14.
fn pipelines(output: &Output) -> Vec<(Vec<Node>, Graph)> {
    let mut pipelines = GRAPHS
        .iter()
        .map(|&graph| (Vec::new(), graph))
        .collect::<Vec<_>>();
    match output {
        Output::Serial(_) => {
            for width in [1, 2, 4, 8] {
                for chain in NUMERIC_CHAINS {
                    let mut nodes = vec![Node::SerialToNumLe(width)];
                    nodes.extend(chain);
                    pipelines.push((nodes.clone(), Graph::Store));
                    nodes.push(Node::NumToSerialLe);
                    pipelines.push((nodes, Graph::Zstd));
                }
            }
            for bits in BITUNPACK_WIDTHS {
                pipelines.push((vec![Node::Bitunpack(bits)], Graph::Store));
            }
            for node in DEPRECATED_SERIAL_NODES {
                pipelines.push((vec![node], Graph::Store));
            }
            for width in [2, 4, 8] {
                for node in DEPRECATED_STRUCT_NODES {
                    pipelines.push((vec![Node::SerialToStruct(width), node], Graph::Store));
                }
            }
        }
        Output::Numeric { .. } => {
            for chain in NUMERIC_CHAINS {
                pipelines.push((chain.to_vec(), Graph::Store));
            }
        }
        Output::Struct { .. } => {
            for node in DEPRECATED_STRUCT_NODES {
                pipelines.push((vec![node], Graph::Store));
            }
        }
        _ => {}
    }
    pipelines
}

#[test]
fn every_format_version_decodes() {
    let mut frames = 0;
    let mut failures = Vec::new();
    for version in openzl_shim::min_format_version()..=openzl_shim::max_format_version() {
        for (name, expected) in cases() {
            for (nodes, graph) in pipelines(&expected) {
                let compress_options = CompressOptions {
                    graph,
                    format_version: version,
                    // Keep every node, even where it expands the data.
                    store_on_expansion: false,
                    ..CompressOptions::default()
                };
                // Upstream rejects graphs that do not fit the input type,
                // its values or the format version.
                let Ok(frame) = compress_pipeline(&[input(&expected)], &nodes, compress_options)
                else {
                    continue;
                };
                frames += 1;
                match ozlrip::decode_outputs(&frame) {
                    Ok(outputs) if outputs == [expected.clone()] => {}
                    Ok(_) => failures.push(format!(
                        "v{version} {nodes:?} {graph:?} {name}: wrong output"
                    )),
                    Err(err) => {
                        failures.push(format!("v{version} {nodes:?} {graph:?} {name}: {err}"))
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {frames} frames failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(frames > 12_000, "{frames} frames");
}

/// Inputs large enough for the deprecated LZ nodes to split their sequences
/// into several entropy blocks, with Huffman-coded 16-bit tokens.
#[test]
fn deprecated_lz_nodes_decode_large_inputs() {
    let words = (0..500)
        .map(|i| format!("w{i}x").into_bytes())
        .collect::<Vec<_>>();
    let mut picks = random(9);
    let mut input = Vec::new();
    while input.len() < 1 << 20 {
        input.extend_from_slice(&words[(picks.next().unwrap() % 500) as usize]);
        input.push(b' ');
    }
    for version in openzl_shim::min_format_version()..=12 {
        for node in &DEPRECATED_SERIAL_NODES[..2] {
            let options = CompressOptions {
                graph: Graph::Store,
                format_version: version,
                ..CompressOptions::default()
            };
            let frame = compress_pipeline(&[Input::Serial(&input)], &[*node], options).unwrap();
            let decoded =
                ozlrip::decode(&frame).unwrap_or_else(|err| panic!("v{version} {node:?}: {err}"));
            assert!(decoded == input, "v{version} {node:?}");
        }
    }
}
