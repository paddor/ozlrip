//! Nodes that take stale pooled buffers must overwrite every output byte, or
//! bytes from an earlier stream leak into the output.

use super::*;
use crate::execute::numeric::decode_bitpack_int_chunk;

/// `len` bytes that vary, starting from `seed`.
fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .scan(seed, |byte, _| {
            *byte = byte.wrapping_mul(5).wrapping_add(3);
            Some(*byte)
        })
        .collect()
}

/// Runs `node` with an empty pool, then with a pool whose one buffer holds
/// stale bytes, shorter and longer than the output, and checks that every
/// run decodes the same bytes.
fn assert_overwrites_stale_buffer(
    name: &str,
    mut node: impl FnMut(&mut DecodeScratch) -> Result<OwnedStream>,
) {
    let fresh = node(&mut DecodeScratch::new()).unwrap();
    let len = fresh.bytes.len();
    assert_ne!(len, 0, "{name}");
    for stale_len in [len / 2, len + 7] {
        let mut stale = Vec::with_capacity(len + 7);
        stale.resize(stale_len, 0xa5);
        let mut scratch = DecodeScratch::new();
        scratch.recycle_byte_buffer(stale);

        let output = node(&mut scratch).unwrap();

        assert_eq!(output.bytes.capacity(), len + 7, "{name}: pool unused");
        assert_eq!(
            output.bytes, fresh.bytes,
            "{name}, stale length {stale_len}"
        );
        assert_eq!(output.element_width, fresh.element_width, "{name}");
    }
}

fn input(bytes: &[u8], element_width: usize) -> StreamInput<'_> {
    StreamInput {
        bytes,
        element_width,
        string_lengths: None,
    }
}

#[test]
fn delta_overwrites_stale_buffer() {
    for width in [1, 2, 4, 8] {
        let stored = data(13 * width, 1);
        let first = data(width, 2);
        assert_overwrites_stale_buffer(&format!("delta width {width}"), |scratch| {
            decode_delta_node(
                input(&stored, width),
                &first,
                21,
                Limits::default(),
                scratch,
            )
        });
    }
}

#[test]
fn transpose_overwrites_stale_buffer() {
    let source = data(4 * 13, 3);
    assert_overwrites_stale_buffer("transpose", |scratch| {
        decode_transpose_node(input(&source, 4), &[], Limits::default(), scratch)
    });
}

#[test]
fn transpose_split_overwrites_stale_buffer() {
    for width in [2, 3, 4, 8] {
        let lanes: Vec<Vec<u8>> = (0..width).map(|lane| data(13, lane)).collect();
        let inputs: Vec<StreamInput<'_>> = lanes.iter().map(|lane| input(lane, 1)).collect();
        assert_overwrites_stale_buffer(&format!("transpose_split {width}"), |scratch| {
            decode_transpose_split_node(&inputs, 0, &[], Limits::default(), scratch)
        });
    }
}

#[test]
fn bitpack_overwrites_stale_buffer() {
    let stored = data(23, 4);
    for (width_log, bits) in [(0, 3), (0, 8), (1, 5), (1, 16), (2, 17), (3, 40), (3, 60)] {
        let header = [(width_log << 6) | (bits - 1)];
        assert_overwrites_stale_buffer(&format!("bitpack {width_log} {bits}"), |scratch| {
            decode_bitpack_int_chunk(&stored, &header, Limits::default(), scratch)
        });
    }
}

#[test]
fn tokenize_overwrites_stale_buffer() {
    for element_width in [1, 2, 3, 4, 8] {
        let alphabet = data(5 * element_width, 5);
        for index_width in [1, 2, 4, 8] {
            let indices: Vec<u8> = (0..13u64)
                .flat_map(|index| (index * 3 % 5).to_le_bytes()[..index_width].to_vec())
                .collect();
            let name = format!("tokenize {element_width} {index_width}");
            assert_overwrites_stale_buffer(&name, |scratch| {
                decode_tokenize_fixed_node(
                    &[
                        input(&alphabet, element_width),
                        input(&indices, index_width),
                    ],
                    &[],
                    Limits::default(),
                    scratch,
                )
            });
        }
    }
}
