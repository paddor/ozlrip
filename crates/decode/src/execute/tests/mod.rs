#[cfg(feature = "lz4")]
use super::codecs::decode_lz4_chunk;
use super::decode_plan;
use super::dispatch::decode_dispatch_string_node_to_serial_output;
use super::dispatch::{decode_dispatch_n_by_tag_node, decode_dispatch_string_node};
use super::entropy;
use super::entropy::{
    decode_fse_deprecated_node, decode_fse_ncount_node, decode_fse_v2_node,
    decode_huffman_deprecated_node, decode_huffman_fixed_deprecated_node,
    decode_huffman_struct_v2_node, decode_huffman_v2_node,
};
use super::lz::{
    decode_fastlz_deprecated_node, decode_field_lz_node, decode_lz_node, decode_lz_node_to_output,
    decode_rolz_deprecated_node,
};
use super::node::execute_standard_node;
use super::numeric::{
    QUANTIZE_LENGTHS, QUANTIZE_OFFSETS, decode_bitunpack_node, decode_constant_fixed_chunk,
    decode_dedup_num_node, decode_delta_node, decode_divide_by_node, decode_partition_node,
    decode_quantize_node, decode_range_pack_node, decode_zigzag_numeric_chunk,
};
use super::runtime::StandardNodeContext;
use super::runtime::{DecodeRuntime, DecodeScratch};
use super::{layout::*, streams::*, strings::*};
use crate::dict::DictionaryStore;
use crate::info::FrameValueType;
use crate::parse::parse_frame_plan;
use crate::standard;
use alloc::vec::Vec;
use alloc::{format, vec};
use ozlrip_core::{ErrorKind, Limits, Result};
use ozlrip_test_support::standard_transform_serial_frame;
#[cfg(feature = "zstd")]
use ozlrip_test_support::{Chunk, FrameBuilder, Node};
use ozlrip_test_support::{bits_needed, magic, push_bitpacked_u32, push_var_u64};

struct StandardGraphNode<'a> {
    transform_id: u32,
    variable_inputs: u32,
    outputs: usize,
    header: &'a [u8],
}

fn standard_graph_serial_frame(
    version: u32,
    decoded_len: usize,
    nodes: &[StandardGraphNode<'_>],
    logical_stored_streams: &[&[u8]],
) -> Vec<u8> {
    let distances = nodes
        .iter()
        .flat_map(|node| (0..node.outputs).map(|distance| u32::try_from(distance).unwrap()))
        .collect::<Vec<_>>();
    standard_graph_serial_frame_with_distances(
        version,
        decoded_len,
        nodes,
        logical_stored_streams,
        &distances,
    )
}

fn standard_graph_serial_frame_with_distances(
    version: u32,
    decoded_len: usize,
    nodes: &[StandardGraphNode<'_>],
    logical_stored_streams: &[&[u8]],
    regen_distances: &[u32],
) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&magic(version));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    push_var_u64(&mut input, u64::try_from(nodes.len() + 1).unwrap());
    push_var_u64(
        &mut input,
        u64::try_from(logical_stored_streams.len()).unwrap(),
    );
    push_graph_nodes(&mut input, version, nodes);
    let regenerated = nodes.iter().map(|node| node.outputs).sum::<usize>();
    assert_eq!(regen_distances.len(), regenerated);
    let distance_bits = bits_needed(regenerated + logical_stored_streams.len());
    push_bitpacked_u32(&mut input, regen_distances, distance_bits);
    push_graph_payloads(&mut input, nodes, logical_stored_streams);
    input
}

/// Writes the per-node graph fields: transform types (all standard), transform
/// ids, header sizes, variable input counts and output counts.
fn push_graph_nodes(input: &mut Vec<u8>, version: u32, nodes: &[StandardGraphNode<'_>]) {
    push_bitpacked_u32(input, &vec![0; nodes.len()], 1);
    push_bitpacked_u32(
        input,
        &nodes
            .iter()
            .map(|node| node.transform_id)
            .collect::<Vec<_>>(),
        if version < 24 { 6 } else { 7 },
    );
    push_optional_node_values(input, nodes, |node| {
        (!node.header.is_empty()).then(|| u64::try_from(node.header.len() - 1).unwrap())
    });
    push_optional_node_values(input, nodes, |node| {
        (node.variable_inputs != 0).then(|| u64::from(node.variable_inputs - 1))
    });
    push_optional_node_values(input, nodes, |node| {
        (node.outputs != 1).then(|| u64::try_from(node.outputs - 2).unwrap())
    });
}

/// Writes one presence bit per node, then a varint for each node that has a
/// value.
fn push_optional_node_values(
    input: &mut Vec<u8>,
    nodes: &[StandardGraphNode<'_>],
    value: impl Fn(&StandardGraphNode<'_>) -> Option<u64>,
) {
    let values = nodes.iter().map(value).collect::<Vec<_>>();
    let present = values
        .iter()
        .map(|value| u32::from(value.is_some()))
        .collect::<Vec<_>>();
    push_bitpacked_u32(input, &present, 1);
    for value in values.into_iter().flatten() {
        push_var_u64(input, value);
    }
}

/// Writes the stored stream sizes, the node headers, the stored stream bytes
/// and the end marker. Stored streams go in reverse logical order.
fn push_graph_payloads(
    input: &mut Vec<u8>,
    nodes: &[StandardGraphNode<'_>],
    logical_stored_streams: &[&[u8]],
) {
    for stream in logical_stored_streams.iter().rev() {
        push_var_u64(input, u64::try_from(stream.len()).unwrap());
    }
    for node in nodes {
        input.extend_from_slice(node.header);
    }
    for stream in logical_stored_streams.iter().rev() {
        input.extend_from_slice(stream);
    }
    input.push(0);
}

fn legacy_entropy_raw_payload(payload: &[u8], element_width: usize) -> Vec<u8> {
    let decoded_elements = payload.len() / element_width;
    let mut output = Vec::new();
    output.push(3 | (u8::try_from(decoded_elements & 0x0f).unwrap() << 3));
    if decoded_elements > 0x0f {
        output[0] |= 0x80;
        push_var_u64(&mut output, u64::try_from(decoded_elements >> 4).unwrap());
    }
    output.extend_from_slice(payload);
    output
}

fn legacy_entropy_constant_payload(value: &[u8], decoded_elements: usize) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(2 | (u8::try_from(decoded_elements & 0x0f).unwrap() << 3));
    if decoded_elements > 0x0f {
        output[0] |= 0x80;
        push_var_u64(&mut output, u64::try_from(decoded_elements >> 4).unwrap());
    }
    output.extend_from_slice(value);
    output
}

fn legacy_entropy_bit_payload(values: &[u64], bits: u8) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(4 | (bits << 3));
    push_var_u64(&mut output, u64::try_from(values.len()).unwrap());
    output.extend_from_slice(&pack_lsb_values(values, bits));
    output
}

fn legacy_entropy_multi_payload(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut output = Vec::new();
    output.push(5 | (u8::try_from(blocks.len() & 0x0f).unwrap() << 3));
    if blocks.len() > 0x0f {
        output[0] |= 0x80;
        push_var_u64(&mut output, u64::try_from(blocks.len() >> 4).unwrap());
    }
    for block in blocks {
        output.extend_from_slice(block);
    }
    output
}

fn legacy_entropy_fse_payload(symbols: &[u8], nb_states: usize) -> Vec<u8> {
    let distribution = [16i16, 16];
    let accuracy_log = 5;
    let mut encoded =
        zrip_core::fse::table_builder::serialize_fse_table_description(&distribution, accuracy_log);
    encoded.extend_from_slice(&fse_multistate_bitstream(
        symbols,
        nb_states,
        &distribution,
        accuracy_log,
    ));
    legacy_compressed_entropy_payload(1, symbols.len(), &encoded)
}

fn legacy_compressed_entropy_payload(
    entropy_type: u8,
    decoded_elements: usize,
    encoded: &[u8],
) -> Vec<u8> {
    let needs_varints = decoded_elements > 0x1f || encoded.len() > 0x0f;
    let mut header = u16::from(entropy_type)
        | (u16::try_from(decoded_elements & 0x1f).unwrap() << 7)
        | (u16::try_from(encoded.len() & 0x0f).unwrap() << 12);
    if needs_varints {
        header |= 1 << 6;
    }

    let mut output = Vec::new();
    output.extend_from_slice(&header.to_le_bytes());
    if needs_varints {
        push_var_u64(&mut output, u64::try_from(decoded_elements >> 5).unwrap());
        push_var_u64(&mut output, u64::try_from(encoded.len() >> 4).unwrap());
    }
    output.extend_from_slice(encoded);
    output
}

fn fse_multistate_bitstream(
    symbols: &[u8],
    nb_states: usize,
    distribution: &[i16],
    accuracy_log: u8,
) -> Vec<u8> {
    assert!(matches!(nb_states, 2 | 4));
    assert!(symbols.len() >= nb_states);

    let table =
        zrip_core::fse::encode::FseEncodeTable::from_distribution(distribution, accuracy_log);
    let final_start = symbols.len() - nb_states;
    let mut states = (0..nb_states).map(|_| None).collect::<Vec<_>>();
    for index in final_start..symbols.len() {
        states[index % nb_states] = Some(zrip_core::fse::encode::FseEncodeState::init(
            &table,
            symbols[index],
        ));
    }

    let mut writer = zrip_core::bitstream::writer::BitWriter::new();
    for index in (0..final_start).rev() {
        states[index % nb_states]
            .as_mut()
            .unwrap()
            .encode_symbol(&mut writer, symbols[index]);
    }
    for lane in (0..nb_states).rev() {
        states[lane]
            .as_ref()
            .unwrap()
            .flush(&mut writer, accuracy_log);
    }
    writer.close_reverse_stream();
    writer.into_bytes()
}

#[cfg(feature = "zstd")]
fn zstd_stored_stream(decoded: &[u8]) -> Vec<u8> {
    let compressed = zrip::compress(decoded, 1).unwrap();
    let mut stored = Vec::new();
    push_var_u64(&mut stored, 1);
    stored.extend_from_slice(&compressed[4..]);
    stored
}

fn zigzag_delta_graph_frame(zigzag_encoded_deltas: &[u8], first: u8) -> Vec<u8> {
    let decoded_len = zigzag_encoded_deltas.len() + 1;
    let mut input = Vec::new();
    input.extend_from_slice(&magic(21));
    input.push(0);
    input.push(1);
    push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
    input.push(3);
    input.push(1);
    input.push(0);
    input.extend_from_slice(&[67, 0]);
    input.push(2);
    input.push(0);
    input.push(0);
    input.push(0);
    input.push(0);
    push_var_u64(
        &mut input,
        u64::try_from(zigzag_encoded_deltas.len()).unwrap(),
    );
    input.push(first);
    input.extend_from_slice(zigzag_encoded_deltas);
    input.push(0);
    input
}

fn pack_lsb_values(values: &[u64], bits: u8) -> Vec<u8> {
    let bits = usize::from(bits);
    let packed_len = (values.len() * bits).div_ceil(8);
    let mut output = vec![0; packed_len];
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    for (index, &value) in values.iter().enumerate() {
        let bit_offset = index * bits;
        let byte_offset = bit_offset / 8;
        let bit_shift = bit_offset % 8;
        let lane = u128::from(value & mask) << bit_shift;
        let lane_bytes = lane.to_le_bytes();
        let byte_count = (bit_shift + bits).div_ceil(8);
        for byte_index in 0..byte_count {
            output[byte_offset + byte_index] |= lane_bytes[byte_index];
        }
    }
    output
}

mod codecs;
mod entropy_coding;
mod frame;
mod layout;
mod lz;
mod numbers;
mod partitions;
mod strings;
mod typed_outputs;
