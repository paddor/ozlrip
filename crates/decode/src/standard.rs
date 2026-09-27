use alloc::format;

use ozlrip_core::{Error, ErrorKind, Result};

pub(crate) const LZ4_ID: u32 = 62;
pub(crate) const ZSTD_ID: u32 = 22;
pub(crate) const ZSTD_FIXED_ID: u32 = 23;
pub(crate) const DELTA_INT_ID: u32 = 1;
pub(crate) const TRANSPOSE_ID: u32 = 2;
pub(crate) const CONCAT_SERIAL_ID: u32 = 55;
pub(crate) const SPLITN_ID: u32 = 40;
pub(crate) const BITPACK_SERIAL_ID: u32 = 27;
pub(crate) const BITPACK_INT_ID: u32 = 28;
pub(crate) const BITUNPACK_ID: u32 = 34;
pub(crate) const RANGE_PACK_ID: u32 = 35;
pub(crate) const TOKENIZE_FIXED_ID: u32 = 36;
pub(crate) const TOKENIZE_NUMERIC_ID: u32 = 37;
pub(crate) const TOKENIZE_STRING_ID: u32 = 38;
pub(crate) const SPLIT_BY_STRUCT_ID: u32 = 41;
pub(crate) const DISPATCH_N_BY_TAG_ID: u32 = 42;
pub(crate) const MERGE_SORTED_ID: u32 = 43;
pub(crate) const CONSTANT_SERIAL_ID: u32 = 44;
pub(crate) const CONSTANT_FIXED_ID: u32 = 45;
pub(crate) const PREFIX_ID: u32 = 46;
pub(crate) const DISPATCH_STRING_ID: u32 = 54;
pub(crate) const CONVERT_SERIAL_TO_STRUCT_ID: u32 = 5;
pub(crate) const CONVERT_STRUCT_TO_SERIAL_ID: u32 = 6;
pub(crate) const CONVERT_STRUCT_TO_NUM_LE_ID: u32 = 7;
pub(crate) const CONVERT_NUM_TO_STRUCT_LE_ID: u32 = 8;
pub(crate) const CONVERT_SERIAL_TO_NUM_LE_ID: u32 = 9;
pub(crate) const CONVERT_NUM_TO_SERIAL_LE_ID: u32 = 10;
pub(crate) const CONVERT_STRING_TO_SERIAL_ID: u32 = 11;
pub(crate) const SEPARATE_STRING_COMPONENTS_ID: u32 = 12;
pub(crate) const CONVERT_STRUCT_TO_NUM_BE_ID: u32 = 13;
pub(crate) const CONVERT_SERIAL_TO_NUM_BE_ID: u32 = 14;
pub(crate) const FSE_DEPRECATED_ID: u32 = 15;
pub(crate) const HUFFMAN_DEPRECATED_ID: u32 = 16;
pub(crate) const HUFFMAN_FIXED_DEPRECATED_ID: u32 = 17;
pub(crate) const SENTINEL_ID: u32 = 18;
pub(crate) const LZ_ID: u32 = 19;
pub(crate) const ROLZ_DEPRECATED_ID: u32 = 20;
pub(crate) const FASTLZ_DEPRECATED_ID: u32 = 21;
pub(crate) const FIELD_LZ_ID: u32 = 24;
pub(crate) const QUANTIZE_OFFSETS_ID: u32 = 25;
pub(crate) const QUANTIZE_LENGTHS_ID: u32 = 26;
pub(crate) const PARTITION_ID: u32 = 64;
pub(crate) const FLATPACK_ID: u32 = 29;
pub(crate) const FLOAT_DECONSTRUCT_ID: u32 = 33;
pub(crate) const ZIGZAG_ID: u32 = 3;
pub(crate) const TRANSPOSE_SPLIT_ID: u32 = 4;
pub(crate) const CONCAT_NUM_ID: u32 = 57;
pub(crate) const CONCAT_STRUCT_ID: u32 = 58;
pub(crate) const PARSE_INT_ID: u32 = 60;
pub(crate) const TRANSPOSE_SPLIT2_ID: u32 = 30;
pub(crate) const TRANSPOSE_SPLIT4_ID: u32 = 31;
pub(crate) const TRANSPOSE_SPLIT8_ID: u32 = 32;
pub(crate) const SPLITN_STRUCT_ID: u32 = 47;
pub(crate) const SPLITN_NUM_ID: u32 = 48;
pub(crate) const SPARSE_NUM_ID: u32 = 66;
pub(crate) const BIT_SPLIT_ID: u32 = 63;
pub(crate) const MUX_LENGTHS_ID: u32 = 65;
pub(crate) const FSE_V2_ID: u32 = 49;
pub(crate) const HUFFMAN_V2_ID: u32 = 50;
pub(crate) const HUFFMAN_STRUCT_V2_ID: u32 = 51;
pub(crate) const FSE_NCOUNT_ID: u32 = 52;
pub(crate) const DIVIDE_BY_ID: u32 = 53;
pub(crate) const DEDUP_NUM_ID: u32 = 56;
pub(crate) const CONCAT_STRING_ID: u32 = 59;
pub(crate) const INTERLEAVE_STRING_ID: u32 = 61;
pub(crate) const PIVCO_HUFFMAN_ID: u32 = 67;

/// How many streams a standard node reads and regenerates when decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NodeShape {
    /// Streams the node always reads.
    pub(crate) static_inputs: usize,
    /// Whether the frame may give the node more inputs than `static_inputs`.
    pub(crate) variable_inputs: bool,
    pub(crate) min_outputs: usize,
    /// `None` when the node regenerates any number of outputs.
    pub(crate) max_outputs: Option<usize>,
}

/// A standard transform: its ID, upstream name, the format versions that
/// register it, and its shape.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StandardNode {
    pub(crate) id: u32,
    pub(crate) name: &'static str,
    pub(crate) min_version: u32,
    /// Last format version that registers a deprecated node.
    pub(crate) max_version: Option<u32>,
    pub(crate) shape: NodeShape,
}

const fn fixed(inputs: usize, outputs: usize) -> NodeShape {
    NodeShape {
        static_inputs: inputs,
        variable_inputs: false,
        min_outputs: outputs,
        max_outputs: Some(outputs),
    }
}

/// `static_inputs` plus any number of variable inputs, one output.
const fn variable(static_inputs: usize) -> NodeShape {
    NodeShape {
        static_inputs,
        variable_inputs: true,
        min_outputs: 1,
        max_outputs: Some(1),
    }
}

/// Fixed inputs, one or more outputs.
const fn fan_out(static_inputs: usize) -> NodeShape {
    NodeShape {
        static_inputs,
        variable_inputs: false,
        min_outputs: 1,
        max_outputs: None,
    }
}

const fn node(id: u32, name: &'static str, min_version: u32, shape: NodeShape) -> StandardNode {
    StandardNode {
        id,
        name,
        min_version,
        max_version: None,
        shape,
    }
}

const fn deprecated(
    id: u32,
    name: &'static str,
    min_version: u32,
    max_version: u32,
    shape: NodeShape,
) -> StandardNode {
    StandardNode {
        id,
        name,
        min_version,
        max_version: Some(max_version),
        shape,
    }
}

/// Every standard transform ozlrip knows, by ID. Version ranges follow
/// upstream `src/openzl/codecs/decoder_registry.c`.
pub(crate) const STANDARD_NODES: [StandardNode; 66] = [
    node(DELTA_INT_ID, "delta_int", 3, fixed(1, 1)),
    node(TRANSPOSE_ID, "transpose", 3, fixed(1, 1)),
    node(ZIGZAG_ID, "zigzag", 3, fixed(1, 1)),
    node(TRANSPOSE_SPLIT_ID, "transpose_split", 11, variable(0)),
    node(
        CONVERT_SERIAL_TO_STRUCT_ID,
        "convert_serial_to_struct",
        3,
        fixed(1, 1),
    ),
    node(
        CONVERT_STRUCT_TO_SERIAL_ID,
        "convert_struct_to_serial",
        3,
        fixed(1, 1),
    ),
    node(
        CONVERT_STRUCT_TO_NUM_LE_ID,
        "convert_struct_to_num_le",
        3,
        fixed(1, 1),
    ),
    node(
        CONVERT_NUM_TO_STRUCT_LE_ID,
        "convert_num_to_struct_le",
        3,
        fixed(1, 1),
    ),
    node(
        CONVERT_SERIAL_TO_NUM_LE_ID,
        "convert_serial_to_num_le",
        3,
        fixed(1, 1),
    ),
    node(
        CONVERT_NUM_TO_SERIAL_LE_ID,
        "convert_num_to_serial_le",
        3,
        fixed(1, 1),
    ),
    node(
        CONVERT_STRING_TO_SERIAL_ID,
        "convert_string_to_serial",
        10,
        fixed(1, 1),
    ),
    node(
        SEPARATE_STRING_COMPONENTS_ID,
        "separate_string_components",
        10,
        fixed(2, 1),
    ),
    node(
        CONVERT_STRUCT_TO_NUM_BE_ID,
        "convert_struct_to_num_be",
        21,
        fixed(1, 1),
    ),
    node(
        CONVERT_SERIAL_TO_NUM_BE_ID,
        "convert_serial_to_num_be",
        21,
        fixed(1, 1),
    ),
    deprecated(FSE_DEPRECATED_ID, "fse_deprecated", 3, 14, fixed(1, 1)),
    deprecated(
        HUFFMAN_DEPRECATED_ID,
        "huffman_deprecated",
        3,
        14,
        fixed(1, 1),
    ),
    deprecated(
        HUFFMAN_FIXED_DEPRECATED_ID,
        "huffman_fixed_deprecated",
        3,
        14,
        fixed(1, 1),
    ),
    node(SENTINEL_ID, "sentinel", 24, fixed(2, 1)),
    node(LZ_ID, "lz", 24, fixed(4, 1)),
    deprecated(ROLZ_DEPRECATED_ID, "rolz_deprecated", 3, 12, fixed(1, 1)),
    deprecated(
        FASTLZ_DEPRECATED_ID,
        "fastlz_deprecated",
        3,
        12,
        fixed(1, 1),
    ),
    node(ZSTD_ID, "zstd", 3, fixed(1, 1)),
    deprecated(ZSTD_FIXED_ID, "zstd_fixed_legacy", 3, 10, fixed(1, 1)),
    node(FIELD_LZ_ID, "field_lz", 3, fixed(5, 1)),
    node(QUANTIZE_OFFSETS_ID, "quantize_offsets", 3, fixed(2, 1)),
    node(QUANTIZE_LENGTHS_ID, "quantize_lengths", 3, fixed(2, 1)),
    node(BITPACK_SERIAL_ID, "bitpack_serial", 3, fixed(1, 1)),
    node(BITPACK_INT_ID, "bitpack_int", 3, fixed(1, 1)),
    node(FLATPACK_ID, "flatpack", 3, fixed(2, 1)),
    node(TRANSPOSE_SPLIT2_ID, "transpose_split2", 3, fixed(2, 1)),
    node(TRANSPOSE_SPLIT4_ID, "transpose_split4", 3, fixed(4, 1)),
    node(TRANSPOSE_SPLIT8_ID, "transpose_split8", 3, fixed(8, 1)),
    node(FLOAT_DECONSTRUCT_ID, "float_deconstruct", 4, fixed(2, 1)),
    node(BITUNPACK_ID, "bitunpack", 6, fixed(1, 1)),
    node(RANGE_PACK_ID, "range_pack", 8, fixed(1, 1)),
    node(TOKENIZE_FIXED_ID, "tokenize_fixed", 8, fixed(2, 1)),
    node(TOKENIZE_NUMERIC_ID, "tokenize_numeric", 8, fixed(2, 1)),
    node(TOKENIZE_STRING_ID, "tokenize_string", 11, fixed(2, 1)),
    node(SPLITN_ID, "splitn", 9, variable(0)),
    node(SPLIT_BY_STRUCT_ID, "split_by_struct", 9, variable(0)),
    node(DISPATCH_N_BY_TAG_ID, "dispatch_n_by_tag", 9, variable(2)),
    node(MERGE_SORTED_ID, "merge_sorted", 9, fixed(2, 1)),
    node(CONSTANT_SERIAL_ID, "constant_serial", 11, fixed(1, 1)),
    node(CONSTANT_FIXED_ID, "constant_fixed", 11, fixed(1, 1)),
    node(PREFIX_ID, "prefix", 11, fixed(2, 1)),
    node(SPLITN_STRUCT_ID, "splitn_struct", 14, variable(0)),
    node(SPLITN_NUM_ID, "splitn_num", 14, variable(0)),
    node(FSE_V2_ID, "fse_v2", 15, fixed(2, 1)),
    node(HUFFMAN_V2_ID, "huffman_v2", 15, fixed(2, 1)),
    node(HUFFMAN_STRUCT_V2_ID, "huffman_struct_v2", 15, fixed(2, 1)),
    node(FSE_NCOUNT_ID, "fse_ncount", 15, fixed(1, 1)),
    node(DIVIDE_BY_ID, "divide_by", 16, fixed(1, 1)),
    node(DISPATCH_STRING_ID, "dispatch_string", 16, variable(1)),
    node(CONCAT_SERIAL_ID, "concat_serial", 16, fan_out(2)),
    node(DEDUP_NUM_ID, "dedup_num", 16, fan_out(1)),
    node(CONCAT_NUM_ID, "concat_num", 17, fan_out(2)),
    node(CONCAT_STRUCT_ID, "concat_struct", 17, fan_out(2)),
    node(CONCAT_STRING_ID, "concat_string", 18, fan_out(2)),
    node(PARSE_INT_ID, "parse_int", 19, fixed(1, 1)),
    node(INTERLEAVE_STRING_ID, "interleave_string", 20, fan_out(1)),
    node(LZ4_ID, "lz4", 23, fixed(1, 1)),
    node(BIT_SPLIT_ID, "bit_split", 24, variable(0)),
    node(PARTITION_ID, "partition", 24, fixed(2, 1)),
    node(MUX_LENGTHS_ID, "mux_lengths", 24, fixed(2, 2)),
    node(SPARSE_NUM_ID, "sparse_num", 26, fixed(2, 1)),
    node(PIVCO_HUFFMAN_ID, "pivco_huffman", 27, fixed(2, 1)),
];

/// Position in `STANDARD_NODES` of each ID below 128, the OpenZL standard
/// range; `u8::MAX` where no node has that ID.
const NODE_INDEX: [u8; 128] = node_index();

const fn node_index() -> [u8; 128] {
    let mut index = [u8::MAX; 128];
    let mut position = 0;
    while position < STANDARD_NODES.len() {
        let id = STANDARD_NODES[position].id as usize;
        assert!(index[id] == u8::MAX, "duplicate standard node ID");
        #[expect(clippy::cast_possible_truncation, reason = "the table has 66 rows")]
        {
            index[id] = position as u8;
        }
        position += 1;
    }
    index
}

/// The standard node with `id`, if ozlrip knows it.
pub(crate) fn standard_node(id: u32) -> Option<&'static StandardNode> {
    let position = *NODE_INDEX.get(usize::try_from(id).ok()?)?;
    STANDARD_NODES.get(usize::from(position))
}

pub(crate) fn validate_transform_id(id: u32, format_version: u32) -> Result<()> {
    let Some(node) = standard_node(id) else {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("unknown OpenZL standard transform ID")
        );
    };
    let too_new = node
        .max_version
        .is_some_and(|max_version| format_version > max_version);
    if format_version < node.min_version || too_new {
        return Err(Error::new(ErrorKind::Unsupported).with_detail(format!(
            "{} is not available in format version {format_version}",
            node.name
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[test]
    fn table_matches_the_node_coverage_manifest() {
        const MANIFEST: &str = include_str!("../../../tests/fixtures/standard-node-coverage.tsv");
        let rows = MANIFEST
            .lines()
            .skip(1)
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let fields = line.split('\t').collect::<Vec<_>>();
                assert_eq!(fields.len(), 3, "coverage row {line:?}");
                let id = fields[0].parse::<u32>().expect("numeric node ID");
                (id, fields[1])
            })
            .collect::<Vec<_>>();
        let table = STANDARD_NODES
            .iter()
            .map(|node| (node.id, node.name))
            .collect::<Vec<_>>();

        assert_eq!(table, rows);
    }

    #[test]
    fn finds_every_node_by_id() {
        for node in &STANDARD_NODES {
            assert_eq!(standard_node(node.id).map(|found| found.id), Some(node.id));
        }
        for id in [0, 39, 68, 127, 128, u32::MAX] {
            assert!(standard_node(id).is_none(), "id {id}");
        }
    }

    #[test]
    fn rejects_reserved_transform_zero() {
        let err = validate_transform_id(0, 26).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
    }

    #[test]
    fn enforces_standard_transform_min_version() {
        let err = validate_transform_id(66, 25).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        validate_transform_id(66, 26).unwrap();

        let err = validate_transform_id(67, 26).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Unsupported);
        validate_transform_id(67, 27).unwrap();
    }

    #[test]
    fn matches_upstream_minimum_versions() {
        for (id, first) in [(TRANSPOSE_SPLIT_ID, 11), (11, 10), (12, 10)] {
            validate_transform_id(id, first).unwrap();
            let err = validate_transform_id(id, first - 1).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Unsupported);
        }
    }

    #[test]
    fn rejects_deprecated_transforms_after_their_last_version() {
        for (id, last) in [
            (ZSTD_FIXED_ID, 10),
            (ROLZ_DEPRECATED_ID, 12),
            (FASTLZ_DEPRECATED_ID, 12),
            (FSE_DEPRECATED_ID, 14),
            (HUFFMAN_DEPRECATED_ID, 14),
            (HUFFMAN_FIXED_DEPRECATED_ID, 14),
        ] {
            validate_transform_id(id, last).unwrap();
            let err = validate_transform_id(id, last + 1).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::Unsupported);
        }
    }
}
