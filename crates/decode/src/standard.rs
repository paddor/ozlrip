use ozlrip_core::{Error, ErrorKind, Result};

pub(crate) const LZ4_ID: u32 = 62;
pub(crate) const ZSTD_ID: u32 = 22;
pub(crate) const DELTA_INT_ID: u32 = 1;
pub(crate) const CONCAT_SERIAL_ID: u32 = 55;
pub(crate) const SPLITN_ID: u32 = 40;
pub(crate) const BITPACK_SERIAL_ID: u32 = 27;
pub(crate) const BITPACK_INT_ID: u32 = 28;
pub(crate) const BITUNPACK_ID: u32 = 34;
pub(crate) const RANGE_PACK_ID: u32 = 35;
pub(crate) const TOKENIZE_FIXED_ID: u32 = 36;
pub(crate) const TOKENIZE_NUMERIC_ID: u32 = 37;
pub(crate) const SPLIT_BY_STRUCT_ID: u32 = 41;
pub(crate) const DISPATCH_N_BY_TAG_ID: u32 = 42;
pub(crate) const CONSTANT_SERIAL_ID: u32 = 44;
pub(crate) const CONSTANT_FIXED_ID: u32 = 45;
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
pub(crate) const SENTINEL_ID: u32 = 18;
pub(crate) const LZ_ID: u32 = 19;
pub(crate) const FIELD_LZ_ID: u32 = 24;
pub(crate) const QUANTIZE_OFFSETS_ID: u32 = 25;
pub(crate) const QUANTIZE_LENGTHS_ID: u32 = 26;
pub(crate) const PARTITION_ID: u32 = 64;
pub(crate) const FLATPACK_ID: u32 = 29;
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
pub(crate) const FSE_NCOUNT_ID: u32 = 52;
pub(crate) const DIVIDE_BY_ID: u32 = 53;
pub(crate) const PIVCO_HUFFMAN_ID: u32 = 67;

pub(crate) fn validate_transform_id(id: u32, format_version: u32) -> Result<()> {
    let Some(min_version) = min_version(id) else {
        return Err(
            Error::new(ErrorKind::Unsupported).with_detail("unknown OpenZL standard transform ID")
        );
    };
    if format_version < min_version {
        return Err(Error::new(ErrorKind::Unsupported)
            .with_detail("standard transform ID is not available in this format version"));
    }
    Ok(())
}

const fn min_version(id: u32) -> Option<u32> {
    match id {
        1..=3 | 5..=10 | 15..=17 | 20..=32 => Some(3),
        33 => Some(4),
        34 => Some(6),
        35..=37 => Some(8),
        40..=43 => Some(9),
        11 | 12 | 38 | 44..=46 => Some(11),
        4 | 47 | 48 => Some(14),
        49..=52 => Some(15),
        53..=56 => Some(16),
        57 | 58 => Some(17),
        59 => Some(18),
        60 => Some(19),
        61 => Some(20),
        13 | 14 => Some(21),
        62 => Some(23),
        18 | 19 | 63..=65 => Some(24),
        66 => Some(26),
        67 => Some(27),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
