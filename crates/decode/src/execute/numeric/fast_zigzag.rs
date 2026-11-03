use alloc::vec::Vec;

pub(super) fn decode_numeric(input: &[u8], element_width: usize, output: &mut Vec<u8>) {
    match element_width {
        1 => {
            for &encoded in input {
                let mask = 0u8.wrapping_sub(encoded & 1);
                output.push((encoded >> 1) ^ mask);
            }
        }
        2 => {
            for encoded in input.as_chunks::<2>().0 {
                let value = u16::from_le_bytes(*encoded);
                let mask = 0u16.wrapping_sub(value & 1);
                output.extend_from_slice(&((value >> 1) ^ mask).to_le_bytes());
            }
        }
        4 => {
            for encoded in input.as_chunks::<4>().0 {
                let value = u32::from_le_bytes(*encoded);
                let mask = 0u32.wrapping_sub(value & 1);
                output.extend_from_slice(&((value >> 1) ^ mask).to_le_bytes());
            }
        }
        8 => {
            for encoded in input.as_chunks::<8>().0 {
                let value = u64::from_le_bytes(*encoded);
                let mask = 0u64.wrapping_sub(value & 1);
                output.extend_from_slice(&((value >> 1) ^ mask).to_le_bytes());
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
}
