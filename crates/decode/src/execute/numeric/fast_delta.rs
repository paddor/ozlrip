use alloc::vec::Vec;

/// Replaces `output` with the decoded elements. `output` may hold stale
/// bytes: every byte is overwritten.
pub(super) fn decode_delta_elements(
    stored: &[u8],
    header: &[u8],
    element_width: usize,
    output_len: usize,
    output: &mut Vec<u8>,
) {
    if element_width == 1 {
        // Extending from a mapped slice iterator writes each byte once:
        // no zero fill and no per-byte bounds check.
        let mut previous = header[0];
        output.clear();
        output.push(previous);
        output.extend(stored.iter().map(|&delta| {
            previous = previous.wrapping_add(delta);
            previous
        }));
        return;
    }
    // The zip loops below write every byte only when the lengths match.
    debug_assert_eq!(header.len() + stored.len(), output_len);
    debug_assert!(stored.len().is_multiple_of(element_width));
    output.resize(output_len, 0);
    output[..element_width].copy_from_slice(header);
    match element_width {
        2 => {
            let mut previous = u16::from_le_bytes([header[0], header[1]]);
            for (out, delta) in output[2..]
                .as_chunks_mut::<2>()
                .0
                .iter_mut()
                .zip(stored.as_chunks::<2>().0)
            {
                previous = previous.wrapping_add(u16::from_le_bytes(*delta));
                out.copy_from_slice(&previous.to_le_bytes());
            }
        }
        4 => {
            let mut previous = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            for (out, delta) in output[4..]
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(stored.as_chunks::<4>().0)
            {
                previous = previous.wrapping_add(u32::from_le_bytes(*delta));
                out.copy_from_slice(&previous.to_le_bytes());
            }
        }
        8 => {
            let mut previous = u64::from_le_bytes([
                header[0], header[1], header[2], header[3], header[4], header[5], header[6],
                header[7],
            ]);
            for (out, delta) in output[8..]
                .as_chunks_mut::<8>()
                .0
                .iter_mut()
                .zip(stored.as_chunks::<8>().0)
            {
                previous = previous.wrapping_add(u64::from_le_bytes(*delta));
                out.copy_from_slice(&previous.to_le_bytes());
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
}
