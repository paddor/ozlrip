#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

use alloc::vec::Vec;

#[cfg(not(feature = "paranoid"))]
pub(super) fn decode_delta_elements(
    stored: &[u8],
    header: &[u8],
    element_width: usize,
    output_len: usize,
    output: &mut Vec<u8>,
) {
    debug_assert!(output.is_empty());
    debug_assert!(output.capacity() >= output_len);
    match element_width {
        1 => decode_delta_1(stored, header[0], output),
        2 => decode_delta_2(stored, header, output),
        4 => decode_delta_4(stored, header, output),
        8 => decode_delta_8(stored, header, output),
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
}

#[cfg(feature = "paranoid")]
pub(super) fn decode_delta_elements(
    stored: &[u8],
    header: &[u8],
    element_width: usize,
    output_len: usize,
    output: &mut Vec<u8>,
) {
    output.resize(output_len, 0);
    output[..element_width].copy_from_slice(header);
    match element_width {
        1 => {
            let mut previous = header[0];
            for (index, &delta) in stored.iter().enumerate() {
                previous = previous.wrapping_add(delta);
                output[index + 1] = previous;
            }
        }
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

/// Writes the first byte and the running sum of `stored` to `output`,
/// replacing its contents.
#[cfg(not(feature = "paranoid"))]
fn decode_delta_1(stored: &[u8], first: u8, output: &mut Vec<u8>) {
    let len = stored.len() + 1;
    output.clear();
    output.reserve(len);
    let dst = output.as_mut_ptr();
    let mut previous = first;
    // SAFETY: `reserve` made room for `len` bytes from index 0.
    unsafe {
        dst.write(previous);
    }
    for (index, &delta) in stored.iter().enumerate() {
        previous = previous.wrapping_add(delta);
        // SAFETY: `index + 1 < len`.
        unsafe {
            dst.add(index + 1).write(previous);
        }
    }
    // SAFETY: the writes above initialized all `len` bytes.
    unsafe {
        output.set_len(len);
    }
}

/// Writes the first element from `header` and the running sum of the
/// little-endian elements in `stored` to `output`, replacing its contents.
macro_rules! decode_delta_wide {
    ($name:ident, $ty:ty, $width:literal) => {
        #[cfg(not(feature = "paranoid"))]
        fn $name(stored: &[u8], header: &[u8], output: &mut Vec<u8>) {
            let deltas = stored.as_chunks::<$width>().0;
            let len = (deltas.len() + 1) * $width;
            output.clear();
            output.reserve(len);
            let dst = output.as_mut_ptr();
            let first = header
                .first_chunk::<$width>()
                .expect("delta header holds one element");
            let mut previous = <$ty>::from_le_bytes(*first);
            // SAFETY: `reserve` made room for `len` bytes from index 0, and
            // this writes the first element.
            unsafe {
                dst.cast::<$ty>().write_unaligned(previous.to_le());
            }
            for (index, delta) in deltas.iter().enumerate() {
                previous = previous.wrapping_add(<$ty>::from_le_bytes(*delta));
                // SAFETY: element `index + 1` ends at
                // `(index + 2) * width <= len`.
                unsafe {
                    dst.add((index + 1) * $width)
                        .cast::<$ty>()
                        .write_unaligned(previous.to_le());
                }
            }
            // SAFETY: the writes above initialized all `len` bytes.
            unsafe {
                output.set_len(len);
            }
        }
    };
}

decode_delta_wide!(decode_delta_2, u16, 2);
decode_delta_wide!(decode_delta_4, u32, 4);
decode_delta_wide!(decode_delta_8, u64, 8);
