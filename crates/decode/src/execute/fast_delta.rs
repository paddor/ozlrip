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
            for (out, delta) in output[2..].chunks_exact_mut(2).zip(stored.chunks_exact(2)) {
                previous = previous.wrapping_add(u16::from_le_bytes([delta[0], delta[1]]));
                out.copy_from_slice(&previous.to_le_bytes());
            }
        }
        4 => {
            let mut previous = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            for (out, delta) in output[4..].chunks_exact_mut(4).zip(stored.chunks_exact(4)) {
                previous = previous
                    .wrapping_add(u32::from_le_bytes([delta[0], delta[1], delta[2], delta[3]]));
                out.copy_from_slice(&previous.to_le_bytes());
            }
        }
        8 => {
            let mut previous = u64::from_le_bytes([
                header[0], header[1], header[2], header[3], header[4], header[5], header[6],
                header[7],
            ]);
            for (out, delta) in output[8..].chunks_exact_mut(8).zip(stored.chunks_exact(8)) {
                previous = previous.wrapping_add(u64::from_le_bytes([
                    delta[0], delta[1], delta[2], delta[3], delta[4], delta[5], delta[6], delta[7],
                ]));
                out.copy_from_slice(&previous.to_le_bytes());
            }
        }
        _ => unreachable!("validate_numeric_stream_width accepted only supported widths"),
    }
}

#[cfg(not(feature = "paranoid"))]
fn decode_delta_1(stored: &[u8], first: u8, output: &mut Vec<u8>) {
    unsafe {
        let dst = output.as_mut_ptr();
        let src = stored.as_ptr();
        let mut previous = first;
        dst.write(previous);
        for index in 0..stored.len() {
            previous = previous.wrapping_add(src.add(index).read());
            dst.add(index + 1).write(previous);
        }
        output.set_len(stored.len() + 1);
    }
}

#[cfg(not(feature = "paranoid"))]
fn decode_delta_2(stored: &[u8], header: &[u8], output: &mut Vec<u8>) {
    let elements = stored.len() / 2;
    unsafe {
        let dst = output.as_mut_ptr();
        let src = stored.as_ptr();
        let mut previous = u16::from_le_bytes([header[0], header[1]]);
        (dst as *mut u16).write_unaligned(previous);
        for index in 0..elements {
            let delta_ptr = src.add(index * 2);
            let delta = (delta_ptr as *const u16).read_unaligned();
            previous = previous.wrapping_add(u16::from_le(delta));
            (dst.add((index + 1) * 2) as *mut u16).write_unaligned(previous.to_le());
        }
        output.set_len((elements + 1) * 2);
    }
}

#[cfg(not(feature = "paranoid"))]
fn decode_delta_4(stored: &[u8], header: &[u8], output: &mut Vec<u8>) {
    let elements = stored.len() / 4;
    unsafe {
        let dst = output.as_mut_ptr();
        let src = stored.as_ptr();
        let mut previous = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        (dst as *mut u32).write_unaligned(previous);
        for index in 0..elements {
            let delta_ptr = src.add(index * 4);
            let delta = (delta_ptr as *const u32).read_unaligned();
            previous = previous.wrapping_add(u32::from_le(delta));
            (dst.add((index + 1) * 4) as *mut u32).write_unaligned(previous.to_le());
        }
        output.set_len((elements + 1) * 4);
    }
}

#[cfg(not(feature = "paranoid"))]
fn decode_delta_8(stored: &[u8], header: &[u8], output: &mut Vec<u8>) {
    let elements = stored.len() / 8;
    unsafe {
        let dst = output.as_mut_ptr();
        let src = stored.as_ptr();
        let mut previous = u64::from_le_bytes([
            header[0], header[1], header[2], header[3], header[4], header[5], header[6], header[7],
        ]);
        (dst as *mut u64).write_unaligned(previous);
        for index in 0..elements {
            let delta_ptr = src.add(index * 8);
            let delta = (delta_ptr as *const u64).read_unaligned();
            previous = previous.wrapping_add(u64::from_le(delta));
            (dst.add((index + 1) * 8) as *mut u64).write_unaligned(previous.to_le());
        }
        output.set_len((elements + 1) * 8);
    }
}
