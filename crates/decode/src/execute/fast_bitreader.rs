#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]
#![allow(
    clippy::cast_ptr_alignment,
    reason = "fast bit readers use read_unaligned on byte-derived pointers"
)]

pub(super) fn read_window(bytes: &[u8], byte_pos: usize, needed_bytes: usize) -> Option<u128> {
    #[cfg(not(feature = "paranoid"))]
    {
        if let Some(value) = read_window_fast(bytes, byte_pos, needed_bytes) {
            return Some(value);
        }
    }
    read_window_safe(bytes, byte_pos, needed_bytes)
}

#[cfg(not(feature = "paranoid"))]
pub(super) fn read_window_u32(bytes: &[u8], byte_pos: usize, needed_bytes: usize) -> Option<u32> {
    let remaining = bytes.len().checked_sub(byte_pos)?;
    if needed_bytes <= 4 && remaining >= 4 {
        let ptr = bytes.as_ptr().wrapping_add(byte_pos).cast::<u32>();
        unsafe {
            return Some(u32::from_le(core::ptr::read_unaligned(ptr)));
        }
    }

    let byte_end = byte_pos.checked_add(needed_bytes)?;
    let bytes = bytes.get(byte_pos..byte_end)?;
    let mut value = 0u32;
    for (shift, &byte) in bytes.iter().enumerate() {
        value |= u32::from(byte) << (shift * 8);
    }
    Some(value)
}

#[cfg(feature = "paranoid")]
pub(super) fn read_window_u32(bytes: &[u8], byte_pos: usize, needed_bytes: usize) -> Option<u32> {
    if needed_bytes <= 4
        && let Some(bytes) = bytes.get(byte_pos..byte_pos.checked_add(4)?)
    {
        return Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    }

    let byte_end = byte_pos.checked_add(needed_bytes)?;
    let bytes = bytes.get(byte_pos..byte_end)?;
    let mut value = 0u32;
    for (shift, &byte) in bytes.iter().enumerate() {
        value |= u32::from(byte) << (shift * 8);
    }
    Some(value)
}

fn read_window_safe(bytes: &[u8], byte_pos: usize, needed_bytes: usize) -> Option<u128> {
    let byte_end = byte_pos.checked_add(needed_bytes)?;
    let bytes = bytes.get(byte_pos..byte_end)?;
    let mut value = 0u128;
    for (shift, &byte) in bytes.iter().enumerate() {
        value |= u128::from(byte) << (shift * 8);
    }
    Some(value)
}

#[cfg(not(feature = "paranoid"))]
fn read_window_fast(bytes: &[u8], byte_pos: usize, needed_bytes: usize) -> Option<u128> {
    let remaining = bytes.len().checked_sub(byte_pos)?;
    if needed_bytes <= 8 && remaining >= 8 {
        let ptr = bytes.as_ptr().wrapping_add(byte_pos).cast::<u64>();
        unsafe {
            return Some(u128::from(u64::from_le(core::ptr::read_unaligned(ptr))));
        }
    }
    if needed_bytes <= 16 && remaining >= 16 {
        let ptr = bytes.as_ptr().wrapping_add(byte_pos).cast::<u128>();
        unsafe {
            return Some(u128::from_le(core::ptr::read_unaligned(ptr)));
        }
    }
    None
}
