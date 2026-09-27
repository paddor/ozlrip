use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

use crate::dict::DictionaryStore;

use super::OwnedStream;

/// Most buffers the scratch pool keeps.
const MAX_POOLED_BUFFERS: usize = 64;

/// Most bytes of capacity the scratch pool keeps.
const MAX_POOLED_BYTES: usize = 64 << 20;

/// Byte buffers kept for reuse between nodes, chunks and decodes.
#[derive(Default)]
pub(crate) struct DecodeScratch {
    byte_buffers: Vec<Vec<u8>>,
    pooled_bytes: usize,
}

impl DecodeScratch {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Frees all pooled buffers.
    pub(crate) fn clear(&mut self) {
        self.byte_buffers = Vec::new();
        self.pooled_bytes = 0;
    }

    /// Returns an empty buffer with at least `capacity` bytes of capacity.
    pub(super) fn take_byte_buffer(
        &mut self,
        capacity: usize,
        detail: &'static str,
    ) -> Result<Vec<u8>> {
        // Best fit, so a small request does not take the buffer a later
        // large request needs.
        let best = self
            .byte_buffers
            .iter()
            .enumerate()
            .filter(|(_, buffer)| buffer.capacity() >= capacity)
            .min_by_key(|(_, buffer)| buffer.capacity())
            .map(|(index, _)| index);
        if let Some(index) = best {
            let buffer = self.byte_buffers.swap_remove(index);
            self.pooled_bytes -= buffer.capacity();
            return Ok(buffer);
        }

        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| Error::new(ErrorKind::LimitExceeded).with_detail(detail))?;
        Ok(buffer)
    }

    pub(super) fn recycle_owned_stream(&mut self, stream: OwnedStream) {
        if stream.recyclable {
            self.recycle_byte_buffer(stream.bytes);
        }
    }

    /// Keeps `buffer` for reuse, or frees it when the pool is full.
    pub(super) fn recycle_byte_buffer(&mut self, mut buffer: Vec<u8>) {
        let capacity = buffer.capacity();
        if capacity == 0
            || self.byte_buffers.len() == MAX_POOLED_BUFFERS
            || capacity > MAX_POOLED_BYTES - self.pooled_bytes
        {
            return;
        }
        buffer.clear();
        self.pooled_bytes += capacity;
        self.byte_buffers.push(buffer);
    }
}

pub(crate) struct DecodeRuntime<'a> {
    pub(super) scratch: &'a mut DecodeScratch,
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    pub(super) dict_store: &'a mut DictionaryStore,
    #[cfg(feature = "zstd")]
    pub(super) zstd: &'a mut zrip_decode::context::DecompressContext,
}

impl<'a> DecodeRuntime<'a> {
    pub(crate) fn new(
        scratch: &'a mut DecodeScratch,
        dict_store: &'a mut DictionaryStore,
        #[cfg(feature = "zstd")] zstd: &'a mut zrip_decode::context::DecompressContext,
    ) -> Self {
        Self {
            scratch,
            dict_store,
            #[cfg(feature = "zstd")]
            zstd,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_byte_buffer_picks_the_smallest_buffer_that_fits() {
        let mut scratch = DecodeScratch::new();
        scratch.recycle_byte_buffer(Vec::with_capacity(1000));
        scratch.recycle_byte_buffer(Vec::with_capacity(10));
        scratch.recycle_byte_buffer(Vec::with_capacity(100));

        assert_eq!(scratch.take_byte_buffer(5, "").unwrap().capacity(), 10);
        assert_eq!(scratch.take_byte_buffer(50, "").unwrap().capacity(), 100);
        assert_eq!(scratch.pooled_bytes, 1000);
    }

    #[test]
    fn recycle_byte_buffer_stops_at_the_buffer_cap() {
        let mut scratch = DecodeScratch::new();
        for _ in 0..=MAX_POOLED_BUFFERS {
            scratch.recycle_byte_buffer(Vec::with_capacity(16));
        }

        assert_eq!(scratch.byte_buffers.len(), MAX_POOLED_BUFFERS);
        assert_eq!(scratch.pooled_bytes, 16 * MAX_POOLED_BUFFERS);
    }

    #[test]
    fn recycle_byte_buffer_stops_at_the_byte_cap() {
        let mut scratch = DecodeScratch::new();
        scratch.recycle_byte_buffer(Vec::with_capacity(MAX_POOLED_BYTES - 8));
        scratch.recycle_byte_buffer(Vec::with_capacity(16));
        scratch.recycle_byte_buffer(Vec::with_capacity(8));

        assert_eq!(scratch.byte_buffers.len(), 2);
        assert_eq!(scratch.pooled_bytes, MAX_POOLED_BYTES);

        scratch.clear();
        assert_eq!((scratch.byte_buffers.len(), scratch.pooled_bytes), (0, 0));
    }
}
