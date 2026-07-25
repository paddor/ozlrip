use alloc::vec::Vec;

use ozlrip_core::{Error, ErrorKind, Result};

use crate::dict::DictionaryStore;

use super::OwnedStream;

#[derive(Default)]
pub(crate) struct DecodeScratch {
    byte_buffers: Vec<Vec<u8>>,
}

impl DecodeScratch {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(super) fn take_byte_buffer(
        &mut self,
        capacity: usize,
        detail: &'static str,
    ) -> Result<Vec<u8>> {
        if let Some(index) = self
            .byte_buffers
            .iter()
            .position(|buffer| buffer.capacity() >= capacity)
        {
            let mut buffer = self.byte_buffers.swap_remove(index);
            buffer.clear();
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

    pub(super) fn recycle_byte_buffer(&mut self, mut buffer: Vec<u8>) {
        buffer.clear();
        self.byte_buffers.push(buffer);
    }
}

pub(crate) struct DecodeRuntime<'a> {
    pub(super) scratch: &'a mut DecodeScratch,
    #[cfg_attr(not(feature = "zstd"), allow(dead_code))]
    pub(super) dict_store: &'a mut DictionaryStore,
    #[cfg(feature = "zstd")]
    pub(super) zstd: &'a mut zrip::DecompressContext,
}

impl<'a> DecodeRuntime<'a> {
    pub(crate) fn new(
        scratch: &'a mut DecodeScratch,
        dict_store: &'a mut DictionaryStore,
        #[cfg(feature = "zstd")] zstd: &'a mut zrip::DecompressContext,
    ) -> Self {
        Self {
            scratch,
            dict_store,
            #[cfg(feature = "zstd")]
            zstd,
        }
    }
}
