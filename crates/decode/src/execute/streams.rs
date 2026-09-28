use alloc::vec::Vec;

#[derive(Clone, Copy)]
pub(super) struct BorrowedStream<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) element_width: usize,
}

#[derive(Clone, Copy)]
pub(super) struct StreamInput<'a> {
    pub(super) bytes: &'a [u8],
    pub(super) element_width: usize,
    pub(super) string_lengths: Option<&'a [u32]>,
}

#[derive(Debug)]
pub(super) struct OwnedStream {
    pub(super) bytes: Vec<u8>,
    pub(super) element_width: usize,
    pub(super) string_lengths: Option<Vec<u32>>,
    pub(super) recyclable: bool,
}

impl OwnedStream {
    /// Bytes this stream holds: its data plus four bytes per string length.
    /// Length, not capacity, so reused and fresh decoders count the same.
    pub(super) fn live_bytes(&self) -> usize {
        let lengths = self
            .string_lengths
            .as_ref()
            .map_or(0, |lengths| lengths.len().saturating_mul(4));
        self.bytes.len().saturating_add(lengths)
    }

    pub(super) fn serial(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            element_width: 1,
            string_lengths: None,
            recyclable: false,
        }
    }

    pub(super) fn strings(bytes: Vec<u8>, lengths: Vec<u32>) -> Self {
        Self {
            bytes,
            element_width: 1,
            string_lengths: Some(lengths),
            recyclable: false,
        }
    }

    pub(super) fn typed(bytes: Vec<u8>, element_width: usize) -> Self {
        Self {
            bytes,
            element_width,
            string_lengths: None,
            recyclable: false,
        }
    }

    pub(super) fn pooled(bytes: Vec<u8>, element_width: usize) -> Self {
        Self {
            bytes,
            element_width,
            string_lengths: None,
            recyclable: true,
        }
    }
}
