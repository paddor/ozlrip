#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

extern crate alloc;

use alloc::vec::Vec;
use ozlrip_core::{Limits, Result};

mod dict;
mod execute;
mod info;
mod parse;
mod standard;

pub use info::{FrameInfo, FrameValueType};

use dict::DictionaryStore;

/// Decoder configuration.
///
/// Start from [`Options::default`] (or `Options::from(limits)`) and change
/// fields as needed. New options may be added in minor releases.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Options {
    /// Defensive parser, graph, allocation, and expansion limits.
    pub limits: Limits,
}

impl From<Limits> for Options {
    /// Default options with the given limits.
    fn from(limits: Limits) -> Self {
        Self { limits }
    }
}

/// Reusable OpenZL decoder with scratch buffers and codec state.
///
/// Between decodes it keeps up to 64 MiB of intermediate buffers for reuse;
/// [`Decoder::shrink_to_fit`] frees them.
pub struct Decoder {
    options: Options,
    scratch: execute::DecodeScratch,
    dict_store: DictionaryStore,
    /// Created on the first zstd frame or node.
    #[cfg(feature = "zstd")]
    zstd: Option<zrip_decode::context::DecompressContext>,
}

impl Decoder {
    /// Creates a decoder with [`Options::default`].
    pub fn new() -> Self {
        Self::with_options(Options::default())
    }

    /// Creates a decoder with explicit options.
    pub fn with_options(options: Options) -> Self {
        Self {
            options,
            scratch: execute::DecodeScratch::new(),
            dict_store: DictionaryStore::new(),
            #[cfg(feature = "zstd")]
            zstd: None,
        }
    }

    pub fn options(&self) -> Options {
        self.options
    }

    pub fn limits(&self) -> Limits {
        self.options.limits
    }

    /// Loads an OpenZL dictionary bundle for later dictionary-backed decode.
    ///
    /// Currently only zstd dictionary materialization is implemented.
    pub fn load_dictionary_bundle(&mut self, bytes: &[u8]) -> Result<()> {
        self.dict_store.load_fat_bundle(bytes, self.options.limits)
    }

    /// Clears all loaded dictionary bundles.
    pub fn clear_dictionary_bundles(&mut self) {
        self.dict_store.clear();
    }

    /// Frees the buffers and codec state kept for reuse between decodes.
    /// Loaded dictionary bundles stay loaded.
    pub fn shrink_to_fit(&mut self) {
        self.scratch.clear();
        #[cfg(feature = "zstd")]
        {
            self.zstd = None;
        }
    }

    /// Decodes one OpenZL frame and appends the decoded bytes to `dst`.
    ///
    /// Returns the number of bytes appended. On error, `dst` is restored to its
    /// original length.
    pub fn decode_into(&mut self, input: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
        #[cfg(feature = "zstd")]
        if let Some(frame) = parse::parse_single_zstd_frame(input, self.options.limits)? {
            return execute::decode_single_zstd_frame_with_context(
                input,
                frame,
                dst,
                self.options.limits,
                execute::zstd_context(&mut self.zstd),
            );
        }
        let plan = parse::parse_frame_plan(input, self.options.limits)?;
        let mut runtime = execute::DecodeRuntime::new(
            &mut self.scratch,
            &mut self.dict_store,
            #[cfg(feature = "zstd")]
            &mut self.zstd,
        );
        execute::decode_plan_with_context(input, &plan, dst, self.options.limits, &mut runtime)
    }

    /// Decodes one OpenZL frame into a new `Vec`.
    pub fn decode(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        self.decode_into(input, &mut output)?;
        Ok(output)
    }

    /// Parses and validates frame metadata without executing decode nodes.
    pub fn inspect(&self, input: &[u8]) -> Result<FrameInfo> {
        parse::inspect_frame(input, self.options.limits)
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Decoder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Decoder")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Decoder>();
};

/// Decodes one OpenZL frame into a new `Vec` using [`Options::default`].
pub fn decode(input: &[u8]) -> Result<Vec<u8>> {
    Decoder::new().decode(input)
}

/// Decodes one OpenZL frame into a new `Vec` using explicit options.
pub fn decode_with_options(input: &[u8], options: Options) -> Result<Vec<u8>> {
    Decoder::with_options(options).decode(input)
}

/// Decodes one OpenZL frame and appends the decoded bytes to `dst`.
///
/// Returns the number of bytes appended. On error, `dst` is restored to its
/// original length.
pub fn decode_into(input: &[u8], dst: &mut Vec<u8>) -> Result<usize> {
    Decoder::new().decode_into(input, dst)
}

/// Decodes one OpenZL frame into `dst` using explicit options.
pub fn decode_into_with_options(
    input: &[u8],
    dst: &mut Vec<u8>,
    options: Options,
) -> Result<usize> {
    Decoder::with_options(options).decode_into(input, dst)
}

/// Parses and validates frame metadata using [`Options::default`].
pub fn inspect(input: &[u8]) -> Result<FrameInfo> {
    inspect_with_options(input, Options::default())
}

/// Parses and validates frame metadata using explicit options.
pub fn inspect_with_options(input: &[u8], options: Options) -> Result<FrameInfo> {
    parse::inspect_frame(input, options.limits)
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
    use super::*;
    use ozlrip_core::ErrorKind;

    const MAGIC_BASE: u32 = 0xd7b1_a5c0;
    const BUNDLE_INFO_MAGIC: u32 = 0x4942_ccda;
    const PACKED_DICT_MAGIC: u32 = 0x4944_ccda;
    const BUNDLE_ID: [u8; 32] = [7; 32];
    const OTHER_BUNDLE_ID: [u8; 32] = [8; 32];
    const DICT_ID: [u8; 32] = [9; 32];

    fn magic(version: u32) -> [u8; 4] {
        (MAGIC_BASE + version).to_le_bytes()
    }

    fn push_var_u64(out: &mut Vec<u8>, mut value: u64) {
        while value >= 0x80 {
            out.push(u8::try_from(value & 0x7f).unwrap() | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).unwrap());
    }

    #[cfg(feature = "zstd")]
    fn test_zstd_dict_bytes() -> Vec<u8> {
        use zrip_core::dict::DICT_MAGIC;
        use zrip_core::fse::table_builder::serialize_fse_table_description;

        let mut dict = Vec::new();
        dict.extend_from_slice(&DICT_MAGIC.to_le_bytes());
        dict.extend_from_slice(&1u32.to_le_bytes());
        dict.push(128);
        dict.push(0x10);

        let mut of_dist = vec![0i16; 32];
        of_dist[0] = 1 << 8;
        dict.extend_from_slice(&serialize_fse_table_description(&of_dist, 8));

        let mut ml_dist = vec![0i16; 53];
        ml_dist[0] = 1 << 6;
        dict.extend_from_slice(&serialize_fse_table_description(&ml_dist, 6));

        let mut ll_dist = vec![0i16; 36];
        ll_dist[0] = 1 << 6;
        dict.extend_from_slice(&serialize_fse_table_description(&ll_dist, 6));

        dict.extend_from_slice(&1u32.to_le_bytes());
        dict.extend_from_slice(&4u32.to_le_bytes());
        dict.extend_from_slice(&8u32.to_le_bytes());
        dict.extend_from_slice(b"dictionary-backed OpenZL zstd content");
        dict
    }

    #[cfg(feature = "zstd")]
    fn fat_bundle(bundle_id: [u8; 32], raw_dict: &[u8]) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(&1u32.to_le_bytes());
        content.extend_from_slice(&1i32.to_le_bytes());
        content.extend_from_slice(raw_dict);

        let mut bundle = Vec::new();
        bundle.extend_from_slice(&BUNDLE_INFO_MAGIC.to_le_bytes());
        bundle.extend_from_slice(&bundle_id);
        bundle.push(1);
        bundle.extend_from_slice(&1u32.to_le_bytes());
        bundle.extend_from_slice(&DICT_ID);
        bundle.extend_from_slice(&PACKED_DICT_MAGIC.to_le_bytes());
        bundle.extend_from_slice(&DICT_ID);
        bundle.extend_from_slice(&standard::ZSTD_ID.to_le_bytes());
        bundle.push(0);
        bundle.extend_from_slice(&u32::try_from(content.len()).unwrap().to_le_bytes());
        bundle.extend_from_slice(&content);
        bundle
    }

    #[cfg(feature = "zstd")]
    fn zstd_dict_frame(bundle_id: &[u8], stored: &[u8], decoded_len: usize) -> Vec<u8> {
        let mut input = Vec::new();
        input.extend_from_slice(&magic(25));
        input.push(1 << 3);
        input.push(u8::try_from(bundle_id.len()).unwrap());
        input.extend_from_slice(bundle_id);
        input.push(1);
        push_var_u64(&mut input, u64::try_from(decoded_len + 1).unwrap());
        input.push(2);
        input.push(1);
        input.push(0);
        input.push(u8::try_from(standard::ZSTD_ID).unwrap());
        input.push(0);
        input.push(0);
        input.push(0);
        input.push(1);
        input.push(0);
        input.push(0);
        push_var_u64(&mut input, u64::try_from(stored.len()).unwrap());
        input.extend_from_slice(stored);
        input.push(0);
        input
    }

    #[cfg(feature = "zstd")]
    fn push_zstd_block_header(out: &mut Vec<u8>, last: bool, block_type: u32, block_size: usize) {
        let raw = (u32::try_from(block_size).unwrap() << 3) | (block_type << 1) | u32::from(last);
        out.extend_from_slice(&raw.to_le_bytes()[..3]);
    }

    #[cfg(feature = "zstd")]
    fn zstd_raw_frame_with_dict_id(bytes: &[u8], dict_id: u8) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&zrip_core::frame::ZSTD_MAGIC.to_le_bytes());
        frame.push(0x21);
        frame.push(dict_id);
        frame.push(u8::try_from(bytes.len()).unwrap());
        push_zstd_block_header(&mut frame, true, 0, bytes.len());
        frame.extend_from_slice(bytes);
        frame
    }

    #[cfg(feature = "zstd")]
    fn zstd_dict_test_frame() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let raw_dict = test_zstd_dict_bytes();
        let expected = b"dictionary-backed OpenZL zstd frame".to_vec();
        let compressed = zstd_raw_frame_with_dict_id(&expected, 1);
        let mut stored = Vec::new();
        push_var_u64(&mut stored, 1);
        stored.extend_from_slice(&compressed[4..]);
        let frame = zstd_dict_frame(&BUNDLE_ID, &stored, expected.len());
        (frame, fat_bundle(BUNDLE_ID, &raw_dict), expected)
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn decodes_zstd_dictionary_frame_after_loading_bundle() {
        let (frame, bundle, expected) = zstd_dict_test_frame();
        let mut decoder = Decoder::new();
        decoder.load_dictionary_bundle(&bundle).unwrap();
        let mut output = vec![1, 2];

        let written = decoder.decode_into(&frame, &mut output).unwrap();

        assert_eq!(written, expected.len());
        assert_eq!(&output[..2], &[1, 2]);
        assert_eq!(&output[2..], expected);
    }

    /// Dictionary contexts are built on first use, and the dictionary limits
    /// count every loaded bundle, except the one a reload replaces.
    #[cfg(feature = "zstd")]
    #[test]
    fn limits_dictionaries_and_builds_contexts_on_first_use() {
        let (frame, bundle, expected) = zstd_dict_test_frame();
        let raw_dict = test_zstd_dict_bytes();
        let mut limits = Limits::strict();
        limits.max_dictionaries = 1;
        let mut decoder = Decoder::with_options(Options::from(limits));

        decoder.load_dictionary_bundle(&bundle).unwrap();
        assert_eq!(decoder.dict_store.built_contexts(), 0);
        decoder.load_dictionary_bundle(&bundle).unwrap();
        let err = decoder
            .load_dictionary_bundle(&fat_bundle(OTHER_BUNDLE_ID, &raw_dict))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::LimitExceeded);

        assert_eq!(decoder.decode(&frame).unwrap(), expected);
        assert_eq!(decoder.dict_store.built_contexts(), 1);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn rejects_dictionary_frame_without_loaded_bundle_without_mutating_destination() {
        let (frame, _bundle, _expected) = zstd_dict_test_frame();
        let mut decoder = Decoder::new();
        let mut output = vec![1, 2];

        let err = decoder.decode_into(&frame, &mut output).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn rejects_dictionary_frame_with_wrong_bundle_without_mutating_destination() {
        let (frame, _bundle, _expected) = zstd_dict_test_frame();
        let raw_dict = test_zstd_dict_bytes();
        let mut decoder = Decoder::new();
        decoder
            .load_dictionary_bundle(&fat_bundle(OTHER_BUNDLE_ID, &raw_dict))
            .unwrap();
        let mut output = vec![1, 2];

        let err = decoder.decode_into(&frame, &mut output).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn clear_dictionary_bundles_drops_loaded_bundle() {
        let (frame, bundle, _expected) = zstd_dict_test_frame();
        let mut decoder = Decoder::new();
        decoder.load_dictionary_bundle(&bundle).unwrap();
        decoder.clear_dictionary_bundles();
        let mut output = vec![1, 2];

        let err = decoder.decode_into(&frame, &mut output).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(output, [1, 2]);
    }
}
