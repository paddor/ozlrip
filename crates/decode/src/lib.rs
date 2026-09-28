#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "paranoid", forbid(unsafe_code))]

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use ozlrip_core::{Error, ErrorKind, Limits, Result};

mod dict;
mod execute;
mod info;
mod outputs;
mod parse;
mod provider;
mod standard;
mod varint;

pub use info::{FrameHeaderInfo, FrameInfo, FrameValueType};
pub use outputs::Output;
pub use provider::DictionaryProvider;

use dict::DictionaryStore;

/// Decoder configuration.
///
/// Start from [`Options::default`] (or `Options::from(limits)`) and change
/// fields as needed. New options may be added in minor releases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Options {
    /// Defensive parser, graph, allocation, and expansion limits.
    pub limits: Limits,
    /// Verify each chunk's checksum of its decoded content, when the frame
    /// carries one. Upstream's `ZL_DParam_checkContentChecksum`.
    pub verify_content_checksum: bool,
    /// Verify the frame header checksum and each chunk's checksum of its
    /// compressed bytes, when the frame carries them. Upstream's
    /// `ZL_DParam_checkCompressedChecksum`.
    pub verify_compressed_checksum: bool,
}

impl Default for Options {
    /// [`Limits::default`], with both checksums verified.
    fn default() -> Self {
        Self::from(Limits::default())
    }
}

impl From<Limits> for Options {
    /// Default options with the given limits.
    fn from(limits: Limits) -> Self {
        Self {
            limits,
            verify_content_checksum: true,
            verify_compressed_checksum: true,
        }
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
    dictionary_provider: Option<Box<dyn DictionaryProvider + Send + Sync>>,
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
            dictionary_provider: None,
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

    /// Sets the provider this decoder asks for the dictionary bundles that
    /// frames name and it has not loaded. Replaces an earlier provider.
    pub fn set_dictionary_provider<P>(&mut self, provider: P)
    where
        P: DictionaryProvider + Send + Sync + 'static,
    {
        self.dictionary_provider = Some(Box::new(provider));
    }

    /// Removes the dictionary provider. Bundles it supplied stay loaded.
    pub fn clear_dictionary_provider(&mut self) {
        self.dictionary_provider = None;
    }

    /// Loads the bundle `plan` names from the provider, unless it is loaded
    /// or there is no provider.
    fn fetch_dictionary_bundle(&mut self, plan: &parse::FramePlan) -> Result<()> {
        let (Some(bundle_id), Some(provider)) = (
            plan.info.dictionary_bundle_id.as_deref(),
            &self.dictionary_provider,
        ) else {
            return Ok(());
        };
        if self.dict_store.contains(bundle_id) {
            return Ok(());
        }
        let bundle_id: &[u8; dict::UNIQUE_ID_BYTES] = bundle_id.try_into().map_err(|_| {
            Error::new(ErrorKind::Malformed).with_detail("dictionary bundle ID must be 32 bytes")
        })?;
        if let Some(bundle) = provider.fat_bundle(bundle_id)? {
            self.dict_store
                .load_provided_bundle(&bundle, bundle_id, self.options.limits)?;
        }
        Ok(())
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
        let options = self.options;
        #[cfg(feature = "zstd")]
        if let Some(frame) = parse::parse_single_zstd_frame(
            input,
            options.limits,
            options.verify_compressed_checksum,
        )? {
            return execute::decode_single_zstd_frame_with_context(
                input,
                frame,
                dst,
                options.limits,
                options.verify_content_checksum,
                execute::zstd_context(&mut self.zstd),
            );
        }
        let plan = parse::parse_frame(input, options.limits, options.verify_compressed_checksum)?;
        self.fetch_dictionary_bundle(&plan)?;
        let mut runtime = execute::DecodeRuntime::new(
            &mut self.scratch,
            &mut self.dict_store,
            #[cfg(feature = "zstd")]
            &mut self.zstd,
        );
        execute::decode_plan_with_context(
            input,
            &plan,
            dst,
            options.limits,
            options.verify_content_checksum,
            &mut runtime,
        )
    }

    /// Decodes a frame with a single serial output chunk by chunk.
    ///
    /// Each chunk's decoded bytes go to `sink` in frame order. The next chunk
    /// reuses their buffer, so decoded memory peaks at one chunk instead of
    /// the whole output. Returns the total decoded size. Chunks decode one
    /// after the other; there is no parallel decode.
    ///
    /// The whole frame is parsed and its compressed checksums are verified
    /// first. Each chunk's content checksum is verified before the chunk
    /// reaches `sink`. The frame's declared output size is checked as chunks
    /// arrive and after the last one, so `sink` may see chunks of a frame
    /// that then fails. An error from `sink` stops decoding and is returned.
    pub fn decode_chunks<F>(&mut self, input: &[u8], mut sink: F) -> Result<usize>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        let options = self.options;
        let plan = parse::parse_frame(input, options.limits, options.verify_compressed_checksum)?;
        self.fetch_dictionary_bundle(&plan)?;
        let mut runtime = execute::DecodeRuntime::new(
            &mut self.scratch,
            &mut self.dict_store,
            #[cfg(feature = "zstd")]
            &mut self.zstd,
        );
        execute::decode_chunks_with_context(
            input,
            &plan,
            options.limits,
            options.verify_content_checksum,
            &mut runtime,
            &mut sink,
        )
    }

    /// Decodes one OpenZL frame into a new `Vec`.
    ///
    /// The frame must have a single serial output; frames with typed or
    /// several outputs return [`ErrorKind::Unsupported`](ozlrip_core::ErrorKind)
    /// here and decode with [`Decoder::decode_outputs`].
    pub fn decode(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        self.decode_into(input, &mut output)?;
        Ok(output)
    }

    /// Decodes every output of one OpenZL frame, with its type.
    pub fn decode_outputs(&mut self, input: &[u8]) -> Result<Vec<Output>> {
        let mut outputs = Vec::new();
        self.decode_outputs_into(input, &mut outputs)?;
        Ok(outputs)
    }

    /// Decodes every output of one OpenZL frame into `outputs`, replacing
    /// its entries and reusing their buffers. On error, `outputs` holds one
    /// entry per output with partial or no content.
    pub fn decode_outputs_into(&mut self, input: &[u8], outputs: &mut Vec<Output>) -> Result<()> {
        let options = self.options;
        let plan = parse::parse_frame(input, options.limits, options.verify_compressed_checksum)?;
        self.fetch_dictionary_bundle(&plan)?;
        let mut decoded = outputs
            .drain(..)
            .map(Output::into_decoded)
            .collect::<Vec<_>>();
        let mut runtime = execute::DecodeRuntime::new(
            &mut self.scratch,
            &mut self.dict_store,
            #[cfg(feature = "zstd")]
            &mut self.zstd,
        );
        let result = execute::decode_outputs_with_context(
            input,
            &plan,
            &mut decoded,
            options.limits,
            options.verify_content_checksum,
            &mut runtime,
        );
        outputs.extend(decoded.into_iter().map(Output::from_decoded));
        result
    }

    /// Parses and validates frame metadata without executing decode nodes.
    pub fn inspect(&self, input: &[u8]) -> Result<FrameInfo> {
        parse::inspect_frame(
            input,
            self.options.limits,
            self.options.verify_compressed_checksum,
        )
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

/// Decodes every output of one OpenZL frame using [`Options::default`].
pub fn decode_outputs(input: &[u8]) -> Result<Vec<Output>> {
    Decoder::new().decode_outputs(input)
}

/// Decodes every output of one OpenZL frame using explicit options.
pub fn decode_outputs_with_options(input: &[u8], options: Options) -> Result<Vec<Output>> {
    Decoder::with_options(options).decode_outputs(input)
}

/// Decodes every output of one OpenZL frame into `outputs`, reusing its
/// buffers, using [`Options::default`].
pub fn decode_outputs_into(input: &[u8], outputs: &mut Vec<Output>) -> Result<()> {
    Decoder::new().decode_outputs_into(input, outputs)
}

/// Decodes every output of one OpenZL frame into `outputs` using explicit
/// options.
pub fn decode_outputs_into_with_options(
    input: &[u8],
    outputs: &mut Vec<Output>,
    options: Options,
) -> Result<()> {
    Decoder::with_options(options).decode_outputs_into(input, outputs)
}

/// Size of the OpenZL frame at the start of `input`, using
/// [`Options::default`]. `input` may continue past the frame, for example
/// with more frames.
///
/// Like upstream `ZL_getCompressedSize`, this reads the frame and chunk
/// headers but checks neither checksums nor the node graph.
pub fn frame_size(input: &[u8]) -> Result<usize> {
    frame_size_with_options(input, Options::default())
}

/// Size of the OpenZL frame at the start of `input`, using explicit options.
/// The limits apply to the frame, not to all of `input`.
pub fn frame_size_with_options(input: &[u8], options: Options) -> Result<usize> {
    parse::frame_size(input, options.limits)
}

/// Reads the header at the start of an OpenZL frame, using
/// [`Options::default`]. `prefix` needs to hold only the header; its size
/// is [`FrameHeaderInfo::header_bytes`]. The header checksum is verified if
/// the frame has one.
pub fn inspect_header(prefix: &[u8]) -> Result<FrameHeaderInfo> {
    inspect_header_with_options(prefix, Options::default())
}

/// Reads the header at the start of an OpenZL frame using explicit options.
pub fn inspect_header_with_options(prefix: &[u8], options: Options) -> Result<FrameHeaderInfo> {
    parse::inspect_header(prefix, options.limits, options.verify_compressed_checksum)
}

/// Parses and validates frame metadata using [`Options::default`].
pub fn inspect(input: &[u8]) -> Result<FrameInfo> {
    inspect_with_options(input, Options::default())
}

/// Parses and validates frame metadata using explicit options.
pub fn inspect_with_options(input: &[u8], options: Options) -> Result<FrameInfo> {
    parse::inspect_frame(input, options.limits, options.verify_compressed_checksum)
}

#[cfg(all(test, feature = "zstd"))]
mod tests {
    use super::*;
    use ozlrip_core::ErrorKind;
    use ozlrip_test_support::{magic, push_var_u64};

    const BUNDLE_INFO_MAGIC: u32 = 0x4942_ccda;
    const PACKED_DICT_MAGIC: u32 = 0x4944_ccda;
    const BUNDLE_ID: [u8; 32] = [7; 32];
    const OTHER_BUNDLE_ID: [u8; 32] = [8; 32];
    const DICT_ID: [u8; 32] = [9; 32];

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

    /// Serves one bundle and counts how often it is asked.
    struct TestProvider {
        bundle: Option<Vec<u8>>,
        calls: alloc::sync::Arc<core::sync::atomic::AtomicUsize>,
    }

    impl TestProvider {
        fn new(bundle: Option<Vec<u8>>) -> Self {
            Self {
                bundle,
                calls: alloc::sync::Arc::default(),
            }
        }

        fn calls(&self) -> alloc::sync::Arc<core::sync::atomic::AtomicUsize> {
            alloc::sync::Arc::clone(&self.calls)
        }
    }

    impl DictionaryProvider for TestProvider {
        fn fat_bundle(&self, bundle_id: &[u8; 32]) -> Result<Option<alloc::borrow::Cow<'_, [u8]>>> {
            assert_eq!(*bundle_id, BUNDLE_ID);
            self.calls
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(self.bundle.as_deref().map(alloc::borrow::Cow::Borrowed))
        }
    }

    /// A frame's bundle comes from the provider once, then stays loaded.
    #[cfg(feature = "zstd")]
    #[test]
    fn decodes_with_a_bundle_from_the_provider() {
        let (frame, bundle, expected) = zstd_dict_test_frame();
        let provider = TestProvider::new(Some(bundle));
        let calls = provider.calls();
        let mut decoder = Decoder::new();
        decoder.set_dictionary_provider(provider);

        assert_eq!(decoder.decode(&frame).unwrap(), expected);
        assert_eq!(
            decoder.decode_outputs(&frame).unwrap(),
            [Output::Serial(expected)]
        );
        assert_eq!(calls.load(core::sync::atomic::Ordering::Relaxed), 1);

        decoder.clear_dictionary_provider();
        assert!(decoder.decode(&frame).is_ok());
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn does_not_ask_the_provider_for_loaded_bundles() {
        let (frame, bundle, expected) = zstd_dict_test_frame();
        let provider = TestProvider::new(None);
        let calls = provider.calls();
        let mut decoder = Decoder::new();
        decoder.set_dictionary_provider(provider);
        decoder.load_dictionary_bundle(&bundle).unwrap();

        assert_eq!(decoder.decode(&frame).unwrap(), expected);
        assert_eq!(calls.load(core::sync::atomic::Ordering::Relaxed), 0);
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn reports_bundles_the_provider_lacks_as_not_loaded() {
        let (frame, _bundle, _expected) = zstd_dict_test_frame();
        let mut decoder = Decoder::new();
        decoder.set_dictionary_provider(TestProvider::new(None));

        let err = decoder.decode(&frame).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Unsupported);
        assert_eq!(err.detail(), Some("dictionary bundle is not loaded"));
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn rejects_provided_bundles_with_another_id() {
        let (frame, _bundle, _expected) = zstd_dict_test_frame();
        let other = fat_bundle(OTHER_BUNDLE_ID, &test_zstd_dict_bytes());
        let mut decoder = Decoder::new();
        decoder.set_dictionary_provider(TestProvider::new(Some(other)));

        let err = decoder.decode(&frame).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Malformed);
        assert_eq!(
            err.detail(),
            Some("dictionary provider returned a bundle with another ID")
        );
    }

    #[cfg(feature = "zstd")]
    #[test]
    fn returns_provider_errors() {
        struct Failing;
        impl DictionaryProvider for Failing {
            fn fat_bundle(
                &self,
                _bundle_id: &[u8; 32],
            ) -> Result<Option<alloc::borrow::Cow<'_, [u8]>>> {
                Err(Error::new(ErrorKind::LimitExceeded).with_detail("store is offline"))
            }
        }
        let (frame, _bundle, _expected) = zstd_dict_test_frame();
        let mut decoder = Decoder::new();
        decoder.set_dictionary_provider(Failing);
        let mut output = vec![1, 2];

        let err = decoder.decode_into(&frame, &mut output).unwrap_err();

        assert_eq!(err.detail(), Some("store is offline"));
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
