//! Bindings to upstream OpenZL C for ozlrip benchmarks and interop tests.
//!
//! Not published. The C side lives in `openzl_shim.c`; `build.rs` builds
//! `libopenzl.a` from the checkout in `OZLRIP_OPENZL_DIR`.

use std::{
    ffi::{CStr, c_char, c_int, c_uint, c_void},
    ptr,
};

/// C flags the linked OpenZL library was built with (`OZLRIP_OPENZL_MOREFLAGS`).
pub const OPENZL_MOREFLAGS: &str = env!("OZLRIP_OPENZL_MOREFLAGS");

enum ZlDCtx {}

#[repr(C)]
struct ShimInput {
    kind: c_int,
    data: *const c_void,
    data_size: usize,
    width: usize,
    lengths: *const u32,
    count: usize,
}

#[repr(C)]
struct ShimNode {
    kind: c_int,
    param: c_int,
    name: *const c_char,
}

unsafe extern "C" {
    fn ozlrip_shim_last_error() -> *const c_char;
    fn ozlrip_shim_min_format_version() -> c_uint;
    fn ozlrip_shim_max_format_version() -> c_uint;
    fn ozlrip_shim_default_format_version() -> c_uint;
    fn ozlrip_shim_dctx_create() -> *mut ZlDCtx;
    fn ozlrip_shim_dctx_free(dctx: *mut ZlDCtx);
    fn ozlrip_shim_dctx_disable_checksums(dctx: *mut ZlDCtx) -> c_int;
    fn ozlrip_shim_decompress_serial(
        dctx: *mut ZlDCtx,
        dst: *mut c_void,
        dst_capacity: usize,
        src: *const c_void,
        src_size: usize,
        written: *mut usize,
    ) -> c_int;
    fn ozlrip_shim_compress(
        nodes: *const ShimNode,
        nb_nodes: usize,
        graph: c_int,
        format_version: c_uint,
        compression_level: c_int,
        store_on_expansion: c_int,
        inputs: *const ShimInput,
        nb_inputs: usize,
        dst: *mut c_void,
        dst_capacity: usize,
        written: *mut usize,
    ) -> c_int;
    fn ozlrip_shim_compress_bound(total_input_size: usize) -> usize;
    fn ozlrip_shim_compressed_size(src: *const c_void, src_size: usize, size: *mut usize) -> c_int;
}

/// Error from the OpenZL C library, with its context string.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    pub code: i32,
    pub message: String,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenZL error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

fn check(code: c_int) -> Result<(), Error> {
    if code == 0 {
        return Ok(());
    }
    // SAFETY: the shim returns a pointer to a NUL-terminated thread-local
    // buffer that stays valid until the next shim call on this thread.
    let message = unsafe { CStr::from_ptr(ozlrip_shim_last_error()) }
        .to_string_lossy()
        .into_owned();
    Err(Error { code, message })
}

/// Oldest format version the linked library can write and read.
pub fn min_format_version() -> u32 {
    // SAFETY: pure getter.
    unsafe { ozlrip_shim_min_format_version() }
}

/// Newest format version the linked library can write and read.
pub fn max_format_version() -> u32 {
    // SAFETY: pure getter.
    unsafe { ozlrip_shim_max_format_version() }
}

/// Format version the library writes when none is requested.
pub fn default_format_version() -> u32 {
    // SAFETY: pure getter.
    unsafe { ozlrip_shim_default_format_version() }
}

/// Size of the frame at the start of `bytes`, from `ZL_getCompressedSize`.
pub fn compressed_size(bytes: &[u8]) -> Result<usize, Error> {
    let mut size = 0usize;
    // SAFETY: `bytes` is valid for its length for the whole call.
    check(unsafe { ozlrip_shim_compressed_size(bytes.as_ptr().cast(), bytes.len(), &mut size) })?;
    Ok(size)
}

/// Reusable OpenZL decompression context.
pub struct Decompressor {
    dctx: *mut ZlDCtx,
}

impl Decompressor {
    pub fn new() -> Self {
        // SAFETY: plain constructor; null is checked below.
        let dctx = unsafe { ozlrip_shim_dctx_create() };
        assert!(!dctx.is_null(), "ZL_DCtx_create returned null");
        Self { dctx }
    }

    /// Disables compressed and content checksum verification for this
    /// context and later calls.
    pub fn disable_checksums(&mut self) -> Result<(), Error> {
        // SAFETY: `self.dctx` is a live context owned by `self`.
        check(unsafe { ozlrip_shim_dctx_disable_checksums(self.dctx) })
    }

    /// Decompresses a single-serial-output frame into `dst` and returns the
    /// number of bytes written.
    pub fn decompress_serial(&mut self, frame: &[u8], dst: &mut [u8]) -> Result<usize, Error> {
        let mut written = 0usize;
        // SAFETY: `dst` and `frame` are valid for their lengths for the whole
        // call, and `self.dctx` is a live context owned by `self`.
        check(unsafe {
            ozlrip_shim_decompress_serial(
                self.dctx,
                dst.as_mut_ptr().cast(),
                dst.len(),
                frame.as_ptr().cast(),
                frame.len(),
                &mut written,
            )
        })?;
        Ok(written)
    }
}

impl Default for Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Decompressor {
    fn drop(&mut self) {
        // SAFETY: `self.dctx` came from `ozlrip_shim_dctx_create` and is freed
        // exactly once.
        unsafe { ozlrip_shim_dctx_free(self.dctx) };
    }
}

/// Standard OpenZL starting graphs. Keep in sync with `openzl_shim.c`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Graph {
    Generic = 0,
    Store = 1,
    Zstd = 2,
    Lz4 = 3,
    Fse = 4,
    Huffman = 5,
    Entropy = 6,
    FieldLz = 7,
    Bitpack = 8,
    Flatpack = 9,
    Constant = 10,
    Numeric = 11,
}

/// One typed compression input.
#[derive(Clone, Copy, Debug)]
pub enum Input<'a> {
    Serial(&'a [u8]),
    /// Fixed-width records; `bytes.len()` must be a multiple of `width`.
    Struct {
        width: usize,
        bytes: &'a [u8],
    },
    /// Little-endian integers of `width` 1, 2, 4 or 8 bytes.
    Numeric {
        width: usize,
        bytes: &'a [u8],
    },
    /// Concatenated strings and their lengths.
    String {
        bytes: &'a [u8],
        lengths: &'a [u32],
    },
}

/// Compression settings.
#[derive(Clone, Copy, Debug)]
pub struct CompressOptions {
    pub graph: Graph,
    /// `0` selects [`default_format_version`].
    pub format_version: u32,
    pub level: i32,
    /// Store a chunk raw when its graph would expand it. Upstream does so
    /// by default; turning it off keeps every node in the frame.
    pub store_on_expansion: bool,
}

impl Default for CompressOptions {
    fn default() -> Self {
        Self {
            graph: Graph::Generic,
            format_version: 0,
            level: 0,
            store_on_expansion: true,
        }
    }
}

/// Standard nodes with one input and one output, for [`compress_pipeline`].
/// Keep in sync with `openzl_shim.c`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Node {
    /// Serial bytes to little-endian integers of this width: 1, 2, 4 or 8.
    SerialToNumLe(u8),
    /// Integers to their little-endian bytes.
    NumToSerialLe,
    DeltaInt,
    Zigzag,
    RangePack,
    /// Serial bits to integers of this many bits each.
    Bitunpack(u8),
    /// Serial bytes to records of this width: 2, 4 or 8.
    SerialToStruct(u8),
    /// A node by name without the leading `!`, such as upstream's private
    /// `zl.private.rolz_deprecated`.
    Named(&'static CStr),
}

impl Node {
    fn shim(self) -> ShimNode {
        let (kind, param) = match self {
            Self::SerialToNumLe(width) => (0, width),
            Self::NumToSerialLe => (1, 0),
            Self::DeltaInt => (2, 0),
            Self::Zigzag => (3, 0),
            Self::RangePack => (4, 0),
            Self::Bitunpack(bits) => (5, bits),
            Self::Named(_) => (6, 0),
            Self::SerialToStruct(width) => (7, width),
        };
        let name = match self {
            Self::Named(name) => name.as_ptr(),
            _ => ptr::null(),
        };
        ShimNode {
            kind,
            param: c_int::from(param),
            name,
        }
    }
}

/// Compresses typed inputs into one OpenZL frame.
pub fn compress(inputs: &[Input<'_>], options: CompressOptions) -> Result<Vec<u8>, Error> {
    compress_pipeline(inputs, &[], options)
}

/// Compresses typed inputs through `nodes` in order, then `options.graph`.
pub fn compress_pipeline(
    inputs: &[Input<'_>],
    nodes: &[Node],
    options: CompressOptions,
) -> Result<Vec<u8>, Error> {
    let shim_nodes = nodes.iter().map(|node| node.shim()).collect::<Vec<_>>();
    // OpenZL reads numeric inputs as aligned host-endian arrays, so copy them
    // into u64-aligned storage first.
    let aligned = inputs
        .iter()
        .map(|input| match input {
            Input::Numeric { width, bytes } => Some(aligned_numeric(*width, bytes)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let shim_inputs = inputs
        .iter()
        .zip(&aligned)
        .map(|(input, aligned)| shim_input(input, aligned.as_deref()))
        .collect::<Vec<_>>();
    let total = inputs
        .iter()
        .map(|input| match input {
            Input::String { bytes, lengths } => bytes.len() + lengths.len() * 4,
            Input::Serial(bytes) | Input::Struct { bytes, .. } | Input::Numeric { bytes, .. } => {
                bytes.len()
            }
        })
        .sum::<usize>();
    // SAFETY: pure computation.
    let bound = unsafe { ozlrip_shim_compress_bound(total) };
    // Without the store fallback a graph may expand its input, by up to 8
    // times for one-bit unpacking.
    let capacity = if options.store_on_expansion {
        bound
    } else {
        bound.saturating_mul(9)
    };
    let mut dst = vec![0u8; capacity];
    let mut written = 0usize;
    // SAFETY: every `ShimInput` points into `inputs` or `aligned`, both alive
    // for the whole call; `shim_nodes` and `dst` are valid for their lengths.
    check(unsafe {
        ozlrip_shim_compress(
            shim_nodes.as_ptr(),
            shim_nodes.len(),
            options.graph as c_int,
            options.format_version,
            options.level,
            // ZL_TernaryParam_enable and ZL_TernaryParam_disable.
            if options.store_on_expansion { 1 } else { 2 },
            shim_inputs.as_ptr(),
            shim_inputs.len(),
            dst.as_mut_ptr().cast(),
            dst.len(),
            &mut written,
        )
    })?;
    dst.truncate(written);
    Ok(dst)
}

fn aligned_numeric(width: usize, bytes: &[u8]) -> Vec<u64> {
    assert!(
        matches!(width, 1 | 2 | 4 | 8),
        "numeric width must be 1, 2, 4 or 8"
    );
    assert!(
        bytes.len().is_multiple_of(width),
        "numeric input length must be a multiple of its width"
    );
    let mut words = vec![0u64; bytes.len().div_ceil(8)];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        // Bytes keep their input order; this matches the host layout OpenZL
        // expects on little-endian targets.
        *word = u64::from_ne_bytes(buf);
    }
    words
}

fn shim_input(input: &Input<'_>, aligned: Option<&[u64]>) -> ShimInput {
    match *input {
        Input::Serial(bytes) => ShimInput {
            kind: 0,
            data: bytes.as_ptr().cast(),
            data_size: bytes.len(),
            width: 1,
            lengths: ptr::null(),
            count: bytes.len(),
        },
        Input::Struct { width, bytes } => {
            assert!(width > 0 && bytes.len().is_multiple_of(width));
            ShimInput {
                kind: 1,
                data: bytes.as_ptr().cast(),
                data_size: bytes.len(),
                width,
                lengths: ptr::null(),
                count: bytes.len() / width,
            }
        }
        Input::Numeric { width, bytes } => ShimInput {
            kind: 2,
            data: aligned.expect("numeric input is aligned").as_ptr().cast(),
            data_size: bytes.len(),
            width,
            lengths: ptr::null(),
            count: bytes.len() / width,
        },
        Input::String { bytes, lengths } => ShimInput {
            kind: 3,
            data: bytes.as_ptr().cast(),
            data_size: bytes.len(),
            width: 0,
            lengths: lengths.as_ptr(),
            count: lengths.len(),
        },
    }
}
