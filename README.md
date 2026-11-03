# ozlrip

Memory-safe Rust decoder for OpenZL.

## API

```rust
// A frame with one serial output.
let decoded = ozlrip::decode(frame)?;

let mut dst = Vec::new();
let written = ozlrip::decode_into(frame, &mut dst)?;

// Every output of a frame, with its type.
for output in ozlrip::decode_outputs(frame)? {
    match output {
        ozlrip::Output::Serial(bytes) => {}
        ozlrip::Output::Struct { width, bytes } => {}
        ozlrip::Output::Numeric { width, bytes } => {} // little-endian
        ozlrip::Output::String { bytes, lengths } => {}
        _ => {}
    }
}

// Metadata without decoding.
let info = ozlrip::inspect(frame)?;
let header = ozlrip::inspect_header(prefix)?; // needs only the header bytes
let size = ozlrip::frame_size(buffer)?; // the frame at the start of `buffer`

// Limits for untrusted input, and checksum switches.
let mut limits = ozlrip::Limits::strict();
limits.max_decoded_bytes = 1 << 20;
let mut options = ozlrip::Options::from(limits);
options.verify_content_checksum = false;
let decoded = ozlrip::decode_with_options(frame, options)?;
```

A `Decoder` keeps buffers, codec state, and dictionary bundles between
frames. It keeps up to 64 MiB of intermediate buffers; `shrink_to_fit` frees
them.

```rust
let mut decoder = ozlrip::Decoder::with_options(options);
decoder.load_dictionary_bundle(&bundle)?;
let decoded = decoder.decode(frame)?;

// Decoded memory peaks at one chunk.
decoder.decode_chunks(frame, |chunk| {
    sink.extend_from_slice(chunk);
    Ok(())
})?;
```

`Decoder::set_dictionary_provider` takes a `DictionaryProvider`, which
supplies bundles that frames name and the decoder has not loaded, like
upstream's `ZL_DictLoader`.

`Limits`, `Options`, `FrameInfo`, `FrameHeaderInfo`, `ErrorKind`,
`FrameValueType`, and `Output` are `#[non_exhaustive]`: start from a
constructor or `Default` and set fields, and give `match` a wildcard arm.

## Features

- Default: `std`, `alloc`, `zstd`, `lz4`.
- `zstd` and `lz4` decode those nodes with `zrip` and `lz4rip`. Without
  them, frames that use the nodes return `Unsupported`.
- `no_std`: build with `--no-default-features --features alloc`, plus
  `zstd` and `lz4` as needed. `std` adds SIMD dispatch in the codecs.
- `paranoid`: no effect today. Every crate is `#![forbid(unsafe_code)]`, and
  so are the `zrip` and `lz4rip` decoders it calls.
- Outputs: `decode`, `decode_into`, and `Decoder::decode_chunks` take frames
  with one serial output and return `Unsupported` for others.
  `decode_outputs` takes any frame and returns each output with its type.
- Checksums: verification is always compiled in.
  `Options::verify_content_checksum` and `Options::verify_compressed_checksum`
  turn it off at run time, like upstream's `ZL_DParam_checkContentChecksum`
  and `ZL_DParam_checkCompressedChecksum`.

## Current Scope

- [x] Defensive frame parsing, inspection, limits, and typed errors
- [x] Whole-graph validation before execution
- [x] Stored streams, checksums, zstd via `zrip-decode`, lz4 via `lz4rip-decode`
- [x] Core graph transforms: concat, splitN, split-by-struct, transpose split,
  bit split, mux lengths, prefix, dispatch string, dispatchN-byTag
- [x] Numeric/table transforms: endian conversion, delta, divide-by, dedup,
  zigzag, bitpack, bitunpack, range-pack, flatpack, sparse num, partition,
  quantize
- [x] Text/reconstruction transforms: tokenizer, parse-int, LZ, field-LZ
- [x] No `unsafe`: every crate is `#![forbid(unsafe_code)]`
- [x] OpenZL format v27, including PivCo-Huffman
- [x] PivCo-Huffman payload decode, safe scalar path, and std-gated SIMD merge
- [x] Fat-bundle dictionary materialization for zstd
- [x] Broad release-tag interop checkpoint matrix
- [x] Committed standard-node coverage manifest tied to decoder tests
- [ ] External/custom codec and transform extension API
- [ ] Some unobserved transform header variants

## Extension Boundary

`ozlrip` decodes OpenZL standard-codec frames. Custom transforms, custom
dictionary materializers, and non-zstd dictionary materializers are rejected
with typed `Unsupported` errors. Adding extension execution needs a callback API
with explicit graph typing, dictionary lifetime, allocation-limit, and rollback
contracts; it should not be bolted into the standard decoder path.

## Unsupported Frame Shapes

An interop test compresses inputs with upstream at every format version it
writes, through every standard graph and the deprecated nodes, and ozlrip
decodes every frame. A few shapes that no upstream encoder writes return
`Unsupported`:

- The AVX2 layout of the deprecated Huffman codecs. Only the deprecated fastlz
  encoder allows it, for 16-bit symbols up to 1024, and its tokens reach 2047.
- Huffman tables of log 12. Upstream encoders cap Huffman tables at log 11.
- `zstd` nodes with elements wider than a byte. Only `zstd_fixed` writes
  records; `zstd` takes serial input.

## Performance

Decoded MB/s for 0.6.0 against OpenZL C, called in process on the same frames
from upstream `dev` (`b75871d`, format v27), on an Intel Core i7-8700B. Ratios
above 1 mean ozlrip is faster. The headline columns are the portable build:
default features, no target-cpu flags for ozlrip, `-O3` for OpenZL C, each
number the median of 3 sweeps. The native ratio builds both with native CPU
flags, from one sweep.

| case | ozlrip MB/s | OpenZL C MB/s | ratio | native ratio |
|---|---:|---:|---:|---:|
| `serial-random-4k` | 4138 | 3830 | 1.08x | 1.13x |
| `serial-random-1m` | 6319 | 7001 | 0.90x | 0.92x |
| `serial-repeated-4k` | 1993 | 1251 | 1.59x | 1.66x |
| `serial-sequential-1m` | 10976 | 11202 | 0.98x | 0.89x |
| `serial-sequential-16m` | 8325 | 7983 | 1.04x | 1.09x |
| `u8-rle-16m` | 3263 | 3937 | 0.83x | 0.80x |
| `le-u32-delta-16m` | 1590 | 709 | 2.24x | 1.91x |
| `era5-le-i32-sample` | 801 | 970 | 0.83x | 0.85x |
| `le-u64-timeseries-32m` | 1595 | 734 | 2.17x | 2.10x |
| `csv-timeseries-3m` | 273 | 202 | 1.35x | 1.31x |
| `csv-timeseries-30m` | 356 | 213 | 1.67x | 1.66x |
| `csv-pums-sample` | 317 | 169 | 1.87x | 1.82x |
| `tbl-supplier-pipe` | 64 | 53 | 1.20x | 1.26x |
| `sao-fixed-5m` | 1455 | 674 | 2.16x | 2.06x |
| `sao-fixed-28m` | 1583 | 819 | 1.93x | 1.76x |
| `sddl2-sao-silesia-28m` | 1127 | 629 | 1.79x | 1.58x |
| `parquet-canonical-sample` | 86 | 59 | 1.45x | 1.51x |
| `parquet-nested-sample` | 104 | 78 | 1.34x | 1.33x |
| `lorem-serial-sample` | 1359 | 1077 | 1.26x | 0.36x |
| `u16-zigzag-sample` | 768 | 565 | 1.36x | 1.45x |

- `u8-rle-16m` lost half its speed in `zrip-decode` 0.8.11, the first
  safe-only release. On the same machine, ozlrip at `d13b17c` decodes it at
  6177 MB/s with `zrip-decode` 0.8.10 and 3293 MB/s with 0.8.11.
- OpenZL C decodes `lorem-serial-sample` 3.6x faster with native CPU flags.
  Most of that time is in its LZ decode loop.
- `era5-le-i32-sample` moves by up to 10% between builds with code layout
  alone.

## Benchmarking

Decode benchmarks compare `ozlrip` against OpenZL C (`libopenzl.a`, called in
process) on frames generated by upstream `zli` from `tmp/openzl-upstream`.
Each case and implementation runs in its own process. Results report decoded
MB/s and are appended to `~/.cache/ozlrip/<arch>/<impl>.jsonl`
(`OZLRIP_BENCH_CACHE_DIR` overrides the directory).

```sh
scripts/bench.sh                      # portable build, the default
scripts/bench.sh --native             # both sides with native CPU flags
scripts/bench.sh --case csv-pums-sample --target-ms 1000
```

Portable and native builds use separate target directories and separate
OpenZL builds, so the two flavors never mix.
