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
let mut limits = ozlrip::Limits::paranoid();
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
- `paranoid`: forbids unsafe code in `ozlrip` and in the `zrip` and `lz4rip`
  code it calls, and takes the safe paths. It does not change the limits;
  use `Limits::paranoid` for tighter ones.
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
- [x] `paranoid` safe-code baseline
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

- Baseline: in-process `openzl-c-ffi`, not the `zli` CLI.
- Default features: latest local checksum bench pass is at or above OpenZL C on
  most generated cases; shape-sensitive rows still need repeated runs on quiet
  hardware.
- Representative parity rows from the last perf pass: CSV time-series
  `1.00x-1.01x`, SDDL2/SAO `1.07x`, ERA5-shaped i32 `1.25x` in isolated rerun.
- `paranoid`: about `1.27x` mean, `0.99x` median OpenZL C on the current
  generated corpus.
- `paranoid` representative range: CSV/numeric samples around `0.70x-0.79x`,
  SAO-style bitpack around `0.90x-0.94x`, LZ-heavy serial around
  `1.00x-1.39x`.
- Noisy/shape-sensitive rows: PUMS CSV, ERA5-shaped data, tiny parquet samples,
  large RLE output, and short stored/serial frames.

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
