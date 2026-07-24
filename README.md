# ozlrip

Memory-safe Rust decoder for OpenZL.

## API

```rust
let decoded = ozlrip::decode(frame)?;

let mut dst = Vec::new();
let written = ozlrip::decode_into(frame, &mut dst)?;

let info = ozlrip::inspect(frame)?;

let options = ozlrip::Options {
    limits: ozlrip::Limits::strict(),
    plan_cache_max_frame_bytes: 0,
    ..ozlrip::Options::default()
};
let decoded = ozlrip::decode_with_options(frame, options)?;
```

For reusable allocation state, create `ozlrip::Decoder` and call
`Decoder::decode` or `Decoder::decode_into`. Use `Decoder::with_options` when
the default decoder options are not the right fit.

## Current Scope

- [x] Defensive frame parsing, inspection, limits, and typed errors
- [x] Whole-graph validation before execution
- [x] Stored streams, checksums, zstd via `zrip`, lz4 via `lz4rip`
- [x] Core graph transforms: concat, splitN, split-by-struct, transpose split,
  bit split, mux lengths, dispatch string, dispatchN-byTag
- [x] Numeric/table transforms: endian conversion, delta, zigzag, bitpack,
  bitunpack, range-pack, flatpack, sparse num, partition, quantize
- [x] Text/reconstruction transforms: tokenizer, parse-int, LZ, field-LZ
- [x] `paranoid` safe-code baseline
- [x] OpenZL `dev-format` v27 metadata and PivCo-Huffman graph validation
- [x] PivCo-Huffman payload decode, safe scalar path, and std-gated SIMD merge
- [x] Fat-bundle dictionary materialization for zstd
- [ ] External/custom codecs
- [ ] Custom transform execution
- [ ] Broad release-tag interop matrix
- [ ] Committed fixture coverage for every standard node variant
- [ ] Some unobserved transform header variants

## Performance

- Baseline: in-process `openzl-c-ffi`, not the `zli` CLI.
- Default features: about `1.41x` mean, `1.17x` median OpenZL C on the current
  generated corpus.
- Default representative range: about `0.9x-1.4x` on CSV/numeric/table/SAO
  cases; stored/serial and tiny-sample outliers can be higher.
- `paranoid`: about `1.27x` mean, `0.99x` median OpenZL C on the current
  generated corpus.
- `paranoid` representative range: CSV/numeric samples around `0.70x-0.79x`,
  SAO-style bitpack around `0.90x-0.94x`, LZ-heavy serial around
  `1.00x-1.39x`.
- Noisy/shape-sensitive rows: PUMS CSV, ERA5-shaped data, tiny parquet samples,
  large RLE output, and short stored/serial frames.

## Benchmarking

Decode benchmarks report decoded MB/s and append JSONL results under
`~/.cache/ozlrip/<arch>/<impl>.jsonl`.

```sh
cargo bench --manifest-path bench/Cargo.toml --bench decode_profiles
```

The benchmark uses `rust-openzl` as a bench-only dependency to generate upstream
OpenZL frames and compare `ozlrip` against `openzl-c-ffi` in process.
