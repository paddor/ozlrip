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
- [ ] Dictionary bundle materialization
- [ ] External/custom codecs
- [ ] Custom transform execution
- [ ] Broad release-tag interop matrix
- [ ] Committed fixture coverage for every standard node variant
- [ ] Some unobserved transform header variants

## Performance

- Baseline: in-process `openzl-c-ffi`, not the `zli` CLI.
- Default features: about `1.26x` mean, `1.14x` median OpenZL C on the current
  generated corpus.
- Default representative range: about `1.0x-1.3x` on CSV/numeric/table cases;
  stored/serial outliers can be higher.
- `paranoid`: about `0.75x-1.0x` OpenZL C on focused guards.
- `paranoid` representative range: CSV/numeric samples around `0.78x-0.82x`,
  SAO-style bitpack around `0.9x`, LZ-heavy serial near parity.
- Noisy/shape-sensitive rows: PUMS CSV, ERA5-shaped data, large RLE output.

## Benchmarking

Decode benchmarks report decoded MB/s and append JSONL results under
`~/.cache/ozlrip/<arch>/<impl>.jsonl`.

```sh
cargo bench --manifest-path bench/Cargo.toml --bench decode_profiles
```

The benchmark uses `rust-openzl` as a bench-only dependency to generate upstream
OpenZL frames and compare `ozlrip` against `openzl-c-ffi` in process.
