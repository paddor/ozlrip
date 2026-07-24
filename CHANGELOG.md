# Changelog

## [Unreleased]

- Accept OpenZL format v27 metadata behind `dev-format`, including
  `pivco_huffman` graph validation, safe scalar payload decode, and std-gated
  SIMD merge acceleration.
- Load OpenZL fat dictionary bundles through `Decoder` and decode
  zstd-dictionary-backed frames.

## [0.1.0]

- Initial release: decoder-first OpenZL implementation for standard-codec
  frames, with defensive frame parsing, whole-graph validation before
  execution, typed errors, and configurable limits.
- Public API: `decode`, `decode_into`, `decode_with_options`,
  `decode_into_with_options`, `inspect`, and a reusable `Decoder`.
- Stored streams, chunk and output checksums, zstd nodes via `zrip`, and lz4
  nodes via `lz4rip`.
- Graph transforms: concat, splitN, split-by-struct, transpose split, bit
  split, mux lengths, dispatch string, and dispatchN-byTag.
- Numeric and table transforms: endian conversion, delta, zigzag, bitpack,
  bitunpack, range-pack, flatpack, sparse num, partition, and quantize.
- Text and reconstruction transforms: tokenizer, parse-int, LZ, and field-LZ.
- `paranoid` feature as a safe-code correctness baseline, `no_std` support via
  `alloc`, and typed `Unsupported` errors for dictionaries, materialized
  bundles, and custom codecs.
