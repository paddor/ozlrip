# Changelog

## [Unreleased]

## [0.3.0]

- Decode OpenZL `prefix` string reconstruction nodes.
- Decode OpenZL `dedup_num` nodes that regenerate multiple numeric streams.
- Decode OpenZL `divide_by` numeric nodes with checked reconstruction.
- Decode OpenZL `splitn_num` numeric split nodes, including empty numeric
  outputs that carry element width in the transform header.

## [0.2.0]

- Accept OpenZL format v27 metadata behind `dev-format`, including
  `pivco_huffman` graph validation, safe scalar payload decode, and std-gated
  SIMD merge acceleration.
- Load OpenZL fat dictionary bundles through `Decoder` and decode
  zstd-dictionary-backed frames.
- Track OpenZL release-checkpoint interop and standard-node fixture coverage in
  committed manifests.
- Add fuzz entry points for public-frame Field-LZ and dispatch-string graphs.
- Decode OpenZL `constant_fixed` typed repeat streams.
- Speed up constant repeat fills and quantized numeric reconstruction.
- Pin public API behavior for custom transforms and unsupported dictionary
  materializers to typed `Unsupported` errors.

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
