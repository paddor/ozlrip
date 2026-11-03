use std::collections::BTreeSet;

const RELEASE_MATRIX: &str = include_str!("fixtures/openzl-release-matrix.tsv");
const NODE_COVERAGE: &str = include_str!("fixtures/standard-node-coverage.tsv");
const ERROR_TAXONOMY: &str = include_str!("fixtures/error-taxonomy.tsv");
const FEATURE_COMPATIBILITY: &str = include_str!("fixtures/feature-compatibility.tsv");

/// Error taxonomy categories. The manifest must use each one at least once.
const ERROR_CATEGORIES: &[&str] = &[
    "unsupported",
    "malformed",
    "truncated",
    "limit",
    "invalid_graph",
    "invalid_type",
    "overflow",
    "checksum",
];

/// Operations an error taxonomy case can run.
const ERROR_OPERATIONS: &[&str] = &["inspect", "decode", "load-dictionary"];

/// Error kinds an error taxonomy case may expect.
const ERROR_KINDS: &[&str] = &[
    "Unsupported",
    "Malformed",
    "Truncated",
    "LimitExceeded",
    "AllocationFailed",
    "ChecksumMismatch",
    "InvalidGraph",
    "InvalidType",
    "IntegerOverflow",
];

/// Error kinds the error taxonomy manifest must cover.
const REQUIRED_ERROR_KINDS: &[&str] = &[
    "Unsupported",
    "Malformed",
    "Truncated",
    "LimitExceeded",
    "ChecksumMismatch",
    "InvalidGraph",
    "InvalidType",
    "IntegerOverflow",
];

/// Features an error taxonomy case may require.
const ERROR_FEATURES: &[&str] = &["none", "lz4"];

/// Profiles a feature compatibility row may name.
const COMPATIBILITY_PROFILES: &[&str] = &[
    "serial",
    "u8",
    "i8",
    "le-u16",
    "le-i32",
    "csv",
    "sao",
    "sddl2",
    "parquet",
    "numeric-ml-selector-64",
    "zstd",
];

#[test]
fn openzl_release_matrix_tracks_known_checkpoints() {
    let rows = parse_tsv(RELEASE_MATRIX, "checkpoint\tkind\tsource\tverification", 4);
    let checkpoints = rows.iter().map(|row| row[0]).collect::<BTreeSet<_>>();

    for checkpoint in ["v0.0.23", "v0.1.0", "v0.2.0", "dev"] {
        assert!(
            checkpoints.contains(checkpoint),
            "missing OpenZL checkpoint {checkpoint}"
        );
    }
}

#[test]
fn standard_node_fixture_manifest_has_one_row_per_node() {
    let rows = parse_tsv(NODE_COVERAGE, "id\tname\tcoverage", 3);
    let mut ids = BTreeSet::new();

    for row in rows {
        let id = row[0]
            .parse::<u32>()
            .expect("standard-node id must be numeric");
        assert!(ids.insert(id), "duplicate standard-node id {id}");
        assert!(!row[1].is_empty(), "standard-node name must not be empty");
        assert!(
            !row[2].is_empty(),
            "standard-node coverage must not be empty"
        );
        let mut coverage_tags = BTreeSet::new();
        for tag in row[2].split('+') {
            assert!(
                coverage_tags.insert(tag),
                "duplicate standard-node coverage tag {tag} for id {id}"
            );
            assert!(
                matches!(tag, "unit" | "inline-frame" | "fuzz" | "interop"),
                "bad standard-node coverage tag {tag} for id {id}"
            );
        }
        assert!(
            coverage_tags.contains("unit"),
            "standard-node coverage must include unit tag for id {id}"
        );
    }

    for id in [1, 22, 24, 54, 62, 66, 67] {
        assert!(
            ids.contains(&id),
            "missing standard-node coverage for id {id}"
        );
    }
}

#[test]
fn error_taxonomy_manifest_tracks_public_error_classes() {
    let rows = parse_tsv(
        ERROR_TAXONOMY,
        "case\tcategory\toperation\texpected_kind\trequired_feature",
        5,
    );
    let mut cases = BTreeSet::new();
    let mut categories = BTreeSet::new();
    let mut kinds = BTreeSet::new();

    for row in rows {
        assert_unique(&mut cases, row[0], "error taxonomy case");
        assert_member(row[1], ERROR_CATEGORIES, "error taxonomy category");
        assert_member(row[2], ERROR_OPERATIONS, "error taxonomy operation");
        assert_member(row[3], ERROR_KINDS, "error taxonomy kind");
        assert_member(row[4], ERROR_FEATURES, "error taxonomy feature");
        categories.insert(row[1]);
        kinds.insert(row[3]);
    }

    assert_covers(&categories, ERROR_CATEGORIES, "error taxonomy category");
    assert_covers(&kinds, REQUIRED_ERROR_KINDS, "error taxonomy kind");
}

#[test]
fn feature_compatibility_manifest_tracks_profiles() {
    let rows = parse_tsv(
        FEATURE_COMPATIBILITY,
        "feature\tcase\tprofile\tprofile_arg\tcoverage",
        5,
    );
    let mut features = BTreeSet::new();
    let mut cases = BTreeSet::new();
    let mut profiles = BTreeSet::new();

    for row in rows {
        assert_unique(&mut features, row[0], "feature compatibility feature");
        assert_unique(&mut cases, row[1], "feature compatibility case");
        assert_member(
            row[2],
            COMPATIBILITY_PROFILES,
            "feature compatibility profile",
        );
        assert!(!row[3].is_empty(), "profile_arg must be present");
        assert!(!row[4].is_empty(), "coverage must be present");
        profiles.insert(row[2]);
    }

    assert_covers(
        &features,
        &[
            "serial-profile",
            "csv-dispatch",
            "sao-structured",
            "sddl2-structured",
            "parquet-structured",
            "zstd-profile",
            "pivco-huffman",
        ],
        "feature compatibility row for",
    );
    assert_covers(
        &profiles,
        &["serial", "csv", "sao", "sddl2", "parquet", "zstd"],
        "feature compatibility profile",
    );
}

/// Asserts that `value` was not seen before and records it in `seen`.
fn assert_unique<'a>(seen: &mut BTreeSet<&'a str>, value: &'a str, what: &str) {
    assert!(seen.insert(value), "duplicate {what} {value}");
}

/// Asserts that `value` is one of `allowed`.
fn assert_member(value: &str, allowed: &[&str], what: &str) {
    assert!(allowed.contains(&value), "bad {what} {value}");
}

/// Asserts that `seen` contains every value in `required`.
fn assert_covers(seen: &BTreeSet<&str>, required: &[&str], what: &str) {
    for value in required {
        assert!(seen.contains(value), "missing {what} {value}");
    }
}

fn parse_tsv<'a>(contents: &'a str, expected_header: &str, columns: usize) -> Vec<Vec<&'a str>> {
    let mut lines = contents.lines();
    assert_eq!(lines.next(), Some(expected_header));
    lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            assert_eq!(fields.len(), columns, "bad TSV row: {line}");
            fields
        })
        .collect()
}
