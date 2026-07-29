use std::collections::BTreeSet;

const RELEASE_MATRIX: &str = include_str!("fixtures/openzl-release-matrix.tsv");
const NODE_COVERAGE: &str = include_str!("fixtures/standard-node-coverage.tsv");
const ERROR_TAXONOMY: &str = include_str!("fixtures/error-taxonomy.tsv");
const FEATURE_COMPATIBILITY: &str = include_str!("fixtures/feature-compatibility.tsv");

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
        assert!(
            cases.insert(row[0]),
            "duplicate error taxonomy case {}",
            row[0]
        );
        assert!(
            matches!(
                row[1],
                "unsupported"
                    | "malformed"
                    | "truncated"
                    | "limit"
                    | "invalid_graph"
                    | "invalid_type"
                    | "overflow"
                    | "checksum"
            ),
            "bad error taxonomy category {}",
            row[1]
        );
        assert!(
            matches!(row[2], "inspect" | "decode" | "load-dictionary"),
            "bad error taxonomy operation {}",
            row[2]
        );
        assert!(
            matches!(
                row[3],
                "Unsupported"
                    | "Malformed"
                    | "Truncated"
                    | "LimitExceeded"
                    | "ChecksumMismatch"
                    | "InvalidGraph"
                    | "InvalidType"
                    | "IntegerOverflow"
            ),
            "bad error taxonomy kind {}",
            row[3]
        );
        assert!(
            matches!(row[4], "none" | "checksum"),
            "bad error taxonomy feature {}",
            row[4]
        );
        categories.insert(row[1]);
        kinds.insert(row[3]);
    }

    for category in [
        "unsupported",
        "malformed",
        "truncated",
        "limit",
        "invalid_graph",
        "invalid_type",
        "overflow",
        "checksum",
    ] {
        assert!(
            categories.contains(category),
            "missing error taxonomy category {category}"
        );
    }

    for kind in [
        "Unsupported",
        "Malformed",
        "Truncated",
        "LimitExceeded",
        "ChecksumMismatch",
        "InvalidGraph",
        "InvalidType",
        "IntegerOverflow",
    ] {
        assert!(kinds.contains(kind), "missing error taxonomy kind {kind}");
    }
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
        assert!(
            features.insert(row[0]),
            "duplicate feature compatibility feature {}",
            row[0]
        );
        assert!(
            cases.insert(row[1]),
            "duplicate feature compatibility case {}",
            row[1]
        );
        assert!(
            matches!(
                row[2],
                "serial"
                    | "u8"
                    | "i8"
                    | "le-u16"
                    | "le-i32"
                    | "csv"
                    | "sao"
                    | "sddl2"
                    | "parquet"
                    | "numeric-ml-selector-64"
                    | "zstd"
            ),
            "bad feature compatibility profile {}",
            row[2]
        );
        assert!(!row[3].is_empty(), "profile_arg must be present");
        assert!(!row[4].is_empty(), "coverage must be present");
        profiles.insert(row[2]);
    }

    for feature in [
        "serial-profile",
        "csv-dispatch",
        "sao-structured",
        "sddl2-structured",
        "parquet-structured",
        "zstd-profile",
    ] {
        assert!(
            features.contains(feature),
            "missing feature compatibility row for {feature}"
        );
    }

    for profile in ["serial", "csv", "sao", "sddl2", "parquet", "zstd"] {
        assert!(
            profiles.contains(profile),
            "missing feature compatibility profile {profile}"
        );
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
