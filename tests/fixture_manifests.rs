use std::collections::BTreeSet;

const RELEASE_MATRIX: &str = include_str!("fixtures/openzl-release-matrix.tsv");
const NODE_COVERAGE: &str = include_str!("fixtures/standard-node-coverage.tsv");

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
