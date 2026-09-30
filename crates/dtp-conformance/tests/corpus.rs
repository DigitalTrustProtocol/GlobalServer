use std::path::PathBuf;

fn workspace() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn local_cases_pass() {
    let dir = workspace().join("tests").join("cases");
    let report = dtp_conformance::run_dir(&dir);
    println!("local cases ({}): {}", dir.display(), report.summary());
    assert!(report.total > 0, "no local cases found");
    assert!(report.ok(), "{}", report.summary());
}

/// Runs the shared TrustGraph corpus when it exists. Report-only unless
/// `DTP_CORPUS_STRICT=1`, because the corpus is written concurrently and its
/// error-code vocabulary is not pinned yet.
#[test]
fn trustgraph_corpus() {
    let dir = workspace().join("..").join("TrustGraph").join("corpus");
    if !dir.exists() {
        println!("TrustGraph corpus not present at {}", dir.display());
        return;
    }
    let report = dtp_conformance::run_dir(&dir);
    println!(
        "TrustGraph corpus ({}): {}",
        dir.display(),
        report.summary()
    );
    if std::env::var("DTP_CORPUS_STRICT").as_deref() == Ok("1") {
        assert!(report.ok(), "{}", report.summary());
    }
}
