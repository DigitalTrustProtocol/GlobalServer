//! `dtp-conformance`: runner for the `dtp-wot-corpus/1` format of
//! TrustGraph `conformance.md`, plus the model properties.
//!
//! Local extensions (proposed upstream, see PLAN.md): record fields may be
//! omitted and get defaults; the op `delete` applies a NIP-09 deletion;
//! trust / rating inputs may carry `maxReachedNodes` / `maxWalkRecords`
//! budgets; protocol cases compare this implementation's error codes.

pub mod canon;
pub mod case;
pub mod protocol;

use std::path::{Path, PathBuf};

use serde_json::Value;

pub use case::{CaseOutcome, run_model_case};

/// Result of running a set of cases.
#[derive(Debug, Default)]
pub struct Report {
    pub total: usize,
    pub passed: usize,
    pub failures: Vec<(String, Vec<String>)>,
    pub skipped: Vec<(String, String)>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "{} cases: {} passed, {} failed, {} skipped",
            self.total,
            self.passed,
            self.failures.len(),
            self.skipped.len()
        );
        for (id, errs) in &self.failures {
            s.push_str(&format!("\n  FAIL {id}"));
            for e in errs.iter().take(8) {
                s.push_str(&format!("\n    - {e}"));
            }
        }
        for (id, why) in &self.skipped {
            s.push_str(&format!("\n  SKIP {id}: {why}"));
        }
        s
    }

    fn absorb(&mut self, id: String, outcome: CaseOutcome) {
        self.total += 1;
        match outcome {
            CaseOutcome::Pass => self.passed += 1,
            CaseOutcome::Fail(errs) => self.failures.push((id, errs)),
            CaseOutcome::Skip(why) => self.skipped.push((id, why)),
        }
    }
}

/// Runs one case value (model or protocol).
pub fn run_case(case: &Value) -> CaseOutcome {
    let case = canon::expand_placeholders(case);
    if case.get("event").is_some() || case.get("kind").and_then(Value::as_str) == Some("protocol") {
        protocol::run_protocol_case(&case)
    } else if case.get("records").is_some()
        || case.get("ops").is_some()
        || case.get("queries").is_some()
    {
        run_model_case(&case)
    } else {
        CaseOutcome::Skip("unrecognized case shape".into())
    }
}

fn case_id(case: &Value, fallback: &str) -> String {
    case.get("id")
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_string()
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("generators") {
                continue;
            }
            collect_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("json")
            && path.file_name().and_then(|n| n.to_str()) != Some("manifest.json")
        {
            out.push(path);
        }
    }
}

/// Runs every case under `dir`: the files listed by `manifest.json` when it
/// lists paths, otherwise every `*.json` below `dir` (except generators).
pub fn run_dir(dir: &Path) -> Report {
    let mut report = Report::default();
    let mut files: Vec<PathBuf> = Vec::new();
    let mut inline: Vec<Value> = Vec::new();
    if let Ok(text) = std::fs::read_to_string(dir.join("manifest.json"))
        && let Ok(manifest) = serde_json::from_str::<Value>(&text)
        && let Some(cases) = manifest.get("cases").and_then(Value::as_array)
    {
        for c in cases {
            match c {
                Value::String(p) => files.push(dir.join(p)),
                Value::Object(o) => match o
                    .get("path")
                    .or_else(|| o.get("file"))
                    .and_then(Value::as_str)
                {
                    Some(p) => files.push(dir.join(p)),
                    None => inline.push(c.clone()),
                },
                _ => {}
            }
        }
    }
    if files.is_empty() && inline.is_empty() {
        collect_files(dir, &mut files);
    }
    for (i, case) in inline.iter().enumerate() {
        report.absorb(case_id(case, &format!("inline-{i}")), run_case(case));
    }
    for file in files {
        let name = file.display().to_string();
        let parsed = std::fs::read_to_string(&file)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str::<Value>(&t).map_err(|e| e.to_string()));
        match parsed {
            Err(e) => {
                report.total += 1;
                report
                    .failures
                    .push((name, vec![format!("unreadable: {e}")]));
            }
            Ok(Value::Array(cases)) => {
                for (i, case) in cases.iter().enumerate() {
                    report.absorb(case_id(case, &format!("{name}#{i}")), run_case(case));
                }
            }
            Ok(Value::Object(obj)) if obj.get("cases").is_some_and(Value::is_array) => {
                for (i, case) in obj["cases"].as_array().into_iter().flatten().enumerate() {
                    report.absorb(case_id(case, &format!("{name}#{i}")), run_case(case));
                }
            }
            Ok(case) => report.absorb(case_id(&case, &name), run_case(&case)),
        }
    }
    report
}
