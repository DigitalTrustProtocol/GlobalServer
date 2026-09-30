//! Session suite (TrustGraph `corpus/README.md` § Session suite and
//! `packages/conformance/src/session-runner.ts`): scripted WebSocket
//! sessions. This module loads scripts, plans steps, and matches frames; the
//! WebSocket driver lives in `tests/sessions.rs` because it needs a started
//! server.
//!
//! Capability gating follows the TypeScript runner: a session or step may
//! list `requires`. An operation name must appear in the server's
//! `dtp.capabilities`; `fixed:Gn` holds when `dtp.gaps` does not list `Gn`.
//! When a requirement fails the step asserts `otherwise`, else it is skipped.
//! A server that fixes a gap drops it from `dtp.gaps`, so it asserts
//! `expect`.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::canon::expand_placeholders;

const NUMBER_TOLERANCE: f64 = 1e-9;

/// One loaded session script (placeholders expanded).
#[derive(Clone, Debug)]
pub struct Session {
    pub file: PathBuf,
    pub script: Value,
}

impl Session {
    pub fn id(&self) -> &str {
        self.script
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("session")
    }

    pub fn config(&self) -> serde_json::Map<String, Value> {
        self.script
            .get("config")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    }

    pub fn steps(&self) -> &[Value] {
        self.script
            .get("steps")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Whether the session or any step lists `requires`.
    pub fn needs_features(&self) -> bool {
        !requires(&self.script).is_empty() || self.steps().iter().any(|s| !requires(s).is_empty())
    }
}

/// What a server says it supports: `dtp.capabilities` and `dtp.gaps`.
#[derive(Clone, Debug, Default)]
pub struct Features {
    pub capabilities: Vec<String>,
    pub gaps: Vec<String>,
}

impl Features {
    /// Reads `capabilities` / `gaps` from an `info` result.
    pub fn from_info(info: &Value) -> Option<Features> {
        let strings = |v: Option<&Value>| -> Option<Vec<String>> {
            v?.as_array()?
                .iter()
                .map(|s| s.as_str().map(String::from))
                .collect()
        };
        Some(Features {
            capabilities: strings(info.get("capabilities"))?,
            gaps: strings(info.get("gaps")).unwrap_or_default(),
        })
    }

    pub fn met(&self, requirement: &str) -> bool {
        match requirement.strip_prefix("fixed:") {
            Some(gap) => !self.gaps.iter().any(|g| g == gap),
            None => self.capabilities.iter().any(|c| c == requirement),
        }
    }
}

fn requires(v: &Value) -> Vec<&str> {
    v.get("requires")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn frames<'a>(step: &'a Value, key: &str) -> Option<&'a [Value]> {
    step.get(key).and_then(Value::as_array).map(Vec::as_slice)
}

/// What to assert for one step; `None` means skipped.
pub fn plan_step<'a>(
    session: &Session,
    step: &'a Value,
    features: Option<&Features>,
) -> Option<&'a [Value]> {
    let met = |v: &Value| {
        requires(v)
            .iter()
            .all(|r| features.is_some_and(|f| f.met(r)))
    };
    if met(&session.script) && met(step) {
        frames(step, "expect")
    } else {
        frames(step, "otherwise")
    }
}

/// Whether any expected frame is a `DTP-PUSH` (other pushes are dropped).
pub fn wants_push(expected: &[Value]) -> bool {
    expected
        .iter()
        .any(|f| f.get(0).and_then(Value::as_str) == Some("DTP-PUSH"))
}

/// Session scripts listed by `manifest.sessions`, otherwise every
/// `sessions/*.json` below `dir`.
pub fn load_sessions(dir: &Path) -> Result<Vec<Session>, String> {
    let listed: Option<Vec<PathBuf>> = std::fs::read_to_string(dir.join("manifest.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .and_then(|m| m.get("sessions").and_then(Value::as_array).cloned())
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|p| dir.join(p))
                .collect()
        });
    let files = match listed {
        Some(files) => files,
        None => {
            let mut files: Vec<PathBuf> = std::fs::read_dir(dir.join("sessions"))
                .map(|rd| rd.flatten().map(|e| e.path()).collect())
                .unwrap_or_default();
            files.retain(|p| p.extension().and_then(|e| e.to_str()) == Some("json"));
            files.sort();
            files
        }
    };
    files
        .into_iter()
        .map(|file| {
            let text =
                std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
            let raw: Value =
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
            Ok(Session {
                script: expand_placeholders(&raw),
                file,
            })
        })
        .collect()
}

fn is_matcher(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|o| o.keys().any(|k| k.starts_with('$')))
}

fn type_name(v: Option<&Value>) -> &'static str {
    match v {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn show(v: Option<&Value>) -> String {
    let s = v.map_or_else(|| "undefined".to_string(), Value::to_string);
    if s.chars().count() > 200 {
        format!("{}…", s.chars().take(200).collect::<String>())
    } else {
        s
    }
}

/// Pairs every pattern with a distinct item (small arrays; backtracking).
fn match_unordered(actual: &[Value], patterns: &[Value], path: &str, errors: &mut Vec<String>) {
    if actual.len() != patterns.len() {
        errors.push(format!(
            "{path}: expected {} items, got {}",
            patterns.len(),
            actual.len()
        ));
        return;
    }
    fn assign(p: usize, actual: &[Value], patterns: &[Value], used: &mut [bool]) -> bool {
        if p == patterns.len() {
            return true;
        }
        for a in 0..actual.len() {
            if used[a] {
                continue;
            }
            let mut e = Vec::new();
            match_frame(Some(&actual[a]), &patterns[p], "", &mut e);
            if !e.is_empty() {
                continue;
            }
            used[a] = true;
            if assign(p + 1, actual, patterns, used) {
                return true;
            }
            used[a] = false;
        }
        false
    }
    let mut used = vec![false; actual.len()];
    if !assign(0, actual, patterns, &mut used) {
        errors.push(format!(
            "{path}: no order of {} matches the expected items",
            show(Some(&Value::Array(actual.to_vec())))
        ));
    }
}

/// Partial match of one frame: `$prefix` / `$type` / `$any` / `$unordered`
/// matchers, arrays by position with equal length, objects by the keys
/// `expected` names, numbers within `1e-9`. `null` also matches an absent
/// field (README § Canonical comparison; the TypeScript `matchFrame`
/// requires a literal `null`, see PLAN.md).
pub fn match_frame(actual: Option<&Value>, expected: &Value, path: &str, errors: &mut Vec<String>) {
    if is_matcher(expected) {
        if expected.get("$any") == Some(&Value::Bool(true)) {
            return;
        }
        if let Some(prefix) = expected.get("$prefix").and_then(Value::as_str) {
            if !actual
                .and_then(Value::as_str)
                .is_some_and(|s| s.starts_with(prefix))
            {
                errors.push(format!(
                    "{path}: expected prefix {prefix}, got {}",
                    show(actual)
                ));
            }
            return;
        }
        if let Some(ty) = expected.get("$type").and_then(Value::as_str) {
            if type_name(actual) != ty {
                errors.push(format!("{path}: expected {ty}, got {}", type_name(actual)));
            }
            return;
        }
        if let Some(patterns) = expected.get("$unordered").and_then(Value::as_array) {
            match actual.and_then(Value::as_array) {
                Some(items) => match_unordered(items, patterns, path, errors),
                None => errors.push(format!("{path}: expected array")),
            }
            return;
        }
        errors.push(format!("{path}: unknown matcher"));
        return;
    }
    match expected {
        Value::Null => {
            if !matches!(actual, None | Some(Value::Null)) {
                errors.push(format!("{path}: expected null, got {}", show(actual)));
            }
        }
        Value::Number(n) => {
            let ok = actual
                .and_then(Value::as_f64)
                .zip(n.as_f64())
                .is_some_and(|(a, e)| (a - e).abs() <= NUMBER_TOLERANCE);
            if !ok {
                errors.push(format!("{path}: expected {n}, got {}", show(actual)));
            }
        }
        Value::Bool(_) | Value::String(_) => {
            if actual != Some(expected) {
                errors.push(format!("{path}: expected {expected}, got {}", show(actual)));
            }
        }
        Value::Array(items) => {
            let Some(got) = actual.and_then(Value::as_array) else {
                errors.push(format!("{path}: expected array, got {}", show(actual)));
                return;
            };
            if got.len() != items.len() {
                errors.push(format!(
                    "{path}: expected {} items, got {}: {}",
                    items.len(),
                    got.len(),
                    show(actual)
                ));
                return;
            }
            for (i, item) in items.iter().enumerate() {
                match_frame(got.get(i), item, &format!("{path}[{i}]"), errors);
            }
        }
        Value::Object(fields) => {
            let Some(got) = actual.and_then(Value::as_object) else {
                errors.push(format!("{path}: expected object, got {}", show(actual)));
                return;
            };
            for (k, v) in fields {
                match_frame(got.get(k), v, &format!("{path}.{k}"), errors);
            }
        }
    }
}

/// Outcome of one step.
#[derive(Clone, Debug)]
pub enum StepOutcome {
    Pass,
    Fail(Vec<String>),
    /// A requirement was not met and the step has no `otherwise`.
    Skip,
}

/// Per-session tally.
#[derive(Debug, Default)]
pub struct SessionReport {
    pub id: String,
    pub steps: Vec<(usize, Option<String>, StepOutcome)>,
}

impl SessionReport {
    fn count(&self, f: impl Fn(&StepOutcome) -> bool) -> usize {
        self.steps.iter().filter(|(_, _, o)| f(o)).count()
    }

    pub fn failed(&self) -> usize {
        self.count(|o| matches!(o, StepOutcome::Fail(_)))
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "{}: {} steps: {} passed, {} failed, {} skipped",
            self.id,
            self.steps.len(),
            self.count(|o| matches!(o, StepOutcome::Pass)),
            self.failed(),
            self.count(|o| matches!(o, StepOutcome::Skip)),
        );
        for (i, note, o) in &self.steps {
            let label = match note {
                Some(n) => format!("step {i} ({n})"),
                None => format!("step {i}"),
            };
            match o {
                StepOutcome::Pass => {}
                StepOutcome::Fail(errs) => {
                    s.push_str(&format!("\n  FAIL {label}"));
                    for e in errs.iter().take(8) {
                        s.push_str(&format!("\n    - {e}"));
                    }
                }
                StepOutcome::Skip => s.push_str(&format!("\n  SKIP {label}")),
            }
        }
        s
    }
}

/// Judges one step from the frames received (at most `expected.len()`).
pub fn judge(step: &Value, expected: &[Value], got: &[Value]) -> StepOutcome {
    let mut errors = Vec::new();
    if got.len() < expected.len() {
        errors.push(format!(
            "expected {} frames, got {}: {}",
            expected.len(),
            got.len(),
            show(Some(&Value::Array(got.to_vec())))
        ));
    } else if step.get("unordered") == Some(&Value::Bool(true)) {
        match_unordered(got, expected, "frames", &mut errors);
    } else {
        for (i, frame) in expected.iter().enumerate() {
            match_frame(got.get(i), frame, &format!("frame[{i}]"), &mut errors);
        }
    }
    if errors.is_empty() {
        StepOutcome::Pass
    } else {
        StepOutcome::Fail(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn errs(actual: Value, expected: Value) -> Vec<String> {
        let mut e = Vec::new();
        match_frame(Some(&actual), &expected, "$", &mut e);
        e
    }

    #[test]
    fn matchers() {
        assert!(errs(json!("invalid: x"), json!({"$prefix": "invalid:"})).is_empty());
        assert!(!errs(json!("blocked: x"), json!({"$prefix": "invalid:"})).is_empty());
        assert!(errs(json!(3), json!({"$type": "number"})).is_empty());
        assert!(!errs(json!("3"), json!({"$type": "number"})).is_empty());
        assert!(errs(json!({"a": 1}), json!({"$any": true})).is_empty());
        assert!(errs(json!([2, 1]), json!({"$unordered": [1, 2]})).is_empty());
        assert!(!errs(json!([2, 2]), json!({"$unordered": [1, 2]})).is_empty());
    }

    #[test]
    fn partial_objects_and_exact_arrays() {
        assert!(errs(json!({"a": 1, "b": 2}), json!({"a": 1})).is_empty());
        assert!(errs(json!({"a": 1}), json!({"z": null})).is_empty());
        assert!(!errs(json!([1, 2]), json!([1])).is_empty());
        assert!(errs(json!([1.0, "x"]), json!([1, "x"])).is_empty());
        assert!(errs(json!(0.0000015), json!(1.5e-6)).is_empty());
    }

    #[test]
    fn gating_and_unordered_steps() {
        let session = Session {
            file: PathBuf::new(),
            script: json!({ "requires": ["fixed:G10"], "steps": [] }),
        };
        let step = json!({ "requires": ["graph.field"], "expect": [["A"]], "otherwise": [["B"]] });
        let full = Features {
            capabilities: vec!["graph.field".into()],
            gaps: vec![],
        };
        let gapped = Features {
            capabilities: vec!["graph.field".into()],
            gaps: vec!["G10".into()],
        };
        assert_eq!(
            plan_step(&session, &step, Some(&full)),
            Some(&[json!(["A"])][..])
        );
        assert_eq!(
            plan_step(&session, &step, Some(&gapped)),
            Some(&[json!(["B"])][..])
        );
        let bare = json!({ "requires": ["graph.field"], "expect": [["A"]] });
        assert_eq!(plan_step(&session, &bare, Some(&gapped)), None);

        let step = json!({ "unordered": true });
        let expected = [json!(["OK"]), json!(["DTP-PUSH"])];
        assert!(matches!(
            judge(&step, &expected, &[json!(["DTP-PUSH"]), json!(["OK"])]),
            StepOutcome::Pass
        ));
        assert!(wants_push(&expected));
    }
}
