//! Normalized edge records (wot-model §2.1).

use serde_json::{Number, Value};

use crate::subject::{Subject, SubjectType};
use crate::{KIND_RATING, KIND_TRUST};

/// A rating score in micro-units (`score · 10⁶`), exact for ≤ 6 decimals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScoreMicro(pub u32);

impl ScoreMicro {
    pub const MAX: u32 = 100_000_000;

    /// Parses a canonical score (`canonicalizeRatingScore` grammar):
    /// `0|[1-9]\d*` with an optional fraction of ≤ 6 digits, in `[0, 100]`.
    /// Returns the micro value and whether the string is already canonical
    /// (no trailing fraction zeros).
    pub fn parse(value: &str) -> Option<(ScoreMicro, bool)> {
        let (int_part, frac_part) = match value.split_once('.') {
            Some((i, f)) => (i, Some(f)),
            None => (value, None),
        };
        if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if int_part.len() > 1 && int_part.starts_with('0') {
            return None;
        }
        let mut canonical = true;
        let mut micro: u64 = int_part.parse::<u64>().ok()?.checked_mul(1_000_000)?;
        if let Some(frac) = frac_part {
            if frac.is_empty() || frac.len() > 6 || !frac.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            if frac.ends_with('0') {
                canonical = false;
            }
            let padded = format!("{frac:0<6}");
            micro += padded.parse::<u64>().ok()?;
        }
        if micro > u64::from(ScoreMicro::MAX) {
            return None;
        }
        Some((ScoreMicro(micro as u32), canonical))
    }

    /// The score as a JavaScript-compatible JSON number (`12`, `12.5`).
    pub fn to_json(self) -> Value {
        if self.0.is_multiple_of(1_000_000) {
            Value::Number(Number::from(self.0 / 1_000_000))
        } else {
            let text = self.to_canonical_string();
            let float: f64 = text.parse().expect("canonical score parses");
            Value::Number(Number::from_f64(float).expect("finite score"))
        }
    }

    /// Canonical wire string.
    pub fn to_canonical_string(self) -> String {
        let int = self.0 / 1_000_000;
        let frac = self.0 % 1_000_000;
        if frac == 0 {
            return int.to_string();
        }
        let frac = format!("{frac:06}");
        format!("{int}.{}", frac.trim_end_matches('0'))
    }

    /// The score as `f64` (same value JavaScript `Number()` yields).
    pub fn as_f64(self) -> f64 {
        self.to_canonical_string()
            .parse()
            .expect("canonical score parses")
    }
}

/// The evidence value of a non-Delete record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordValue {
    /// Kind 32009: `-1`, `0`, or `1`.
    Trust(i8),
    /// Kind 32014: score in micro-units.
    Score(ScoreMicro),
}

/// One normalized `32009` / `32014` record. `value == None` is a Delete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeRecord {
    /// Event id (64 lowercase hex).
    pub id: String,
    /// Author pubkey (64 lowercase hex).
    pub pubkey: String,
    pub kind: u32,
    pub created_at: u64,
    /// The `d` tag (usually 64 hex; opaque to the model).
    pub d: String,
    pub subject_type: SubjectType,
    /// Primary subject value, lowercased.
    pub subject: String,
    pub context: String,
    pub value: Option<RecordValue>,
    pub activate: Option<u64>,
    pub expire: Option<u64>,
    pub scope_rank: u8,
    /// First bare npub hint as hex (only `user:id` + `x.com` trust records).
    pub hint_pubkey: Option<String>,
    pub content: String,
    pub labels: Vec<String>,
    /// Sanitized label descriptions, in first-seen order.
    pub label_hints: Vec<(String, String)>,
}

impl EdgeRecord {
    /// `"<kind>:<pubkey>:<d>"`
    pub fn address_key(&self) -> String {
        format!("{}:{}:{}", self.kind, self.pubkey, self.d)
    }

    pub fn is_delete(&self) -> bool {
        self.value.is_none()
    }

    pub fn subject(&self) -> Subject {
        Subject::new(self.subject_type, self.subject.clone())
    }

    /// Kind 32009 trust value, if any.
    pub fn trust_value(&self) -> Option<i8> {
        match self.value {
            Some(RecordValue::Trust(v)) if self.kind == KIND_TRUST => Some(v),
            _ => None,
        }
    }

    /// Kind 32014 score, if any.
    pub fn score(&self) -> Option<ScoreMicro> {
        match self.value {
            Some(RecordValue::Score(s)) if self.kind == KIND_RATING => Some(s),
            _ => None,
        }
    }

    /// Active at `t` (wot-model §4.1): value present and inside `[x, y]`.
    pub fn is_active_at(&self, t: u64) -> bool {
        self.value.is_some()
            && self.activate.is_none_or(|x| t >= x)
            && self.expire.is_none_or(|y| t <= y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_grammar() {
        assert_eq!(ScoreMicro::parse("0"), Some((ScoreMicro(0), true)));
        assert_eq!(
            ScoreMicro::parse("100"),
            Some((ScoreMicro(100_000_000), true))
        );
        assert_eq!(
            ScoreMicro::parse("12.5"),
            Some((ScoreMicro(12_500_000), true))
        );
        assert_eq!(
            ScoreMicro::parse("12.50"),
            Some((ScoreMicro(12_500_000), false))
        );
        assert_eq!(ScoreMicro::parse("0.000001"), Some((ScoreMicro(1), true)));
        assert_eq!(ScoreMicro::parse("0.0000001"), None);
        assert_eq!(ScoreMicro::parse("100.1"), None);
        assert_eq!(ScoreMicro::parse("01"), None);
        assert_eq!(ScoreMicro::parse(".5"), None);
        assert_eq!(ScoreMicro::parse("5."), None);
        assert_eq!(ScoreMicro::parse("1e2"), None);
        assert_eq!(ScoreMicro::parse("+5"), None);
        assert_eq!(ScoreMicro::parse(" 5"), None);
        assert_eq!(ScoreMicro::parse("-0"), None);
    }

    #[test]
    fn score_json_matches_js_numbers() {
        assert_eq!(ScoreMicro(12_000_000).to_json().to_string(), "12");
        assert_eq!(ScoreMicro(12_500_000).to_json().to_string(), "12.5");
        assert_eq!(ScoreMicro(1).to_json().as_f64(), Some(0.000001));
        assert_eq!(ScoreMicro(33_333_333).to_json().to_string(), "33.333333");
    }
}
