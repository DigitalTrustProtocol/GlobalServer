//! NIP-32009 / NIP-32014 validation and normalization.
//!
//! Port of `inspectKind32009` / `inspectKind32014` (AttentionX
//! `src/lib/nostr/kind-32009.ts`, `kind-32014.ts`) plus the scope profile and
//! `hintPubkey` extraction of wot-model §2.1.

use crate::content::sanitize;
use crate::event::Event;
use crate::grammar::{
    CONTENT_CHAR_LIMIT, canonical_scope_string, is_canonical_context, is_canonical_label,
    is_canonical_scope, is_identifier_class, is_name, parse_unix_seconds,
};
use crate::keys::decode_npub;
use crate::record::{EdgeRecord, RecordValue, ScoreMicro};
use crate::scope::{ScopeProfile, X_SCOPE};
use crate::subject::{Subject, SubjectType, twitter_account_id};
use crate::{KIND_RATING, KIND_TRUST, is_hex64, sha256_hex};

/// One validation failure with a stable code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    pub code: &'static str,
    pub message: String,
}

impl ValidationError {
    fn new(code: &'static str, message: impl Into<String>) -> ValidationError {
        ValidationError {
            code,
            message: message.into(),
        }
    }
}

/// A subject hint (additional element of the subject tag).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectHint {
    /// Bare npub; holds the decoded hex pubkey.
    Npub(String),
    Structured {
        class: String,
        property: String,
        value: String,
    },
}

/// A protocol-valid statement before the scope profile is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedStatement {
    pub id: String,
    pub pubkey: String,
    pub kind: u32,
    pub created_at: u64,
    pub d: String,
    pub subject: Subject,
    pub value: Option<RecordValue>,
    pub context: String,
    pub scopes: Vec<String>,
    pub labels: Vec<String>,
    pub label_hints: Vec<(String, String)>,
    pub k: Option<String>,
    pub activate: Option<u64>,
    pub expire: Option<u64>,
    pub hints: Vec<SubjectHint>,
    pub content: String,
}

/// Outcome of validating a statement against the protocol and a profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted(Box<EdgeRecord>),
    Invalid(Vec<ValidationError>),
    /// Valid, but the scope profile does not accept it.
    Blocked(String),
}

/// `d` material for a subject, scope set, and context (NIP-32009 § Building d).
pub fn d_material(subject: &Subject, scopes: &[String], context: &str) -> String {
    let scope = canonical_scope_string(scopes);
    match subject.ty {
        SubjectType::P => format!("p:{}:{scope}:{context}", subject.value),
        SubjectType::E => format!("e:{}:{scope}:{context}", subject.value),
        SubjectType::I => format!("{}:{scope}:{context}", subject.value),
    }
}

/// The `d` tag value: SHA-256 of the material.
pub fn compute_d(subject: &Subject, scopes: &[String], context: &str) -> String {
    sha256_hex(&d_material(subject, scopes, context))
}

fn parse_hint(raw: &str) -> Option<SubjectHint> {
    if let Some(hex) = decode_npub(raw) {
        return Some(SubjectHint::Npub(hex));
    }
    let first = raw.find(':')?;
    let second = first + 1 + raw[first + 1..].find(':')?;
    if first == 0 || second <= first + 1 {
        return None;
    }
    let class = &raw[..first];
    let property = &raw[first + 1..second];
    let value = &raw[second + 1..];
    if !is_name(class) || !is_name(property) || value.is_empty() {
        return None;
    }
    Some(SubjectHint::Structured {
        class: class.into(),
        property: property.into(),
        value: value.into(),
    })
}

/// Parses `l` tags: canonical labels (deduplicated, first-seen order) and
/// sanitized descriptions (first non-empty per label).
pub fn parse_labels(
    event: &Event,
    errors: &mut Vec<ValidationError>,
) -> (Vec<String>, Vec<(String, String)>) {
    let mut labels: Vec<String> = Vec::new();
    let mut hints: Vec<(String, String)> = Vec::new();
    for tag in event.tags_named("l") {
        let Some(label) = tag.get(1).filter(|l| !l.is_empty()) else {
            errors.push(ValidationError::new(
                "l-tag",
                "Each l tag must contain a non-empty label",
            ));
            continue;
        };
        if !is_canonical_label(label) {
            errors.push(ValidationError::new("label", "Label is not canonical"));
            continue;
        }
        if !labels.contains(label) {
            labels.push(label.clone());
        }
        if let Some(raw) = tag.get(2).filter(|h| !h.is_empty())
            && !hints.iter().any(|(k, _)| k == label)
        {
            let hint = sanitize(raw, CONTENT_CHAR_LIMIT);
            if !hint.is_empty() {
                hints.push((label.clone(), hint));
            }
        }
    }
    (labels, hints)
}

fn single_two<'a>(
    event: &'a Event,
    name: &'a str,
    code: &'static str,
    errors: &mut Vec<ValidationError>,
) -> Option<&'a str> {
    let tags: Vec<&Vec<String>> = event.tags_named(name).collect();
    if tags.len() > 1 || (tags.len() == 1 && tags[0].len() != 2) {
        errors.push(ValidationError::new(
            code,
            format!("Event may contain at most one two-element {name} tag"),
        ));
        return None;
    }
    tags.first().map(|t| t[1].as_str())
}

/// Validates a `32009` or `32014` event against the protocol (not the scope
/// profile). `verify` checks the id hash and signature.
pub fn parse_statement(
    event: &Event,
    verify: bool,
) -> Result<ParsedStatement, Vec<ValidationError>> {
    let mut errors = Vec::new();
    if event.check_shape().is_err() {
        return Err(vec![ValidationError::new(
            "shape",
            "Event does not have a valid Nostr event shape",
        )]);
    }
    let kind = event.kind;
    let is_rating = kind == KIND_RATING;
    if kind != KIND_TRUST && kind != KIND_RATING {
        errors.push(ValidationError::new(
            "kind",
            "Event kind must be 32009 or 32014",
        ));
    }
    if event.content.chars().count() > CONTENT_CHAR_LIMIT {
        errors.push(ValidationError::new(
            "content-length",
            "Content must not exceed 1024 Unicode characters",
        ));
    }
    if verify && let Err(err) = event.verify() {
        errors.push(ValidationError::new(err.code(), err.to_string()));
    }

    let d_tags: Vec<&Vec<String>> = event.tags_named("d").collect();
    let subject_tags: Vec<&Vec<String>> = event
        .tags
        .iter()
        .filter(|t| matches!(t.first().map(String::as_str), Some("p" | "e" | "i")))
        .collect();
    let value_name = if is_rating { "score" } else { "v" };
    let value_tags: Vec<&Vec<String>> = event.tags_named(value_name).collect();

    let mut d = None;
    if d_tags.len() != 1 || d_tags[0].len() != 2 {
        errors.push(ValidationError::new(
            "d-tag",
            "Event must contain exactly one two-element d tag",
        ));
    } else if !is_hex64(&d_tags[0][1]) {
        errors.push(ValidationError::new(
            "d-format",
            "d tag must be 64 lowercase hexadecimal characters",
        ));
    } else {
        d = Some(d_tags[0][1].clone());
    }
    if subject_tags.len() != 1 || subject_tags[0].len() < 2 {
        errors.push(ValidationError::new(
            "subject-tag",
            "Event must contain exactly one subject tag with a primary value",
        ));
    }
    if value_tags.len() != 1 || value_tags[0].len() != 2 {
        errors.push(ValidationError::new(
            if is_rating { "score-tag" } else { "v-tag" },
            format!("Event must contain exactly one two-element {value_name} tag"),
        ));
    }
    let k_tags = event.tags_named("k").count();
    let k = single_two(event, "k", "k-tag", &mut errors).map(str::to_string);
    let context = single_two(event, "c", "c-tag", &mut errors)
        .unwrap_or("")
        .to_string();
    let activation = single_two(event, "x", "x-tag", &mut errors).map(str::to_string);
    let expiration = single_two(event, "y", "y-tag", &mut errors).map(str::to_string);

    let context_ok = is_canonical_context(&context);
    if !context_ok {
        errors.push(ValidationError::new("context", "Context is not canonical"));
    }

    let mut scopes = Vec::new();
    for tag in event.tags_named("s") {
        if tag.len() != 2 {
            errors.push(ValidationError::new(
                "s-tag",
                "Each s tag must contain exactly one scope value",
            ));
            continue;
        }
        if !is_canonical_scope(&tag[1]) {
            errors.push(ValidationError::new("scope", "Scope is not canonical"));
            continue;
        }
        scopes.push(tag[1].clone());
    }
    scopes.sort();
    scopes.dedup();

    let (labels, label_hints) = parse_labels(event, &mut errors);

    let subject = subject_tags
        .first()
        .filter(|t| t.len() >= 2)
        .and_then(|t| SubjectType::parse(&t[0]).map(|ty| Subject::new(ty, t[1].clone())));
    let mut hints = Vec::new();
    if let Some(tag) = subject_tags.first() {
        for raw in tag.iter().skip(2) {
            match parse_hint(raw) {
                Some(hint) => hints.push(hint),
                None => errors.push(ValidationError::new(
                    "hint",
                    "Additional subject values must be a bare npub1… or class:property:value",
                )),
            }
        }
    }
    let subject_ok = match &subject {
        Some(s) => match s.validation_error() {
            Some(msg) => {
                errors.push(ValidationError::new("subject", msg));
                false
            }
            None => true,
        },
        None => false,
    };

    if let Some(k) = &k {
        if !is_identifier_class(k) {
            errors.push(ValidationError::new(
                "k-format",
                "Identifier class is not canonical",
            ));
        } else {
            match &subject {
                Some(s) if s.ty == SubjectType::I => {
                    let prefix = format!("{k}:");
                    if !s.value.starts_with(&prefix) || s.value.len() <= prefix.len() {
                        errors.push(ValidationError::new(
                            "k-mismatch",
                            "i subject must equal k plus a non-empty value",
                        ));
                    }
                }
                _ => errors.push(ValidationError::new(
                    "k-without-i",
                    "k tag is only valid with an i subject",
                )),
            }
        }
    } else if k_tags > 0 && subject.as_ref().is_some_and(|s| s.ty == SubjectType::I) {
        errors.push(ValidationError::new(
            "k-tag",
            "k tag must contain exactly one identifier class value",
        ));
    }

    let raw_value = value_tags
        .first()
        .and_then(|t| t.get(1))
        .map(String::as_str);
    let mut value: Option<Option<RecordValue>> = None;
    match raw_value {
        None => {}
        Some("") => value = Some(None),
        Some(raw) if is_rating => match ScoreMicro::parse(raw) {
            Some((micro, true)) => value = Some(Some(RecordValue::Score(micro))),
            _ => errors.push(ValidationError::new(
                "score",
                "score must be empty (cancel) or a canonical number in [0, 100]",
            )),
        },
        Some(raw) => match raw {
            "1" => value = Some(Some(RecordValue::Trust(1))),
            "0" => value = Some(Some(RecordValue::Trust(0))),
            "-1" => value = Some(Some(RecordValue::Trust(-1))),
            _ => errors.push(ValidationError::new(
                "value",
                "Trust value must be 1, 0, -1, or empty",
            )),
        },
    }
    let mut unix = |raw: Option<String>, name: &str, code: &'static str| -> Option<u64> {
        let raw = raw?;
        let parsed = parse_unix_seconds(&raw);
        if parsed.is_none() {
            errors.push(ValidationError::new(
                code,
                format!("{name} tag must contain one base-10 Unix-second integer"),
            ));
        }
        parsed
    };
    let activate = unix(activation, "x", "x-tag");
    let expire = unix(expiration, "y", "y-tag");
    if let (Some(x), Some(y)) = (activate, expire)
        && x > y
    {
        errors.push(ValidationError::new(
            "window",
            "x must be less than or equal to y",
        ));
    }

    if let (Some(d), Some(subject), true, true) = (&d, &subject, subject_ok, context_ok)
        && *d != compute_d(subject, &scopes, &context)
    {
        errors.push(ValidationError::new(
            "d-mismatch",
            "d tag does not match the subject, scope, and context",
        ));
    }

    match (errors.is_empty(), d, subject, value) {
        (true, Some(d), Some(subject), Some(value)) => Ok(ParsedStatement {
            id: event.id.clone(),
            pubkey: event.pubkey.clone(),
            kind,
            created_at: event.created_at,
            d,
            subject,
            value,
            context,
            scopes,
            labels,
            label_hints,
            k,
            activate,
            expire,
            hints,
            content: event.content.clone(),
        }),
        _ => {
            if errors.is_empty() {
                errors.push(ValidationError::new("shape", "Statement is incomplete"));
            }
            Err(errors)
        }
    }
}

impl ParsedStatement {
    /// Applies the scope profile and produces the model record, or `Err`
    /// with the reason the profile drops it.
    pub fn normalize(&self, profile: ScopeProfile) -> Result<EdgeRecord, String> {
        let scope_rank = profile
            .scope_rank(self.kind, &self.scopes)
            .ok_or_else(|| format!("scope not accepted by profile {}", profile.name()))?;
        let hint_pubkey = if self.kind == KIND_TRUST
            && self.subject.ty == SubjectType::I
            && twitter_account_id(&self.subject.value).is_some()
            && self.scopes.iter().any(|s| s == X_SCOPE)
        {
            self.hints.iter().find_map(|h| match h {
                SubjectHint::Npub(hex) => Some(hex.clone()),
                SubjectHint::Structured { .. } => None,
            })
        } else {
            None
        };
        Ok(EdgeRecord {
            id: self.id.clone(),
            pubkey: self.pubkey.clone(),
            kind: self.kind,
            created_at: self.created_at,
            d: self.d.clone(),
            subject_type: self.subject.ty,
            subject: self.subject.node_key(),
            context: self.context.clone(),
            value: self.value,
            activate: self.activate,
            expire: self.expire,
            scope_rank,
            hint_pubkey,
            content: self.content.clone(),
            labels: self.labels.clone(),
            label_hints: self.label_hints.clone(),
        })
    }
}

/// Full statement check: protocol validation, then the scope profile.
pub fn validate_statement(event: &Event, profile: ScopeProfile, verify: bool) -> Verdict {
    match parse_statement(event, verify) {
        Err(errors) => Verdict::Invalid(errors),
        Ok(parsed) => match parsed.normalize(profile) {
            Ok(record) => Verdict::Accepted(Box::new(record)),
            Err(reason) => Verdict::Blocked(reason),
        },
    }
}

/// Builds the tags of a statement (for tests, tools, and the Sync Server's
/// fixtures). Mirrors `buildKind32009Event` / `buildKind32014Event`.
#[derive(Clone, Debug, Default)]
pub struct StatementBuilder {
    pub kind: u32,
    pub subject: Option<Subject>,
    pub value: String,
    pub context: String,
    pub scopes: Vec<String>,
    pub labels: Vec<(String, Option<String>)>,
    pub hints: Vec<String>,
    pub activate: Option<u64>,
    pub expire: Option<u64>,
    pub content: String,
}

impl StatementBuilder {
    pub fn trust(subject: Subject, value: &str) -> StatementBuilder {
        StatementBuilder {
            kind: KIND_TRUST,
            subject: Some(subject),
            value: value.into(),
            ..Default::default()
        }
    }

    pub fn rating(subject: Subject, score: &str) -> StatementBuilder {
        StatementBuilder {
            kind: KIND_RATING,
            subject: Some(subject),
            value: score.into(),
            scopes: vec![X_SCOPE.into()],
            ..Default::default()
        }
    }

    pub fn context(mut self, context: &str) -> Self {
        self.context = context.into();
        self
    }

    pub fn scope(mut self, scope: &str) -> Self {
        self.scopes.push(scope.into());
        self
    }

    pub fn hint(mut self, hint: &str) -> Self {
        self.hints.push(hint.into());
        self
    }

    pub fn label(mut self, label: &str, description: Option<&str>) -> Self {
        self.labels
            .push((label.into(), description.map(Into::into)));
        self
    }

    pub fn window(mut self, activate: Option<u64>, expire: Option<u64>) -> Self {
        self.activate = activate;
        self.expire = expire;
        self
    }

    pub fn content(mut self, content: &str) -> Self {
        self.content = content.into();
        self
    }

    pub fn tags(&self) -> Vec<Vec<String>> {
        let subject = self.subject.as_ref().expect("subject set");
        let mut tags = vec![vec![
            "d".to_string(),
            compute_d(subject, &self.scopes, &self.context),
        ]];
        let mut subject_tag = vec![subject.ty.as_str().to_string(), subject.value.clone()];
        subject_tag.extend(self.hints.iter().cloned());
        tags.push(subject_tag);
        let value_name = if self.kind == KIND_RATING {
            "score"
        } else {
            "v"
        };
        tags.push(vec![value_name.into(), self.value.clone()]);
        if subject.ty == SubjectType::I {
            let class = if subject.value.starts_with("user:id:") {
                Some("user:id")
            } else if subject.value.starts_with("post:id:") {
                Some("post:id")
            } else {
                None
            };
            if let Some(class) = class {
                tags.push(vec!["k".into(), class.into()]);
            }
        }
        let mut scopes = self.scopes.clone();
        scopes.sort();
        for scope in scopes {
            tags.push(vec!["s".into(), scope]);
        }
        if !self.context.is_empty() {
            tags.push(vec!["c".into(), self.context.clone()]);
        }
        for (label, description) in &self.labels {
            let mut tag = vec!["l".to_string(), label.clone()];
            if let Some(description) = description {
                tag.push(description.clone());
            }
            tags.push(tag);
        }
        if let Some(x) = self.activate {
            tags.push(vec!["x".into(), x.to_string()]);
        }
        if let Some(y) = self.expire {
            tags.push(vec!["y".into(), y.to_string()]);
        }
        tags
    }

    pub fn sign(&self, keys: &crate::Keys, created_at: u64) -> Event {
        keys.sign_event(created_at, self.kind, self.tags(), &self.content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keys, encode_npub};

    const T: u64 = 1_700_000_000;

    fn account() -> Subject {
        Subject::new(SubjectType::I, "user:id:11348282")
    }

    fn codes(event: &Event) -> Vec<&'static str> {
        match parse_statement(event, true) {
            Ok(_) => vec![],
            Err(errors) => errors.into_iter().map(|e| e.code).collect(),
        }
    }

    fn resign(keys: &Keys, event: &Event, tags: Vec<Vec<String>>) -> Event {
        keys.sign_event(event.created_at, event.kind, tags, &event.content)
    }

    #[test]
    fn nip_material_examples() {
        let s = Subject::new(SubjectType::I, "user:id:343");
        let x = vec!["x.com".to_string()];
        assert_eq!(d_material(&s, &x, "identity"), "user:id:343:x.com:identity");
        assert_eq!(d_material(&s, &[], "identity"), "user:id:343::identity");
        assert_eq!(d_material(&s, &x, ""), "user:id:343:x.com:");
        assert_eq!(d_material(&s, &[], ""), "user:id:343::");
        let both = vec!["x.com".to_string(), "twitter.com".into()];
        assert_eq!(
            d_material(&s, &both, "identity"),
            "user:id:343:twitter.com,x.com:identity"
        );
        let hex = "ab".repeat(32);
        let p = Subject::new(SubjectType::P, hex.clone());
        assert_eq!(
            d_material(&p, &x, "development"),
            format!("p:{hex}:x.com:development")
        );
        assert_eq!(d_material(&p, &[], ""), format!("p:{hex}::"));
        let e = Subject::new(SubjectType::E, hex.clone());
        assert_eq!(
            d_material(&e, &[], "news:accuracy"),
            format!("e:{hex}::news:accuracy")
        );
        // `d` is SHA-256 of the material.
        assert_eq!(
            compute_d(&s, &x, "identity"),
            crate::sha256_hex("user:id:343:x.com:identity")
        );
        assert_eq!(
            crate::sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn nip_examples_validate() {
        let keys = Keys::from_seed("author");
        let npub = encode_npub(Keys::from_seed("owner").pubkey()).unwrap();
        let examples = vec![
            StatementBuilder::trust(account(), "1")
                .scope("x.com")
                .hint("user:name:nasa")
                .hint(&npub),
            StatementBuilder::trust(account(), "1")
                .scope("x.com")
                .context("identity"),
            StatementBuilder::trust(
                Subject::new(SubjectType::I, "post:id:2080659774136291424"),
                "-1",
            )
            .scope("x.com"),
            StatementBuilder::trust(account(), "1")
                .scope("x.com")
                .scope("twitter.com")
                .content("Discoverable under either hostname; one replaceable slot."),
            StatementBuilder::trust(Subject::new(SubjectType::P, "cd".repeat(32)), "1")
                .scope("nostr")
                .context("development"),
            StatementBuilder::trust(Subject::new(SubjectType::E, "ef".repeat(32)), "1")
                .context("news:accuracy"),
            StatementBuilder::trust(account(), "0")
                .scope("x.com")
                .label("reviewer", None),
            StatementBuilder::trust(account(), "").scope("x.com"),
            StatementBuilder::trust(Subject::new(SubjectType::P, "cd".repeat(32)), "1")
                .scope("corp.example")
                .context("access")
                .window(Some(1_672_531_600), Some(1_672_618_000)),
            StatementBuilder::rating(Subject::new(SubjectType::I, "post:id:1"), "87.5"),
            StatementBuilder::rating(Subject::new(SubjectType::I, "post:id:1"), ""),
            StatementBuilder::rating(Subject::new(SubjectType::I, "post:id:1"), "0"),
        ];
        for builder in examples {
            let event = builder.sign(&keys, T);
            assert_eq!(codes(&event), Vec::<&str>::new(), "{:?}", event.tags);
        }
    }

    #[test]
    fn normalization_and_hint_pubkey() {
        let keys = Keys::from_seed("author");
        let owner = Keys::from_seed("owner");
        let npub = encode_npub(owner.pubkey()).unwrap();
        let event = StatementBuilder::trust(account(), "1")
            .scope("x.com")
            .context("identity")
            .hint("user:name:nasa")
            .hint(&npub)
            .label("reviewer", Some("Trusted <b>reviewer</b>"))
            .label("reviewer", Some("second"))
            .sign(&keys, T);
        let Verdict::Accepted(record) = validate_statement(&event, ScopeProfile::XCom, true) else {
            panic!("accepted");
        };
        assert_eq!(record.scope_rank, 2);
        assert_eq!(record.hint_pubkey.as_deref(), Some(owner.pubkey()));
        assert_eq!(record.value, Some(RecordValue::Trust(1)));
        assert_eq!(record.labels, vec!["reviewer"]);
        assert_eq!(
            record.label_hints,
            vec![("reviewer".to_string(), "Trusted breviewer/b".to_string())]
        );
        assert_eq!(
            record.address_key(),
            format!("32009:{}:{}", keys.pubkey(), record.d)
        );

        // No hint without x.com scope.
        let empty_scope = StatementBuilder::trust(account(), "1")
            .hint(&npub)
            .sign(&keys, T);
        let Verdict::Accepted(record) = validate_statement(&empty_scope, ScopeProfile::XCom, true)
        else {
            panic!("accepted");
        };
        assert_eq!(record.scope_rank, 1);
        assert_eq!(record.hint_pubkey, None);

        // Other scopes are blocked by the x.com profile.
        let nostr = StatementBuilder::trust(account(), "1")
            .scope("nostr")
            .sign(&keys, T);
        assert!(matches!(
            validate_statement(&nostr, ScopeProfile::XCom, true),
            Verdict::Blocked(_)
        ));
        // Ratings without x.com are blocked.
        let mut rating = StatementBuilder::rating(Subject::new(SubjectType::I, "post:id:1"), "5");
        rating.scopes.clear();
        assert!(matches!(
            validate_statement(&rating.sign(&keys, T), ScopeProfile::XCom, true),
            Verdict::Blocked(_)
        ));
    }

    #[test]
    fn rejects_malformed_statements() {
        let keys = Keys::from_seed("author");
        let base = StatementBuilder::trust(account(), "1")
            .scope("x.com")
            .sign(&keys, T);
        let tags = base.tags.clone();

        let mut wrong_d = tags.clone();
        wrong_d[0][1] = "00".repeat(32);
        assert_eq!(codes(&resign(&keys, &base, wrong_d)), vec!["d-mismatch"]);

        let mut two_subjects = tags.clone();
        two_subjects.push(vec!["p".into(), "ab".repeat(32)]);
        assert!(codes(&resign(&keys, &base, two_subjects)).contains(&"subject-tag"));

        let mut bad_value = tags.clone();
        bad_value[2][1] = "2".into();
        assert_eq!(codes(&resign(&keys, &base, bad_value)), vec!["value"]);

        let mut ws_value = tags.clone();
        ws_value[2][1] = " ".into();
        assert_eq!(codes(&resign(&keys, &base, ws_value)), vec!["value"]);

        let mut no_value = tags.clone();
        no_value.remove(2);
        assert_eq!(codes(&resign(&keys, &base, no_value)), vec!["v-tag"]);

        let mut bad_hint = tags.clone();
        bad_hint[1].push("npub1notvalid".into());
        assert_eq!(codes(&resign(&keys, &base, bad_hint)), vec!["hint"]);

        let mut k_mismatch = tags.clone();
        k_mismatch[3][1] = "post:id".into();
        assert_eq!(codes(&resign(&keys, &base, k_mismatch)), vec!["k-mismatch"]);

        let mut bad_x = tags.clone();
        bad_x.push(vec!["x".into(), "soon".into()]);
        assert_eq!(codes(&resign(&keys, &base, bad_x)), vec!["x-tag"]);

        let mut window = tags.clone();
        window.push(vec!["x".into(), "10".into()]);
        window.push(vec!["y".into(), "9".into()]);
        assert_eq!(codes(&resign(&keys, &base, window)), vec!["window"]);

        let mut two_c = tags.clone();
        two_c.push(vec!["c".into(), "a".into()]);
        two_c.push(vec!["c".into(), "b".into()]);
        assert!(codes(&resign(&keys, &base, two_c)).contains(&"c-tag"));

        let mut bad_label = tags.clone();
        bad_label.push(vec!["l".into(), "Bad Label".into()]);
        assert_eq!(codes(&resign(&keys, &base, bad_label)), vec!["label"]);

        let long = keys.sign_event(T, KIND_TRUST, tags.clone(), &"x".repeat(1025));
        assert_eq!(codes(&long), vec!["content-length"]);
        let exact = keys.sign_event(T, KIND_TRUST, tags.clone(), &"é".repeat(1024));
        assert_eq!(codes(&exact), Vec::<&str>::new());

        let mut tampered = base.clone();
        tampered.content = "tampered".into();
        assert_eq!(codes(&tampered), vec!["id-mismatch"]);

        let bad_user = StatementBuilder::trust(Subject::new(SubjectType::I, "user:id:x1"), "1");
        let mut bad_user_tags = bad_user.tags();
        bad_user_tags.retain(|t| t[0] != "k");
        let ev = keys.sign_event(T, KIND_TRUST, bad_user_tags, "");
        assert!(codes(&ev).contains(&"subject"));
    }

    #[test]
    fn rating_score_grammar_enforced() {
        let keys = Keys::from_seed("author");
        let post = Subject::new(SubjectType::I, "post:id:1");
        for (score, ok) in [
            ("50", true),
            ("0", true),
            ("100", true),
            ("12.25", true),
            ("12.50", false),
            ("101", false),
            ("1e2", false),
            ("-1", false),
        ] {
            let event = StatementBuilder::rating(post.clone(), score).sign(&keys, T);
            assert_eq!(codes(&event).is_empty(), ok, "{score}");
        }
    }
}
