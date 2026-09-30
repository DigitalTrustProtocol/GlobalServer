//! Scope profiles (wot-model §2.3).

use serde::{Deserialize, Serialize};

use crate::{KIND_RATING, KIND_TRUST};

/// The `x.com` scope value.
pub const X_SCOPE: &str = "x.com";

/// A deployment's scope profile. Only `x.com` exists in v1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeProfile {
    #[default]
    #[serde(rename = "x.com")]
    XCom,
}

impl ScopeProfile {
    pub fn name(self) -> &'static str {
        match self {
            ScopeProfile::XCom => X_SCOPE,
        }
    }

    pub fn parse(value: &str) -> Option<ScopeProfile> {
        (value == X_SCOPE).then_some(ScopeProfile::XCom)
    }

    /// `scopeRank` for an eligible event, or `None` if the profile drops it.
    pub fn scope_rank(self, kind: u32, scopes: &[String]) -> Option<u8> {
        let has_x = scopes.iter().any(|s| s == X_SCOPE);
        match (self, kind) {
            (ScopeProfile::XCom, KIND_TRUST) if has_x => Some(2),
            (ScopeProfile::XCom, KIND_TRUST) if scopes.is_empty() => Some(1),
            (ScopeProfile::XCom, KIND_RATING) if has_x => Some(2),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn x_profile() {
        let p = ScopeProfile::XCom;
        assert_eq!(p.scope_rank(KIND_TRUST, &s(&[])), Some(1));
        assert_eq!(p.scope_rank(KIND_TRUST, &s(&["x.com"])), Some(2));
        assert_eq!(
            p.scope_rank(KIND_TRUST, &s(&["twitter.com", "x.com"])),
            Some(2)
        );
        assert_eq!(p.scope_rank(KIND_TRUST, &s(&["nostr"])), None);
        assert_eq!(p.scope_rank(KIND_RATING, &s(&[])), None);
        assert_eq!(p.scope_rank(KIND_RATING, &s(&["x.com"])), Some(2));
    }
}
