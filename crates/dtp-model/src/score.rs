//! Integer trust percent and resolution bands (wot-model §5, §7.1).

/// `floor((200·trust + s) / (2·s))`, `None` when `s = trust + distrust = 0`.
/// Equals JavaScript `Math.round(100 * trust / s)` for every count.
pub fn percent(trust: u64, distrust: u64) -> Option<u64> {
    let s = trust + distrust;
    if s == 0 {
        return None;
    }
    Some((200 * trust + s) / (2 * s))
}

/// `qualifies` for a non-root node.
pub fn meets_threshold(trust: u64, distrust: u64, threshold: u64) -> bool {
    percent(trust, distrust).is_some_and(|p| p >= threshold)
}

/// Resolution band of a trust result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Trusted,
    Distrusted,
    Mixed,
    None,
}

impl Resolution {
    pub fn as_str(self) -> &'static str {
        match self {
            Resolution::Trusted => "trusted",
            Resolution::Distrusted => "distrusted",
            Resolution::Mixed => "mixed",
            Resolution::None => "none",
        }
    }
}

/// Resolution from hitting-degree counts and the band.
pub fn resolution(trust: u64, distrust: u64, connected: bool, red: u64, green: u64) -> Resolution {
    if !connected {
        return Resolution::None;
    }
    match percent(trust, distrust) {
        None => Resolution::None,
        Some(p) if p >= green => Resolution::Trusted,
        Some(p) if p < red => Resolution::Distrusted,
        Some(_) => Resolution::Mixed,
    }
}

/// Clamps a green knob like `clampFollowTrustThreshold` (round, 0–100,
/// default 75 when missing or not finite).
pub fn clamp_green(value: Option<f64>) -> u64 {
    clamp_percent(value, 75)
}

/// Clamps a red knob like `clampFollowTrustRed` (≤ green).
pub fn clamp_red(value: Option<f64>, green: u64) -> u64 {
    clamp_percent(value, 25).min(green)
}

fn clamp_percent(value: Option<f64>, fallback: u64) -> u64 {
    match value {
        Some(v) if v.is_finite() => js_round(v).clamp(0.0, 100.0) as u64,
        _ => fallback,
    }
}

/// JavaScript `Math.round` (halves round toward +∞).
pub fn js_round(v: f64) -> f64 {
    (v + 0.5).floor()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_percent_equals_js_round() {
        for trust in 0..60u64 {
            for distrust in 0..60u64 {
                let s = trust + distrust;
                let expected = if s == 0 {
                    None
                } else {
                    Some(js_round(100.0 * trust as f64 / s as f64) as u64)
                };
                assert_eq!(percent(trust, distrust), expected, "{trust}/{distrust}");
            }
        }
    }

    #[test]
    fn bands() {
        assert_eq!(resolution(3, 1, true, 25, 75), Resolution::Trusted);
        assert_eq!(resolution(1, 1, true, 25, 75), Resolution::Mixed);
        assert_eq!(resolution(0, 1, true, 25, 75), Resolution::Distrusted);
        assert_eq!(resolution(1, 0, false, 25, 75), Resolution::None);
        assert_eq!(clamp_green(Some(80.4)), 80);
        assert_eq!(clamp_green(Some(120.0)), 100);
        assert_eq!(clamp_green(None), 75);
        assert_eq!(clamp_red(Some(90.0), 75), 75);
        assert_eq!(clamp_red(None, 75), 25);
    }
}
