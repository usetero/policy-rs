//! Compiled keep expressions for policy evaluation.

use crate::error::PolicyError;

/// Compiled keep expression.
///
/// This represents the parsed and validated form of a keep expression
/// from a policy. The keep expression determines what happens to
/// matching telemetry.
#[derive(Debug, Clone, PartialEq)]
pub enum CompiledKeep {
    /// Keep all matching telemetry.
    All,
    /// Drop all matching telemetry.
    None,
    /// Keep a percentage of matching telemetry (0.0 to 1.0).
    Percentage(f64),
    /// Rate limit to N per second.
    RatePerSecond(u64),
    /// Rate limit to N per minute.
    RatePerMinute(u64),
}

impl CompiledKeep {
    /// Parse a keep expression string.
    ///
    /// Valid formats:
    /// - `"all"` or `""` - Keep everything
    /// - `"none"` - Drop everything
    /// - `"N%"` - Keep N percent (0-100)
    /// - `"N/s"` - Keep at most N per second
    /// - `"N/m"` - Keep at most N per minute
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let s = s.trim();

        if s.is_empty() || s.eq_ignore_ascii_case("all") {
            return Ok(CompiledKeep::All);
        }

        if s.eq_ignore_ascii_case("none") {
            return Ok(CompiledKeep::None);
        }

        // Check for percentage: "N%"
        if let Some(pct_str) = s.strip_suffix('%') {
            let pct: f64 =
                pct_str
                    .trim()
                    .parse()
                    .map_err(|_| PolicyError::InvalidKeepExpression {
                        expression: s.to_string(),
                        reason: "invalid percentage value".to_string(),
                    })?;

            if !(0.0..=100.0).contains(&pct) {
                return Err(PolicyError::InvalidKeepExpression {
                    expression: s.to_string(),
                    reason: "percentage must be between 0 and 100".to_string(),
                });
            }

            return Ok(CompiledKeep::Percentage(pct / 100.0));
        }

        // Check for rate per second: "N/s"
        if let Some(rate_str) = s.strip_suffix("/s") {
            let rate: u64 =
                rate_str
                    .trim()
                    .parse()
                    .map_err(|_| PolicyError::InvalidKeepExpression {
                        expression: s.to_string(),
                        reason: "invalid rate value".to_string(),
                    })?;

            return Ok(CompiledKeep::RatePerSecond(rate));
        }

        // Check for rate per minute: "N/m"
        if let Some(rate_str) = s.strip_suffix("/m") {
            let rate: u64 =
                rate_str
                    .trim()
                    .parse()
                    .map_err(|_| PolicyError::InvalidKeepExpression {
                        expression: s.to_string(),
                        reason: "invalid rate value".to_string(),
                    })?;

            return Ok(CompiledKeep::RatePerMinute(rate));
        }

        Err(PolicyError::InvalidKeepExpression {
            expression: s.to_string(),
            reason: "unknown keep expression format".to_string(),
        })
    }

    /// Get the restrictiveness score of this keep expression.
    ///
    /// Higher scores are more restrictive. This is used to select
    /// the most restrictive policy when multiple policies match.
    ///
    /// Scores:
    /// - `None` = 1000 (most restrictive)
    /// - `Percentage(p)` = 100 - (p * 100) (lower percentage = more restrictive)
    /// - `RatePerSecond/Minute` = 10
    /// - `All` = 0 (least restrictive)
    pub fn restrictiveness(&self) -> u32 {
        match self {
            CompiledKeep::None => 1000,
            CompiledKeep::Percentage(p) => (100.0 - (p * 100.0)) as u32,
            CompiledKeep::RatePerSecond(_) => 10,
            CompiledKeep::RatePerMinute(_) => 10,
            CompiledKeep::All => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all() {
        assert_eq!(CompiledKeep::parse("all").unwrap(), CompiledKeep::All);
        assert_eq!(CompiledKeep::parse("ALL").unwrap(), CompiledKeep::All);
        assert_eq!(CompiledKeep::parse("").unwrap(), CompiledKeep::All);
        assert_eq!(CompiledKeep::parse("  ").unwrap(), CompiledKeep::All);
    }

    #[test]
    fn parse_none() {
        assert_eq!(CompiledKeep::parse("none").unwrap(), CompiledKeep::None);
        assert_eq!(CompiledKeep::parse("NONE").unwrap(), CompiledKeep::None);
        assert_eq!(CompiledKeep::parse(" none ").unwrap(), CompiledKeep::None);
    }

    #[test]
    fn parse_percentage() {
        assert_eq!(
            CompiledKeep::parse("50%").unwrap(),
            CompiledKeep::Percentage(0.5)
        );
        assert_eq!(
            CompiledKeep::parse("100%").unwrap(),
            CompiledKeep::Percentage(1.0)
        );
        assert_eq!(
            CompiledKeep::parse("0%").unwrap(),
            CompiledKeep::Percentage(0.0)
        );
        assert_eq!(
            CompiledKeep::parse(" 25 %").unwrap(),
            CompiledKeep::Percentage(0.25)
        );
    }

    #[test]
    fn parse_percentage_invalid() {
        assert!(CompiledKeep::parse("101%").is_err());
        assert!(CompiledKeep::parse("-1%").is_err());
        assert!(CompiledKeep::parse("abc%").is_err());
    }

    #[test]
    fn parse_rate_per_second() {
        assert_eq!(
            CompiledKeep::parse("100/s").unwrap(),
            CompiledKeep::RatePerSecond(100)
        );
        assert_eq!(
            CompiledKeep::parse(" 50 /s").unwrap(),
            CompiledKeep::RatePerSecond(50)
        );
    }

    #[test]
    fn parse_rate_per_minute() {
        assert_eq!(
            CompiledKeep::parse("1000/m").unwrap(),
            CompiledKeep::RatePerMinute(1000)
        );
        assert_eq!(
            CompiledKeep::parse(" 500 /m").unwrap(),
            CompiledKeep::RatePerMinute(500)
        );
    }

    #[test]
    fn parse_invalid() {
        assert!(CompiledKeep::parse("invalid").is_err());
        assert!(CompiledKeep::parse("50").is_err());
        assert!(CompiledKeep::parse("100/h").is_err());
    }

    #[test]
    fn restrictiveness_ordering() {
        let none = CompiledKeep::None.restrictiveness();
        let pct_10 = CompiledKeep::Percentage(0.1).restrictiveness();
        let pct_50 = CompiledKeep::Percentage(0.5).restrictiveness();
        let pct_90 = CompiledKeep::Percentage(0.9).restrictiveness();
        let rate = CompiledKeep::RatePerSecond(100).restrictiveness();
        let all = CompiledKeep::All.restrictiveness();

        // none is most restrictive
        assert!(none > pct_10);

        // lower percentage is more restrictive
        assert!(pct_10 > pct_50);
        assert!(pct_50 > pct_90);

        // rate and 90% are both 10, so they're equal
        assert_eq!(pct_90, rate);

        // all is least restrictive
        assert!(rate > all);
    }
}
