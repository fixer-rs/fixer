use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::fix_helpers::parse_raw_fix;

const SOH: u8 = 0x01;

/// Result of comparing two FIX messages.
#[derive(Debug)]
pub enum CompareResult {
    Match,
    Mismatch { reason: String },
}

impl CompareResult {
    pub fn is_match(&self) -> bool {
        matches!(self, CompareResult::Match)
    }
}

/// Compares expected and actual FIX messages, using regex patterns for
/// time-varying fields (loaded from `fields.fmt`).
pub struct Comparator {
    patterns: HashMap<Vec<u8>, Regex>,
}

impl Default for Comparator {
    fn default() -> Self {
        Self::new()
    }
}

impl Comparator {
    /// Load field comparison patterns from a `fields.fmt` file.
    ///
    /// Format: one `tag=regex_pattern` per line. Lines starting with `#` are comments.
    pub fn load_patterns(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;

        let mut patterns = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(eq_pos) = line.find('=') {
                let tag = line[..eq_pos].trim();
                let pattern = line[eq_pos + 1..].trim();

                // Anchor the pattern to match the full value.
                let anchored = format!("^(?:{pattern})$");
                let regex = Regex::new(&anchored)
                    .map_err(|e| format!("invalid regex for tag {tag}: {e}"))?;

                patterns.insert(tag.as_bytes().to_vec(), regex);
            }
        }

        Ok(Comparator { patterns })
    }

    /// Create a comparator with no patterns (exact match for all fields).
    pub fn new() -> Self {
        Comparator {
            patterns: HashMap::new(),
        }
    }

    /// Compare an expected FIX message against an actual FIX message.
    ///
    /// Both messages should be in raw FIX wire format (SOH-delimited).
    pub fn compare(&self, expected: &[u8], actual: &[u8]) -> CompareResult {
        let expected_fields = parse_raw_fix(expected);
        let actual_fields = parse_raw_fix(actual);

        // Check field count.
        if expected_fields.len() != actual_fields.len() {
            let exp_readable = format_readable(expected);
            let act_readable = format_readable(actual);
            return CompareResult::Mismatch {
                reason: format!(
                    "field count mismatch: expected {} fields, got {}\n  expected: {exp_readable}\n  actual:   {act_readable}",
                    expected_fields.len(),
                    actual_fields.len(),
                ),
            };
        }

        // Compare field by field.
        for (i, (exp, act)) in expected_fields.iter().zip(&actual_fields).enumerate() {
            let (exp_tag, exp_val) = exp;
            let (act_tag, act_val) = act;

            // Tags must be in the same order.
            if exp_tag != act_tag {
                return CompareResult::Mismatch {
                    reason: format!(
                        "field {i}: expected tag '{}' but got tag '{}'",
                        String::from_utf8_lossy(exp_tag),
                        String::from_utf8_lossy(act_tag),
                    ),
                };
            }

            // Check if this tag has a regex pattern.
            if let Some(regex) = self.patterns.get(*exp_tag) {
                let act_str = String::from_utf8_lossy(act_val);
                if !regex.is_match(&act_str) {
                    return CompareResult::Mismatch {
                        reason: format!(
                            "field {i}: tag '{}' value '{}' does not match pattern '{}'",
                            String::from_utf8_lossy(exp_tag),
                            act_str,
                            regex.as_str(),
                        ),
                    };
                }
            } else {
                // Exact comparison.
                if exp_val != act_val {
                    return CompareResult::Mismatch {
                        reason: format!(
                            "field {i}: tag '{}' expected '{}' but got '{}'",
                            String::from_utf8_lossy(exp_tag),
                            String::from_utf8_lossy(exp_val),
                            String::from_utf8_lossy(act_val),
                        ),
                    };
                }
            }
        }

        CompareResult::Match
    }
}

/// Format a raw FIX message for readable error output (replace SOH with `|`).
fn format_readable(msg: &[u8]) -> String {
    msg.iter()
        .map(|&b| if b == SOH { b'|' } else { b })
        .map(|b| b as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_exact_match() {
        let comp = Comparator::new();
        let msg = b"8=FIX.4.2\x019=5\x0135=A\x0110=123\x01";
        let result = comp.compare(msg, msg);
        assert!(result.is_match());
    }

    #[test]
    fn test_compare_field_count_mismatch() {
        let comp = Comparator::new();
        let expected = b"8=FIX.4.2\x0135=A\x01";
        let actual = b"8=FIX.4.2\x0135=A\x0134=1\x01";
        let result = comp.compare(expected, actual);
        assert!(!result.is_match());
        if let CompareResult::Mismatch { reason } = result {
            assert!(reason.contains("field count"));
        }
    }

    #[test]
    fn test_compare_tag_order_mismatch() {
        let comp = Comparator::new();
        let expected = b"8=FIX.4.2\x0135=A\x0134=1\x01";
        let actual = b"8=FIX.4.2\x0134=1\x0135=A\x01";
        let result = comp.compare(expected, actual);
        assert!(!result.is_match());
        if let CompareResult::Mismatch { reason } = result {
            assert!(reason.contains("expected tag '35'"));
        }
    }

    #[test]
    fn test_compare_value_mismatch() {
        let comp = Comparator::new();
        let expected = b"8=FIX.4.2\x0135=A\x0134=1\x01";
        let actual = b"8=FIX.4.2\x0135=A\x0134=2\x01";
        let result = comp.compare(expected, actual);
        assert!(!result.is_match());
        if let CompareResult::Mismatch { reason } = result {
            assert!(reason.contains("expected '1' but got '2'"));
        }
    }

    #[test]
    fn test_compare_with_regex_pattern() {
        let mut patterns = HashMap::new();
        patterns.insert(
            b"52".to_vec(),
            Regex::new(r"^\d{8}-\d{2}:\d{2}:\d{2}$").unwrap(),
        );
        let comp = Comparator { patterns };

        let expected = b"8=FIX.4.2\x0152=00000000-00:00:00\x01";
        let actual = b"8=FIX.4.2\x0152=20260227-14:30:00\x01";
        let result = comp.compare(expected, actual);
        assert!(result.is_match());
    }

    #[test]
    fn test_compare_regex_no_match() {
        let mut patterns = HashMap::new();
        patterns.insert(
            b"10".to_vec(),
            Regex::new(r"^\d{3}$").unwrap(),
        );
        let comp = Comparator { patterns };

        let expected = b"10=000\x01";
        let actual = b"10=12\x01"; // only 2 digits
        let result = comp.compare(expected, actual);
        assert!(!result.is_match());
    }

    #[test]
    fn test_load_patterns() {
        let dir = std::env::temp_dir().join("fixer_test_patterns");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("fields.fmt");
        fs::write(
            &path,
            "10=\\d{3}\n52=\\d{8}-\\d{2}:\\d{2}:\\d{2}\n",
        )
        .unwrap();

        let comp = Comparator::load_patterns(&path).unwrap();
        assert_eq!(comp.patterns.len(), 2);
        assert!(comp.patterns.contains_key(b"10".as_slice()));
        assert!(comp.patterns.contains_key(b"52".as_slice()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_format_readable() {
        let msg = b"8=FIX.4.2\x0135=A\x01";
        assert_eq!(format_readable(msg), "8=FIX.4.2|35=A|");
    }

    #[test]
    fn test_load_actual_fields_fmt() {
        let path = Path::new("_test/fields.fmt");
        if path.exists() {
            let comp = Comparator::load_patterns(path).unwrap();
            assert_eq!(comp.patterns.len(), 5); // 10, 42, 52, 60, 122
        }
    }
}
