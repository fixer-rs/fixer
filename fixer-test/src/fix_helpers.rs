use std::time::{SystemTime, UNIX_EPOCH};

const SOH: u8 = 0x01;

/// Replace `<TIME>` and `<TIME+N>` / `<TIME-N>` placeholders with UTC timestamps.
///
/// Format: `YYYYMMDD-HH:MM:SS` (FIX standard `SendingTime` format).
pub fn timify(msg: &[u8]) -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch");
    let secs = now.as_secs();

    // First replace <TIME+N> and <TIME-N> patterns (must be done before <TIME>).
    let mut result = msg.to_vec();
    loop {
        let Some(start) = result
            .windows(6)
            .position(|w| w == b"<TIME+" || w == b"<TIME-")
        else {
            break;
        };
        let sign: i64 = if result[start + 5] == b'+' { 1 } else { -1 };
        let Some(end) = result[start + 6..].iter().position(|&b| b == b'>') else {
            break;
        };
        let offset_str =
            std::str::from_utf8(&result[start + 6..start + 6 + end]).unwrap_or("0");
        let offset: i64 = offset_str.parse().unwrap_or(0);
        let adjusted = (secs as i64 + sign * offset) as u64;
        let ts = format_utc_timestamp(adjusted);
        let mut new_result = Vec::with_capacity(result.len());
        new_result.extend_from_slice(&result[..start]);
        new_result.extend_from_slice(ts.as_bytes());
        new_result.extend_from_slice(&result[start + 6 + end + 1..]);
        result = new_result;
    }

    // Then replace plain <TIME>.
    if contains_bytes(&result, b"<TIME>") {
        let timestamp = format_utc_timestamp(secs);
        result = replace_bytes(&result, b"<TIME>", timestamp.as_bytes());
    }

    result
}

/// Replace all occurrences of `pattern` with `replacement` in `data`.
fn replace_bytes(data: &[u8], pattern: &[u8], replacement: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i..].starts_with(pattern) {
            result.extend_from_slice(replacement);
            i += pattern.len();
        } else {
            result.push(data[i]);
            i += 1;
        }
    }
    result
}

/// Check if `data` contains `pattern`.
fn contains_bytes(data: &[u8], pattern: &[u8]) -> bool {
    data.windows(pattern.len()).any(|w| w == pattern)
}

/// Format seconds since epoch as `YYYYMMDD-HH:MM:SS`.
fn format_utc_timestamp(epoch_secs: u64) -> String {
    let days = epoch_secs / 86400;
    let day_secs = epoch_secs % 86400;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    let (year, month, day) = days_to_ymd(days);

    format!("{year:04}{month:02}{day:02}-{hours:02}:{minutes:02}:{seconds:02}")
}

/// Convert days since 1970-01-01 to (year, month, day).
/// Algorithm from Howard Hinnant's civil date conversion.
#[allow(clippy::cast_possible_truncation)] // values always fit in u32
fn days_to_ymd(days: u64) -> (u32, u32, u32) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

/// Convert a raw `.def` message (already SOH-delimited) to proper FIX wire format.
///
/// The `.def` files use actual SOH (0x01) bytes between fields. This function:
/// 1. Calculates and sets `BodyLength` (tag 9) if value is `0`
/// 2. Calculates and sets `CheckSum` (tag 10) if value is `0`
/// 3. Returns the complete FIX wire-format message
pub fn fixify(msg: &[u8]) -> Vec<u8> {
    let fields = parse_raw_fix(msg);
    if fields.is_empty() {
        return Vec::new();
    }

    // Separate header (8=, 9=), body, and trailer (10=) fields.
    let mut begin_string: Option<&[u8]> = None;
    let mut body_length_val: Option<&[u8]> = None;
    let mut checksum_val: Option<&[u8]> = None;
    let mut body_fields: Vec<(&[u8], &[u8])> = Vec::new();

    for &(tag, value) in &fields {
        match tag {
            b"8" => begin_string = Some(value),
            b"9" => body_length_val = Some(value),
            b"10" => checksum_val = Some(value),
            _ => body_fields.push((tag, value)),
        }
    }

    // Build the body bytes (everything between 9=..SOH and 10=..SOH).
    let mut body_bytes: Vec<u8> = Vec::new();
    for (tag, value) in &body_fields {
        body_bytes.extend_from_slice(tag);
        body_bytes.push(b'=');
        body_bytes.extend_from_slice(value);
        body_bytes.push(SOH);
    }

    let body_len = body_bytes.len();

    // Build full message.
    let mut result: Vec<u8> = Vec::new();

    // 8=BeginString\x01
    if let Some(bs) = begin_string {
        result.extend_from_slice(b"8=");
        result.extend_from_slice(bs);
        result.push(SOH);
    }

    // 9=BodyLength\x01
    let auto_body_length = body_length_val == Some(b"0") || body_length_val.is_none();
    if auto_body_length {
        let len_str = body_len.to_string();
        result.extend_from_slice(b"9=");
        result.extend_from_slice(len_str.as_bytes());
        result.push(SOH);
    } else if let Some(bl) = body_length_val {
        result.extend_from_slice(b"9=");
        result.extend_from_slice(bl);
        result.push(SOH);
    }

    // Body fields.
    result.extend_from_slice(&body_bytes);

    // 10=CheckSum\x01
    let auto_checksum = checksum_val == Some(b"0") || checksum_val.is_none();
    if auto_checksum {
        let sum: u32 = result.iter().map(|&b| u32::from(b)).sum();
        let cs = format!("{:03}", sum % 256);
        result.extend_from_slice(b"10=");
        result.extend_from_slice(cs.as_bytes());
        result.push(SOH);
    } else if let Some(cs) = checksum_val {
        result.extend_from_slice(b"10=");
        result.extend_from_slice(cs);
        result.push(SOH);
    }

    result
}

/// Parse raw FIX bytes into a list of (tag, value) byte slice pairs.
///
/// Each field is delimited by SOH (0x01). Tags and values are separated by `=`.
pub fn parse_raw_fix(data: &[u8]) -> Vec<(&[u8], &[u8])> {
    let mut pairs = Vec::new();

    for field in data.split(|&b| b == SOH) {
        if field.is_empty() {
            continue;
        }
        if let Some(eq_pos) = field.iter().position(|&b| b == b'=') {
            let tag = &field[..eq_pos];
            let value = &field[eq_pos + 1..];
            pairs.push((tag, value));
        }
    }

    pairs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixify_auto_body_length_and_checksum() {
        // Input: SOH-delimited, with 9=0 and 10=0 (auto-calculate).
        let msg = b"8=FIX.4.2\x019=0\x0135=A\x0134=1\x0149=TW\x0152=20260101-00:00:00\x0156=ISLD\x0198=0\x01108=30\x0110=0\x01";
        let raw = fixify(msg);

        // Should start with 8=FIX.4.2\x01
        assert!(raw.starts_with(b"8=FIX.4.2\x01"));
        // Should have auto-calculated body length.
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(!raw_str.contains("9=0\x01"));
        // Should contain 35=A
        assert!(raw_str.contains("35=A\x01"));
        // Should end with 10=xxx\x01 (3 digit checksum).
        assert!(raw_str.ends_with('\x01'));
    }

    #[test]
    fn test_fixify_preserves_explicit_body_length() {
        let msg = b"8=FIX.4.2\x019=99\x0135=A\x0134=1\x0110=0\x01";
        let raw = fixify(msg);
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.contains("9=99\x01"));
    }

    #[test]
    fn test_fixify_preserves_explicit_checksum() {
        let msg = b"8=FIX.4.2\x019=0\x0135=A\x0134=1\x0110=042\x01";
        let raw = fixify(msg);
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.contains("10=042\x01"));
    }

    #[test]
    fn test_timify_replaces_placeholder() {
        let msg = b"52=<TIME>\x0160=<TIME>\x01";
        let result = timify(msg);
        assert!(!contains_bytes(&result, b"<TIME>"));
        assert!(result.len() > msg.len());
    }

    #[test]
    fn test_timify_no_placeholder() {
        let msg = b"52=20260101-00:00:00\x01";
        let result = timify(msg);
        assert_eq!(result, msg);
    }

    #[test]
    fn test_parse_raw_fix() {
        let data = b"8=FIX.4.2\x019=5\x0135=A\x0110=123\x01";
        let pairs = parse_raw_fix(data);
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0], (b"8".as_slice(), b"FIX.4.2".as_slice()));
        assert_eq!(pairs[1], (b"9".as_slice(), b"5".as_slice()));
        assert_eq!(pairs[2], (b"35".as_slice(), b"A".as_slice()));
        assert_eq!(pairs[3], (b"10".as_slice(), b"123".as_slice()));
    }

    #[test]
    fn test_format_utc_timestamp() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let ts = format_utc_timestamp(1_704_067_200);
        assert_eq!(ts, "20240101-00:00:00");
    }

    #[test]
    fn test_format_utc_timestamp_with_time() {
        // 2024-06-15 13:05:30 UTC
        // 19889 days * 86400 + 13*3600 + 5*60 + 30 = 1718409600 + 47130 = 1718456730
        let ts = format_utc_timestamp(1_718_456_730);
        assert_eq!(ts, "20240615-13:05:30");
    }

    #[test]
    fn test_replace_bytes() {
        let data = b"hello <TIME> world <TIME>";
        let result = replace_bytes(data, b"<TIME>", b"NOW");
        assert_eq!(result, b"hello NOW world NOW");
    }

    #[test]
    fn test_fixify_real_def_message() {
        // Simulate a real .def line (already SOH-delimited from the file).
        let msg = b"8=FIX.4.2\x0135=A\x0134=5\x0149=TW\x0152=20260101-00:00:00\x0156=ISLD\x0198=0\x01108=30\x01";
        let raw = fixify(msg);

        // Should have auto-calculated body length and checksum (since 9= and 10= were absent).
        let pairs = parse_raw_fix(&raw);
        assert_eq!(pairs[0].0, b"8");
        assert_eq!(pairs[1].0, b"9"); // auto-calculated
        // Last field should be checksum.
        assert_eq!(pairs.last().unwrap().0, b"10");
    }
}
