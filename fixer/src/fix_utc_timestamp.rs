use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use jiff::{Timestamp, civil, tz::TimeZone};
use simple_error::SimpleResult;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimestampPrecision {
    #[default]
    Millis,
    Seconds,
    Micros,
    Nanos,
}

// FIXUTCTimestamp is a FIX UTC Timestamp value, implements FieldValue
#[derive(Default, Debug)]
pub struct FIXUTCTimestamp {
    pub time: Timestamp,
    pub precision: TimestampPrecision,
}

/// Parse exactly `len` ASCII digit bytes from `input[offset..]` as a u32.
#[allow(clippy::inline_always)]
#[inline(always)]
fn parse_digits(input: &[u8], offset: usize, len: usize) -> Option<u32> {
    let mut val = 0u32;
    for &b in &input[offset..offset + len] {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val * 10 + u32::from(b - b'0');
    }
    Some(val)
}

impl FieldValueReader for FIXUTCTimestamp {
    // Format: YYYYMMDD-HH:MM:SS[.fff[fff[fff]]]
    // Lengths: 17 (seconds), 21 (millis), 24 (micros), 27 (nanos)
    fn read(&mut self, input: &[u8]) -> SimpleResult<()> {
        let err = || {
            simple_error!(
                "Invalid Value for Timestamp: {}",
                std::str::from_utf8(input).unwrap_or("<invalid utf8>")
            )
        };

        if input.len() < 17 {
            return Err(err());
        }

        // Validate separators: '-' at 8, ':' at 11, ':' at 14
        if input[8] != b'-' || input[11] != b':' || input[14] != b':' {
            return Err(err());
        }

        #[allow(clippy::cast_possible_truncation)]
        let year = parse_digits(input, 0, 4).ok_or_else(err)? as i16;
        #[allow(clippy::cast_possible_truncation)]
        let month = parse_digits(input, 4, 2).ok_or_else(err)? as i8;
        #[allow(clippy::cast_possible_truncation)]
        let day = parse_digits(input, 6, 2).ok_or_else(err)? as i8;
        #[allow(clippy::cast_possible_truncation)]
        let hour = parse_digits(input, 9, 2).ok_or_else(err)? as i8;
        #[allow(clippy::cast_possible_truncation)]
        let minute = parse_digits(input, 12, 2).ok_or_else(err)? as i8;
        #[allow(clippy::cast_possible_truncation)]
        let second = parse_digits(input, 15, 2).ok_or_else(err)? as i8;

        #[allow(clippy::cast_possible_wrap)]
        let (precision, nanos) = match input.len() {
            17 => (TimestampPrecision::Seconds, 0i32),
            21 => {
                if input[17] != b'.' {
                    return Err(err());
                }
                let ms = parse_digits(input, 18, 3).ok_or_else(err)?;
                (TimestampPrecision::Millis, ms as i32 * 1_000_000)
            }
            24 => {
                if input[17] != b'.' {
                    return Err(err());
                }
                let us = parse_digits(input, 18, 6).ok_or_else(err)?;
                (TimestampPrecision::Micros, us as i32 * 1_000)
            }
            27 => {
                if input[17] != b'.' {
                    return Err(err());
                }
                let ns = parse_digits(input, 18, 9).ok_or_else(err)?;
                (TimestampPrecision::Nanos, ns as i32)
            }
            _ => return Err(err()),
        };

        self.time = civil::date(year, month, day)
            .at(hour, minute, second, nanos)
            .to_zoned(TimeZone::UTC)
            .map_err(|_| err())?
            .timestamp();
        self.precision = precision;
        Ok(())
    }
}

impl FieldValueWriter for FIXUTCTimestamp {
    fn write_to(&self, buf: &mut Vec<u8>) {
        use std::io::Write;
        let zdt = self.time.to_zoned(TimeZone::UTC);
        let dt = zdt.datetime();
        let (y, mo, d) = (dt.year(), dt.month(), dt.day());
        let (h, mi, s) = (dt.hour(), dt.minute(), dt.second());
        match self.precision {
            TimestampPrecision::Seconds => {
                write!(buf, "{y:04}{mo:02}{d:02}-{h:02}:{mi:02}:{s:02}").unwrap();
            }
            TimestampPrecision::Millis => {
                let ms = dt.subsec_nanosecond() / 1_000_000;
                write!(buf, "{y:04}{mo:02}{d:02}-{h:02}:{mi:02}:{s:02}.{ms:03}").unwrap();
            }
            TimestampPrecision::Micros => {
                let us = dt.subsec_nanosecond() / 1_000;
                write!(buf, "{y:04}{mo:02}{d:02}-{h:02}:{mi:02}:{s:02}.{us:06}").unwrap();
            }
            TimestampPrecision::Nanos => {
                let ns = dt.subsec_nanosecond();
                write!(buf, "{y:04}{mo:02}{d:02}-{h:02}:{mi:02}:{s:02}.{ns:09}").unwrap();
            }
        }
    }
}

impl FieldValue for FIXUTCTimestamp {}

impl FIXUTCTimestamp {
    pub fn from_time(time: Timestamp) -> Self {
        FIXUTCTimestamp {
            time,
            precision: TimestampPrecision::default(),
        }
    }

    pub fn from_time_with_precision(time: Timestamp, precision: TimestampPrecision) -> Self {
        FIXUTCTimestamp { time, precision }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_statements)]
mod tests {
    use super::*;
    use jiff::civil;

    fn ts(year: i16, month: i8, day: i8, hour: i8, min: i8, sec: i8, nanos: i32) -> Timestamp {
        civil::date(year, month, day)
            .at(hour, min, sec, nanos)
            .to_zoned(jiff::tz::TimeZone::UTC)
            .unwrap()
            .timestamp()
    }

    #[test]
    fn test_fixutc_timestamp_write() {
        let the_ts = ts(2016, 2, 8, 22, 7, 16, 954_123_123);

        struct TestCase<'a> {
            precision: TimestampPrecision,
            val: &'a [u8],
        }

        let tests = [
            TestCase {
                precision: TimestampPrecision::Millis,
                val: "20160208-22:07:16.954".as_bytes(),
            },
            TestCase {
                precision: TimestampPrecision::Seconds,
                val: "20160208-22:07:16".as_bytes(),
            },
            TestCase {
                precision: TimestampPrecision::Micros,
                val: "20160208-22:07:16.954123".as_bytes(),
            },
            TestCase {
                precision: TimestampPrecision::Nanos,
                val: "20160208-22:07:16.954123123".as_bytes(),
            },
        ];

        for test in &tests {
            let f = FIXUTCTimestamp {
                time: the_ts,
                precision: test.precision,
            };
            let b = f.write();
            assert_eq!(b, test.val, "got {:?}; want {:?}", b, test.val);
        }
    }

    #[test]
    fn test_fixutc_timestamp_read() {
        struct TestCase<'a> {
            time_str: &'a str,
            expected_time: Timestamp,
            expected_precision: TimestampPrecision,
        }

        let tests = [
            TestCase {
                time_str: "20160208-22:07:16.310",
                expected_time: ts(2016, 2, 8, 22, 7, 16, 310_000_000),
                expected_precision: TimestampPrecision::Millis,
            },
            TestCase {
                time_str: "20160208-22:07:16",
                expected_time: ts(2016, 2, 8, 22, 7, 16, 0),
                expected_precision: TimestampPrecision::Seconds,
            },
            TestCase {
                time_str: "20160208-22:07:16.123455",
                expected_time: ts(2016, 2, 8, 22, 7, 16, 123_455_000),
                expected_precision: TimestampPrecision::Micros,
            },
            TestCase {
                time_str: "20160208-22:07:16.954123123",
                expected_time: ts(2016, 2, 8, 22, 7, 16, 954_123_123),
                expected_precision: TimestampPrecision::Nanos,
            },
        ];

        for test in &tests {
            let mut f = FIXUTCTimestamp::default();
            let result = f.read(test.time_str.as_bytes());
            assert!(result.is_ok(), "Unexpected error: {result:?}");
            assert_eq!(
                f.time, test.expected_time,
                "For Time expected {} got {}",
                test.expected_time, f.time
            );
            assert_eq!(
                f.precision, test.expected_precision,
                "For NoMillis expected expected {:?} got {:?}",
                test.expected_precision, f.precision,
            );
        }
    }
}
