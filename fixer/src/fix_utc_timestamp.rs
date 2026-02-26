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

pub const UTC_TIMESTAMP_SECONDS_FORMAT: &str = "%Y%m%d-%H:%M:%S";
pub const UTC_TIMESTAMP_MILLIS_FORMAT: &str = "%Y%m%d-%H:%M:%S%.3f";
pub const UTC_TIMESTAMP_MICROS_FORMAT: &str = "%Y%m%d-%H:%M:%S%.6f";
pub const UTC_TIMESTAMP_NANOS_FORMAT: &str = "%Y%m%d-%H:%M:%S%.9f";

// FIXUTCTimestamp is a FIX UTC Timestamp value, implements FieldValue
#[derive(Default, Debug)]
pub struct FIXUTCTimestamp {
    pub time: Timestamp,
    pub precision: TimestampPrecision,
}

impl FieldValueReader for FIXUTCTimestamp {
    fn read(&mut self, input: &[u8]) -> SimpleResult<()> {
        let res = |_| {
            simple_error!(
                "Invalid Value for Timestamp: {}",
                String::from_utf8_lossy(input)
            )
        };
        let input_str = String::from_utf8_lossy(input).to_string();
        let parse_to_ts = |fmt: &str, s: &str| -> SimpleResult<Timestamp> {
            let dt = civil::DateTime::strptime(fmt, s).map_err(res)?;
            dt.to_zoned(TimeZone::UTC)
                .map(|z| z.timestamp())
                .map_err(res)
        };
        match input_str.len() {
            17 => {
                self.precision = TimestampPrecision::Seconds;
                self.time = parse_to_ts(UTC_TIMESTAMP_SECONDS_FORMAT, &input_str)?;
                Ok(())
            }
            21 => {
                self.precision = TimestampPrecision::Millis;
                self.time = parse_to_ts(UTC_TIMESTAMP_MILLIS_FORMAT, &input_str)?;
                Ok(())
            }
            24 => {
                self.precision = TimestampPrecision::Micros;
                self.time = parse_to_ts(UTC_TIMESTAMP_MICROS_FORMAT, &input_str)?;
                Ok(())
            }
            27 => {
                self.precision = TimestampPrecision::Nanos;
                self.time = parse_to_ts(UTC_TIMESTAMP_NANOS_FORMAT, &input_str)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl FieldValueWriter for FIXUTCTimestamp {
    fn write_to(&self, buf: &mut Vec<u8>) {
        use std::io::Write;
        let fmt = match self.precision {
            TimestampPrecision::Seconds => UTC_TIMESTAMP_SECONDS_FORMAT,
            TimestampPrecision::Millis => UTC_TIMESTAMP_MILLIS_FORMAT,
            TimestampPrecision::Micros => UTC_TIMESTAMP_MICROS_FORMAT,
            TimestampPrecision::Nanos => UTC_TIMESTAMP_NANOS_FORMAT,
        };
        write!(buf, "{}", self.time.strftime(fmt)).unwrap();
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
