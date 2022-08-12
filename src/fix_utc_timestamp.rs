use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use chrono::naive::NaiveDateTime;

#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub enum TimestampPrecision {
    #[default]
    Millis,
    Seconds,
    Micros,
    Nanos,
}

const UTC_TIMESTAMP_SECONDS_FORMAT: &str = "%Y%m%d-%H:%M:%S";
const UTC_TIMESTAMP_MILLIS_FORMAT: &str = "%Y%m%d-%H:%M:%S%.3f";
const UTC_TIMESTAMP_MICROS_FORMAT: &str = "%Y%m%d-%H:%M:%S%.6f";
const UTC_TIMESTAMP_NANOS_FORMAT: &str = "%Y%m%d-%H:%M:%S%.9f";

// FIXUTCTimestamp is a FIX UTC Timestamp value, implements FieldValue
#[derive(Default)]
pub struct FIXUTCTimestamp {
    pub time: NaiveDateTime,
    pub precision: TimestampPrecision,
}

impl FieldValueReader for FIXUTCTimestamp {
    fn read(&mut self, input: &str) -> Result<(), ()> {
        match input.len() {
            17 => {
                self.precision = TimestampPrecision::Seconds;
                self.time = NaiveDateTime::parse_from_str(input, UTC_TIMESTAMP_SECONDS_FORMAT)
                    .map_err(|_| ())?;
            }
            21 => {
                self.precision = TimestampPrecision::Millis;
                self.time = NaiveDateTime::parse_from_str(input, UTC_TIMESTAMP_MILLIS_FORMAT)
                    .map_err(|_| ())?;
            }
            24 => {
                self.precision = TimestampPrecision::Micros;
                self.time = NaiveDateTime::parse_from_str(input, UTC_TIMESTAMP_MICROS_FORMAT)
                    .map_err(|_| ())?;
            }
            27 => {
                self.precision = TimestampPrecision::Nanos;
                self.time = NaiveDateTime::parse_from_str(input, UTC_TIMESTAMP_NANOS_FORMAT)
                    .map_err(|_| ())?;
            }
            _ => (),
        };

        Ok(())
    }
}

impl FieldValueWriter for FIXUTCTimestamp {
    fn write(&self) -> String {
        match self.precision {
            TimestampPrecision::Seconds => {
                self.time.format(UTC_TIMESTAMP_SECONDS_FORMAT).to_string()
            }
            TimestampPrecision::Millis => self.time.format(UTC_TIMESTAMP_MILLIS_FORMAT).to_string(),
            TimestampPrecision::Micros => self.time.format(UTC_TIMESTAMP_MICROS_FORMAT).to_string(),
            TimestampPrecision::Nanos => self.time.format(UTC_TIMESTAMP_NANOS_FORMAT).to_string(),
        }
    }
}

impl FieldValue for FIXUTCTimestamp {}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::naive::NaiveDate;

    #[test]
    fn test_fixutc_timestamp_write() {
        let ts = NaiveDate::from_ymd(2016, 2, 8).and_hms_nano(22, 7, 16, 954_123_123);

        struct TestCase {
            precision: TimestampPrecision,
            val: String,
        }

        let tests = vec![
            TestCase {
                precision: TimestampPrecision::Millis,
                val: "20160208-22:07:16.954".to_string(),
            },
            TestCase {
                precision: TimestampPrecision::Seconds,
                val: "20160208-22:07:16".to_string(),
            },
            TestCase {
                precision: TimestampPrecision::Micros,
                val: "20160208-22:07:16.954123".to_string(),
            },
            TestCase {
                precision: TimestampPrecision::Nanos,
                val: "20160208-22:07:16.954123123".to_string(),
            },
        ];

        for test in tests.iter() {
            let mut f = FIXUTCTimestamp::default();
            f.time = ts;
            f.precision = test.precision;
            let b = f.write();
            assert_eq!(b, test.val, "got {}; want {}", b, test.val);
        }
    }

    #[test]
    fn test_fixutc_timestamp_read() {
        struct TestCase<'a> {
            time_str: &'a str,
            expected_time: NaiveDateTime,
            expected_precision: TimestampPrecision,
        }

        let tests = vec![
            TestCase {
                time_str: "20160208-22:07:16.310",
                expected_time: NaiveDate::from_ymd(2016, 2, 8).and_hms_nano(22, 7, 16, 310_000_000),
                expected_precision: TimestampPrecision::Millis,
            },
            TestCase {
                time_str: "20160208-22:07:16",
                expected_time: NaiveDate::from_ymd(2016, 2, 8).and_hms_nano(22, 7, 16, 0),
                expected_precision: TimestampPrecision::Seconds,
            },
            TestCase {
                time_str: "20160208-22:07:16.123455",
                expected_time: NaiveDate::from_ymd(2016, 2, 8).and_hms_nano(22, 7, 16, 123_455_000),
                expected_precision: TimestampPrecision::Micros,
            },
            TestCase {
                time_str: "20160208-22:07:16.954123123",
                expected_time: NaiveDate::from_ymd(2016, 2, 8).and_hms_nano(22, 7, 16, 954_123_123),
                expected_precision: TimestampPrecision::Nanos,
            },
        ];

        for test in tests.iter() {
            let mut f = FIXUTCTimestamp::default();
            let result = f.read(test.time_str);
            assert!(result.is_ok(), "Unexpected error: {:?}", result);
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
