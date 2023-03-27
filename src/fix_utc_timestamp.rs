use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use chrono::{naive::NaiveDateTime, DateTime, TimeZone, Utc};

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
#[derive(Default)]
pub struct FIXUTCTimestamp {
    pub time: DateTime<Utc>,
    pub precision: TimestampPrecision,
}

impl FieldValueReader for FIXUTCTimestamp {
    fn read(&mut self, input: &[u8]) -> Result<(), ()> {
        let input_str = String::from_utf8_lossy(input).to_string();
        match input_str.len() {
            17 => {
                self.precision = TimestampPrecision::Seconds;
                self.time = Utc
                    .datetime_from_str(&input_str, UTC_TIMESTAMP_SECONDS_FORMAT)
                    .map_err(|_| ())?;
            }
            21 => {
                self.precision = TimestampPrecision::Millis;
                self.time = Utc
                    .datetime_from_str(&input_str, UTC_TIMESTAMP_MILLIS_FORMAT)
                    .map_err(|_| ())?;
            }
            24 => {
                self.precision = TimestampPrecision::Micros;
                self.time = Utc
                    .datetime_from_str(&input_str, UTC_TIMESTAMP_MICROS_FORMAT)
                    .map_err(|_| ())?;
            }
            27 => {
                self.precision = TimestampPrecision::Nanos;
                self.time = Utc
                    .datetime_from_str(&input_str, UTC_TIMESTAMP_NANOS_FORMAT)
                    .map_err(|_| ())?;
            }
            _ => (),
        };

        Ok(())
    }
}

impl FieldValueWriter for FIXUTCTimestamp {
    fn write(&self) -> Vec<u8> {
        match self.precision {
            TimestampPrecision::Seconds => self
                .time
                .format(UTC_TIMESTAMP_SECONDS_FORMAT)
                .to_string()
                .into_bytes(),
            TimestampPrecision::Millis => self
                .time
                .format(UTC_TIMESTAMP_MILLIS_FORMAT)
                .to_string()
                .into_bytes(),
            TimestampPrecision::Micros => self
                .time
                .format(UTC_TIMESTAMP_MICROS_FORMAT)
                .to_string()
                .into_bytes(),
            TimestampPrecision::Nanos => self
                .time
                .format(UTC_TIMESTAMP_NANOS_FORMAT)
                .to_string()
                .into_bytes(),
        }
    }
}

impl FieldValue for FIXUTCTimestamp {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::time_range::utc;
    use chrono::{naive::NaiveDate, Timelike};

    #[test]
    fn test_fixutc_timestamp_write() {
        let ts = utc()
            .with_ymd_and_hms(2016, 2, 8, 22, 7, 16)
            .unwrap()
            .with_nanosecond(954_123_123)
            .unwrap();

        struct TestCase<'a> {
            precision: TimestampPrecision,
            val: &'a [u8],
        }

        let tests = vec![
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

        for test in tests.iter() {
            let mut f = FIXUTCTimestamp::default();
            f.time = ts.into();
            f.precision = test.precision;
            let b = f.write();
            assert_eq!(b, test.val, "got {:?}; want {:?}", b, test.val);
        }
    }

    #[test]
    fn test_fixutc_timestamp_read() {
        struct TestCase<'a> {
            time_str: &'a str,
            expected_time: DateTime<Utc>,
            expected_precision: TimestampPrecision,
        }

        let tests = vec![
            TestCase {
                time_str: "20160208-22:07:16.310",
                expected_time: NaiveDate::from_ymd_opt(2016, 2, 8)
                    .unwrap()
                    .and_hms_nano_opt(22, 7, 16, 310_000_000)
                    .unwrap()
                    .and_local_timezone(Utc)
                    .unwrap(),
                expected_precision: TimestampPrecision::Millis,
            },
            TestCase {
                time_str: "20160208-22:07:16",
                expected_time: NaiveDate::from_ymd_opt(2016, 2, 8)
                    .unwrap()
                    .and_hms_nano_opt(22, 7, 16, 0)
                    .unwrap()
                    .and_local_timezone(Utc)
                    .unwrap(),
                expected_precision: TimestampPrecision::Seconds,
            },
            TestCase {
                time_str: "20160208-22:07:16.123455",
                expected_time: NaiveDate::from_ymd_opt(2016, 2, 8)
                    .unwrap()
                    .and_hms_nano_opt(22, 7, 16, 123_455_000)
                    .unwrap()
                    .and_local_timezone(Utc)
                    .unwrap(),
                expected_precision: TimestampPrecision::Micros,
            },
            TestCase {
                time_str: "20160208-22:07:16.954123123",
                expected_time: NaiveDate::from_ymd_opt(2016, 2, 8)
                    .unwrap()
                    .and_hms_nano_opt(22, 7, 16, 954_123_123)
                    .unwrap()
                    .and_local_timezone(Utc)
                    .unwrap(),
                expected_precision: TimestampPrecision::Nanos,
            },
        ];

        for test in tests.iter() {
            let mut f = FIXUTCTimestamp::default();
            let result = f.read(test.time_str.as_bytes());
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
