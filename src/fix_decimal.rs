use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};
use rust_decimal::Decimal;
use simple_error::SimpleResult;

// FIXDecimal is a FIX Float Value that implements an arbitrary precision fixed-point decimal.  Implements FieldValue
pub struct FIXDecimal {
    decimal: Decimal,
    pub scale: i32,
}

impl FieldValueReader for FIXDecimal {
    fn read(&mut self, input: &[u8]) -> SimpleResult<()> {
        let fix_decimal = Decimal::from_str_exact(&String::from_utf8_lossy(input))
            .map_err(|err| simple_error!("{}", err))?;
        self.decimal = fix_decimal;
        Ok(())
    }
}

impl FieldValueWriter for FIXDecimal {
    fn write(&self) -> Vec<u8> {
        self.decimal
            .round_dp(self.scale.try_into().unwrap())
            .to_string()
            .into_bytes()
    }
}

impl FieldValue for FIXDecimal {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_decimal_write() {
        struct TestCase {
            decimal: FIXDecimal,
            expected: String,
        }
        let tests = vec![
            TestCase {
                decimal: FIXDecimal {
                    decimal: Decimal::new(-1243456, 4),
                    scale: 4,
                },
                expected: String::from("-124.3456"),
            },
            TestCase {
                decimal: FIXDecimal {
                    decimal: Decimal::new(-1243456, 4),
                    scale: 5,
                },
                expected: String::from("-124.3456"), // FIXME: should be "-124.34560"
            },
            TestCase {
                decimal: FIXDecimal {
                    decimal: Decimal::new(-1243456, 4),
                    scale: 0,
                },
                expected: String::from("-124"),
            },
        ];

        for test in tests.iter() {
            let b = test.decimal.write();
            assert_eq!(test.expected.as_bytes(), b);
        }
    }

    #[test]
    fn test_fix_decimal_read() {
        struct TestCase {
            bytes: String,
            expected: Decimal,
            expect_error: bool,
        }
        let tests = vec![
            TestCase {
                bytes: String::from("15"),
                expected: Decimal::new(15, 0),
                expect_error: false,
            },
            TestCase {
                bytes: String::from("15.000"),
                expected: Decimal::new(15, 0),
                expect_error: false,
            },
            TestCase {
                bytes: String::from("15.001"),
                expected: Decimal::new(15001, 3),
                expect_error: false,
            },
            TestCase {
                bytes: String::from("-15.001"),
                expected: Decimal::new(-15001, 3),
                expect_error: false,
            },
            TestCase {
                bytes: String::from("blah"),
                expected: Decimal::default(),
                expect_error: true,
            },
            TestCase {
                bytes: String::from("+200.00"),
                expected: Decimal::new(200, 0),
                expect_error: false,
            },
        ];

        for test in tests.iter() {
            let decimal_result = Decimal::from_str_exact(&test.bytes);
            if test.expect_error {
                assert!(decimal_result.is_err());
            } else {
                let decimal = decimal_result.unwrap();
                assert_eq!(
                    test.expected, decimal,
                    "Expected {} got {}",
                    test.expected, decimal,
                );
            }
        }
    }
}
