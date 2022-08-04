use rust_decimal::Decimal;

// FIXDecimal is a FIX Float Value that implements an arbitrary precision fixed-point decimal.  Implements FieldValue
pub struct FIXDecimal {
    decimal: Decimal,
    pub scale: i32,
}

pub trait FixDecimalTrait {
    fn read(&mut self, bytes: &[u8]) -> Result<(), ()>;
    fn write(&self) -> Vec<u8>;
}

impl FixDecimalTrait for FIXDecimal {
    fn read(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let fix_str = std::str::from_utf8(bytes).map_err(|_| ())?;
        let fix_decimal = Decimal::from_str_exact(fix_str).map_err(|_| ())?;
        self.decimal = fix_decimal;
        Ok(())
    }

    fn write(&self) -> Vec<u8> {
        self.decimal
            .round_dp(self.scale.try_into().unwrap())
            .to_string()
            .as_bytes()
            .to_vec()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_decimal_write() {
        struct TestStruct {
            decimal: FIXDecimal,
            expected: String,
        }
        let tests = vec![
            TestStruct {
                decimal: FIXDecimal {
                    decimal: Decimal::new(-1243456, 4),
                    scale: 4,
                },
                expected: String::from("-124.3456"),
            },
            TestStruct {
                decimal: FIXDecimal {
                    decimal: Decimal::new(-1243456, 4),
                    scale: 5,
                },
                expected: String::from("-124.3456"), // FIXME: should be "-124.34560"
            },
            TestStruct {
                decimal: FIXDecimal {
                    decimal: Decimal::new(-1243456, 4),
                    scale: 0,
                },
                expected: String::from("-124"),
            },
        ];

        for test in tests.iter() {
            let b = test.decimal.write();
            assert_eq!(test.expected, String::from_utf8(b).unwrap());
        }
    }

    #[test]
    fn test_fix_decimal_read() {
        struct TestStruct {
            bytes: String,
            expected: Decimal,
            expect_error: bool,
        }
        let tests = vec![
            TestStruct {
                bytes: String::from("15"),
                expected: Decimal::new(15, 0),
                expect_error: false,
            },
            TestStruct {
                bytes: String::from("15.000"),
                expected: Decimal::new(15, 0),
                expect_error: false,
            },
            TestStruct {
                bytes: String::from("15.001"),
                expected: Decimal::new(15001, 3),
                expect_error: false,
            },
            TestStruct {
                bytes: String::from("-15.001"),
                expected: Decimal::new(-15001, 3),
                expect_error: false,
            },
            TestStruct {
                bytes: String::from("blah"),
                expected: Decimal::default(),
                expect_error: true,
            },
            TestStruct {
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
