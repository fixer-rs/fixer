use crate::field::{FieldValue, FieldValueReader, FieldValueWriter};

// FIXFloat is a FIX Float Value, implements FieldValue
pub type FIXFloat = f64;

pub trait FIXFloatTrait {
    fn float64(&self) -> f64;
}

impl FIXFloatTrait for FIXFloat {
    fn float64(&self) -> f64 {
        *self
    }
}

impl FieldValueReader for FIXFloat {
    fn read(&mut self, input: &str) -> Result<(), ()> {
        let f = fast_float::parse(input).map_err(|_| ())?;

        for chr in input.chars() {
            if chr != '.' && chr != '-' && !('0'..='9').contains(&chr) {
                return Err(());
            }
        }

        *self = f;

        Ok(())
    }
}

impl FieldValueWriter for FIXFloat {
    fn write(&self) -> String {
        format!("{}", self)
    }
}

impl FieldValue for FIXFloat {}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_float_write() {
        struct TestCase<'a> {
            field: FIXFloat,
            val: &'a str,
        }
        let tests = vec![TestCase {
            field: 5.0,
            val: "5",
        }];
        for test in tests.iter() {
            let b = test.field.write();
            assert_eq!(b, test.val, "got {}; want {}", b, test.val);
        }
    }

    #[test]
    fn test_float_read() {
        struct TestCase<'a> {
            bytes: &'a str,
            value: f64,
            expect_error: bool,
        }
        let tests = vec![
            TestCase {
                bytes: "15",
                value: 15.0,
                expect_error: false,
            },
            TestCase {
                bytes: "99.9",
                value: 99.9,
                expect_error: false,
            },
            TestCase {
                bytes: "0.00",
                value: 0.0,
                expect_error: false,
            },
            TestCase {
                bytes: ("-99.9"),
                value: -99.9,
                expect_error: false,
            },
            TestCase {
                bytes: ("-99.9.9"),
                value: 0.0,
                expect_error: true,
            },
            TestCase {
                bytes: ("blah"),
                value: 0.0,
                expect_error: true,
            },
            TestCase {
                bytes: ("1.a1"),
                value: 0.0,
                expect_error: true,
            },
            TestCase {
                bytes: ("+200.00"),
                value: 0.0,
                expect_error: true,
            },
        ];
        for test in tests.iter() {
            let mut field = FIXFloat::default();
            let err = field.read(test.bytes);
            assert_eq!(test.expect_error, err.is_err());
            assert_eq!(test.value, field.float64());
        }
    }
}
