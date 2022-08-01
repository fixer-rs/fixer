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
                expected: String::from("-124.34560"),
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
            // 		b := test.decimal.Write()
            // 		assert.Equal(t, test.expected, string(b))
        }
        // 	var tests = []struct {
        // 		decimal  FIXDecimal
        // 		expected string
        // 	}{
        // 		{decimal: FIXDecimal{Decimal: decimal.New(-1243456, -4), Scale: 4}, expected: "-124.3456"},
        // 		{decimal: FIXDecimal{Decimal: decimal.New(-1243456, -4), Scale: 5}, expected: "-124.34560"},
        // 		{decimal: FIXDecimal{Decimal: decimal.New(-1243456, -4), Scale: 0}, expected: "-124"},
        // 	}

        // 	for _, test := range tests {
        // 		b := test.decimal.Write()
        // 		assert.Equal(t, test.expected, string(b))
        // 	}
    }

    // func TestFIXDecimalRead(t *testing.T) {
    // 	var tests = []struct {
    // 		bytes       string
    // 		expected    decimal.Decimal
    // 		expectError bool
    // 	}{
    // 		{bytes: "15", expected: decimal.New(15, 0)},
    // 		{bytes: "15.000", expected: decimal.New(15, 0)},
    // 		{bytes: "15.001", expected: decimal.New(15001, -3)},
    // 		{bytes: "-15.001", expected: decimal.New(-15001, -3)},
    // 		{bytes: "blah", expectError: true},
    // 		{bytes: "+200.00", expected: decimal.New(200, 0)},
    // 	}

    // 	for _, test := range tests {
    // 		var field FIXDecimal

    // 		err := field.Read([]byte(test.bytes))
    // 		require.Equal(t, test.expectError, err != nil)

    // 		if !test.expectError {
    // 			assert.True(t, test.expected.Equals(field.Decimal), "Expected %s got %s", test.expected, field.Decimal)
    // 		}
    // 	}
    // }
}
