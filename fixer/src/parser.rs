use crate::fix_int::atoi;
use jiff::Timestamp;
use memchr::memmem::Finder;
use simple_error::SimpleResult;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

const BEGIN_STRING: &str = "8=";
const BODY_LENGTH: &str = "\u{1}9=";
const CHECKSUM: &str = "\u{1}10=";
const DEFAULT_BUF_SIZE: usize = 4096;

pub struct Parser<T: Unpin + AsyncRead> {
    big_buffer: Vec<u8>,
    reader: BufReader<T>,
    pub last_read: Timestamp,
    start: usize,
    end: usize,
    len: usize,
    cap: usize,
}

impl<T> Parser<T>
where
    T: Unpin + AsyncRead,
{
    pub fn new(reader: BufReader<T>) -> Self
    where
        T: AsyncReadExt,
    {
        Self {
            big_buffer: vec![],
            reader,
            last_read: Timestamp::now(),
            start: 0,
            end: 0,
            len: 0,
            cap: 0,
        }
    }

    async fn read_more(&mut self) -> SimpleResult<isize> {
        if self.len == self.cap {
            if self.big_buffer.is_empty() {
                self.big_buffer = Vec::with_capacity(DEFAULT_BUF_SIZE);
                self.big_buffer.resize(DEFAULT_BUF_SIZE, 0);
                self.start = 0;
                self.end = 0;
                self.len = 0;
                self.cap = DEFAULT_BUF_SIZE;
            } else if self.len * 2 <= self.big_buffer.len() {
                // Enough room — shift data to the front in-place
                self.big_buffer.copy_within(self.start..self.end, 0);
                self.start = 0;
                self.end = self.len;
            } else {
                // Need to grow — shift data to front, then resize
                self.big_buffer.copy_within(self.start..self.end, 0);
                self.cap = 2 * self.len;
                let new_reserve = self.cap - self.big_buffer.len();
                self.big_buffer.reserve_exact(new_reserve);
                self.big_buffer.resize(self.cap, 0);
                self.start = 0;
                self.end = self.len;
            }

            self.cap = self.big_buffer.capacity();
        }

        let n = self
            .reader
            .read(&mut self.big_buffer[self.end..self.start + self.cap])
            .await
            .map_err(|_| simple_error!("failed to parse big_buffer"))?;

        if n == 0 {
            return Err(simple_error!("eof"));
        }
        self.last_read = Timestamp::now();

        self.end += n;
        self.len = self.end - self.start;

        Ok(n.try_into().unwrap())
    }

    async fn find_index(&mut self, finder: &Finder<'_>) -> SimpleResult<isize> {
        self.find_index_after_offset(0, finder).await
    }

    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    async fn find_index_after_offset(
        &mut self,
        offset: isize,
        finder: &Finder<'_>,
    ) -> SimpleResult<isize> {
        loop {
            if offset as usize > self.len {
                self.read_more().await?;
                continue;
            }

            let haystack = &self.big_buffer[self.start + offset as usize..self.end];
            if let Some(index) = finder.find(haystack) {
                return Ok(index as isize + offset);
            }

            self.read_more().await?;
        }
    }

    // Fast path for single-byte delimiter (SOH).
    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    async fn find_byte_after_offset(
        &mut self,
        offset: isize,
        byte: u8,
    ) -> SimpleResult<isize> {
        loop {
            if offset as usize > self.len {
                self.read_more().await?;
                continue;
            }

            let haystack = &self.big_buffer[self.start + offset as usize..self.end];
            if let Some(index) = memchr::memchr(byte, haystack) {
                return Ok(index as isize + offset);
            }

            self.read_more().await?;
        }
    }

    async fn find_start(&mut self) -> SimpleResult<isize> {
        let finder = Finder::new(BEGIN_STRING.as_bytes());
        self.find_index(&finder).await
    }

    async fn find_end_after_offset(&mut self, offset: isize) -> SimpleResult<isize> {
        let checksum_finder = Finder::new(CHECKSUM.as_bytes());
        let index = self
            .find_index_after_offset(offset, &checksum_finder)
            .await?;

        let index = self
            .find_byte_after_offset(index + 1, b'\x01')
            .await?;

        Ok(index + 1)
    }

    #[allow(clippy::cast_sign_loss)]
    async fn jump_length(&mut self) -> SimpleResult<isize> {
        let body_length_finder = Finder::new(BODY_LENGTH.as_bytes());
        let mut length_index = self.find_index(&body_length_finder).await?;

        length_index += 3;

        let offset = self
            .find_byte_after_offset(length_index, b'\x01')
            .await?;

        if offset == length_index {
            return Err(simple_error!("No length given"));
        }

        let length = atoi(
            &self.big_buffer[(self.start + length_index as usize)..(self.start + offset as usize)],
        )
        .map_err(|_| simple_error!("Invalid length"))?;

        Ok(offset + length)
    }

    #[allow(clippy::cast_sign_loss)]
    pub async fn read_message(&mut self) -> SimpleResult<bytes::Bytes> {
        let start = self.find_start().await?;

        self.start += start as usize;
        self.len = self.end - self.start;
        self.cap -= start as usize;

        let index = self.jump_length().await?;

        let index = self.find_end_after_offset(index).await?;

        let msg_bytes =
            bytes::Bytes::copy_from_slice(&self.big_buffer[self.start..self.start + index as usize]);

        self.start += index as usize;
        self.len = self.end - self.start;
        self.cap -= index as usize;

        Ok(msg_bytes)
    }
}

#[cfg(test)]
#[allow(clippy::items_after_statements, clippy::struct_field_names)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_invalid_nil_length() {
        let stream = "8=\u{1}9=\u{1}";
        let buf_reader = BufReader::new(stream.as_bytes());
        let mut s = Parser::new(buf_reader);
        let result = s.read_message().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_overflow_length() {
        let stream = "8=\u{1}9=9300000000000000000\u{1}";
        let buf_reader = BufReader::new(stream.as_bytes());
        let mut s = Parser::new(buf_reader);
        let result = s.read_message().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_jump_length() {
        let stream = "8=FIXT.1.19=11135=D34=449=TW52=20140511-23:10:3456=ISLD11=ID21=340=154=155=INTC60=20140511-23:10:3410=2348=FIXT.1.19=9535=D34=549=TW52=20140511-23:10:3456=ISLD11=ID21=340=154=155=INTC60=20140511-23:10:3410=198";
        let buf_reader = BufReader::new(stream.as_bytes());
        let mut s = Parser::new(buf_reader);
        let index_result = s.jump_length().await;
        assert!(index_result.is_ok());

        let index = index_result.unwrap();
        let expected_index = 111 + 17 - 1;
        assert_eq!(expected_index, index);
    }

    #[tokio::test]
    async fn test_bad_length() {
        let stream = "8=FIXT.1.19=11135=D34=449=TW52=20140511-23:10:3456=ISLD11=ID21=340=154=155=INTC60=20140511-23:10:3410=2348=FIXT.1.19=9535=D34=549=TW52=20140511-23:10:3456=ISLD11=ID21=340=154=155=INTC60=20140511-23:10:3410=198";
        let buf_reader = BufReader::new(stream.as_bytes());
        let mut s = Parser::new(buf_reader);
        let bytes_result = s.read_message().await;
        assert!(bytes_result.is_ok());
        let bytes = bytes_result.unwrap();
        assert_eq!(stream, std::str::from_utf8(&bytes).unwrap());
    }

    #[tokio::test]
    #[allow(clippy::cast_sign_loss)]
    async fn test_find_start() {
        struct TestCase<'a> {
            stream: &'a str,
            expect_error: bool,
            expected_start: usize,
        }
        let tests = [TestCase {
                stream: "",
                expect_error: true,
                expected_start: 0,
            },
            TestCase {
                stream: "nostarthere",
                expect_error: true,
                expected_start: 0,
            },
            TestCase {
                stream: "hello8=FIX.4.0",
                expect_error: false,
                expected_start: 5,
            }];
        for test in &tests {
            let buf_reader = BufReader::new(test.stream.as_bytes());
            let mut s = Parser::new(buf_reader);
            let start_result = s.find_start().await;
            if test.expect_error {
                assert!(start_result.is_err());
                continue;
            }

            assert!(start_result.is_ok());
            assert_eq!(test.expected_start, start_result.unwrap() as usize);
        }
    }

    #[tokio::test]
    async fn test_read_eof() {
        struct TestCase<'a> {
            stream: &'a str,
        }
        let tests = [TestCase { stream: "" },
            TestCase {
                stream: "hello8=FIX.4.0",
            }];

        for test in &tests {
            let buf_reader = BufReader::new(test.stream.as_bytes());
            let mut s = Parser::new(buf_reader);

            let bytes_result = s.read_message().await;
            assert!(bytes_result.is_err());
        }
    }

    #[tokio::test]
    async fn test_read_message() {
        let stream = "hello8=FIX.4.09=5blah10=1038=FIX.4.09=4foo10=103";
        let buf_reader = BufReader::new(stream.as_bytes());
        let mut s = Parser::new(buf_reader);

        struct TestCase<'a> {
            expected_bytes: &'a str,
            expected_buffer_len: usize,
            expected_buffer_cap: usize,
        }

        let tests = [TestCase {
                expected_bytes: "8=FIX.4.09=5blah10=103",
                expected_buffer_cap: DEFAULT_BUF_SIZE - 31,
                expected_buffer_len: stream.len() - 31,
            },
            TestCase {
                expected_bytes: "8=FIX.4.09=4foo10=103",
                expected_buffer_cap: DEFAULT_BUF_SIZE - 31 - 25,
                expected_buffer_len: 0,
            }];

        for test in &tests {
            let msg_result = s.read_message().await;
            assert!(msg_result.is_ok());

            let msg = msg_result.unwrap();
            assert_eq!(test.expected_bytes.as_bytes(), msg);
            assert_eq!(test.expected_buffer_cap, s.cap);
            assert_eq!(test.expected_buffer_len, s.len);
        }
    }

    #[tokio::test]
    async fn test_read_message_grow_big_buffer() {
        let stream = "hello8=FIX.4.09=5blah10=1038=FIX.4.09=4foo10=103";

        struct TestCase {
            initial_buf_cap: usize,
            expected_buffer_len: usize,
            expected_buffer_cap: usize,
            expected_big_buffer_len: usize,
        }

        let tests = vec![
            TestCase {
                initial_buf_cap: 0,
                expected_buffer_cap: (DEFAULT_BUF_SIZE - 31),
                expected_buffer_len: (stream.len() - 31),
                expected_big_buffer_len: DEFAULT_BUF_SIZE,
            },
            TestCase {
                initial_buf_cap: 4,
                expected_buffer_cap: 6,
                expected_buffer_len: 6,
                expected_big_buffer_len: 32,
            },
            TestCase {
                initial_buf_cap: 8,
                expected_buffer_cap: 6,
                expected_buffer_len: 6,
                expected_big_buffer_len: 32,
            },
            TestCase {
                initial_buf_cap: 14,
                expected_buffer_cap: 10,
                expected_buffer_len: 10,
                expected_big_buffer_len: 36,
            },
            TestCase {
                initial_buf_cap: 16,
                expected_buffer_cap: 18,
                expected_buffer_len: 18,
                expected_big_buffer_len: 44,
            },
            TestCase {
                initial_buf_cap: 23,
                expected_buffer_cap: 10,
                expected_buffer_len: 10,
                expected_big_buffer_len: 36,
            },
            TestCase {
                initial_buf_cap: 30,
                expected_buffer_cap: 24,
                expected_buffer_len: 24,
                expected_big_buffer_len: 50,
            },
            TestCase {
                initial_buf_cap: 31,
                expected_buffer_cap: 0,
                expected_buffer_len: 0,
                expected_big_buffer_len: 31,
            },
            TestCase {
                initial_buf_cap: 40,
                expected_buffer_cap: 9,
                expected_buffer_len: 9,
                expected_big_buffer_len: 40,
            },
            TestCase {
                initial_buf_cap: 60,
                expected_buffer_cap: 29,
                expected_buffer_len: 25,
                expected_big_buffer_len: 60,
            },
            TestCase {
                initial_buf_cap: 80,
                expected_buffer_cap: 49,
                expected_buffer_len: 25,
                expected_big_buffer_len: 80,
            },
        ];

        for test in &tests {
            let buf_reader = BufReader::new(stream.as_bytes());
            let mut s = Parser::new(buf_reader);

            s.big_buffer = vec![0; test.initial_buf_cap];
            s.cap = s.big_buffer.capacity();
            let msg_result = s.read_message().await;
            assert!(msg_result.is_ok());
            let msg = msg_result.unwrap();
            assert_eq!("8=FIX.4.09=5blah10=103", std::str::from_utf8(&msg).unwrap());
            assert_eq!(test.expected_buffer_len, s.len);
            assert_eq!(test.expected_buffer_cap, s.cap);
            assert_eq!(test.expected_big_buffer_len, s.big_buffer.len());
        }
    }
}
