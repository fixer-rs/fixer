use atoi::FromRadix10;
use chrono::{DateTime, Local};
use simple_error::SimpleResult;
use std::io::Read;

const DEFAULT_BUF_SIZE: usize = 4096;

struct Parser {
    big_buffer: Vec<u8>,
    buffer: Vec<u8>,
    reader: Box<dyn Read>,
    last_read: DateTime<Local>,
}

impl Parser {
    pub fn new(reader: Box<dyn Read>) -> Self {
        Self {
            big_buffer: vec![],
            buffer: vec![],
            reader,
            last_read: Local::now(),
        }
    }

    fn read_more(&mut self) -> SimpleResult<isize> {
        if self.buffer.len() == self.buffer.capacity() {
            // initialize the parser
            let new_buffer: &[u8] = if self.big_buffer.len() == 0 {
                self.big_buffer = Vec::with_capacity(DEFAULT_BUF_SIZE);
                &self.big_buffer.get(0..0).unwrap()
            // shift buffer back to the start of big_buffer
            } else if 2 * self.buffer.len() <= self.big_buffer.len() {
                &self.big_buffer.get(0..self.buffer.len()).unwrap()
            // reallocate big buffer with enough space to shift buffer
            } else {
                self.big_buffer = Vec::with_capacity(2 * self.buffer.len());
                &self.big_buffer.get(0..self.buffer.len()).unwrap()
            };

            self.buffer = new_buffer.to_vec();
        }

        let len = self.buffer.len();
        let cap = self.buffer.capacity();

        let buffer = self.buffer.get_mut(len..cap).unwrap();
        let read_buffer = self.reader.read(buffer);
        let n = map_err_with!(read_buffer, "failed to parse buffer")?;

        self.last_read = Local::now();
        self.buffer = self.buffer.get(..self.buffer.len() + n).unwrap().to_vec();
        Ok(n as isize)
    }

    fn find_index(&mut self, delim: &Vec<u8>) -> SimpleResult<isize> {
        self.find_index_after_offset(0, delim)
    }

    fn find_index_after_offset(&mut self, offset: isize, delim: &Vec<u8>) -> SimpleResult<isize> {
        loop {
            if offset as usize > self.buffer.len() {
                if let Err(err) = self.read_more() {
                    return Err(err);
                }
                continue;
            }

            let buffer_offset = self.buffer.get(offset as usize..).unwrap();
            let index = buffer_offset
                .windows(delim.len())
                .position(|window| window == delim);
            if index.is_some() {
                return Ok(index.unwrap() as isize + offset);
            }

            if let Err(err) = self.read_more() {
                return Err(err);
            }
        }
    }

    fn find_start(&mut self) -> SimpleResult<isize> {
        self.find_index(&("8=".as_bytes().to_vec()))
    }

    fn find_end_after_offset(&mut self, offset: isize) -> SimpleResult<isize> {
        let index = self.find_index_after_offset(offset, &("\x0110=".as_bytes().to_vec()))?;

        let index = self.find_index_after_offset(index + 1, &("\x01".as_bytes().to_vec()))?;

        Ok(index + 1)
    }

    fn jump_length(&mut self) -> SimpleResult<isize> {
        let mut length_index = self.find_index(&("9=".as_bytes().to_vec()))?;
        length_index += 3;

        let offset = self.find_index_after_offset(length_index, &("\x01".as_bytes().to_vec()))?;

        if offset == length_index {
            return Err(simple_error!("No length given"));
        }

        let (length, dgt) = isize::from_radix_10(
            self.buffer
                .get(length_index as usize..offset as usize)
                .unwrap(),
        );

        if length == 0 && dgt == 0 {
            return Err(simple_error!("Invalid length"));
        }

        Ok(offset + length)
    }

    fn read_message(&mut self) -> SimpleResult<Vec<u8>> {
        let start = self.find_start()?;
        self.buffer = self.buffer.get(start as usize..).unwrap().to_vec();

        let index = self.jump_length()?;

        let index = self.find_end_after_offset(index)?;

        let msg_bytes = self.buffer.get(..index as usize).unwrap();

        self.buffer = msg_bytes.clone().to_vec();

        Ok(self.buffer.clone())
    }
}
