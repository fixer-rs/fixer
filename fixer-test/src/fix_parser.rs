use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

const SOH: u8 = 0x01;

/// Reads framed FIX messages from a TCP stream.
///
/// Uses tag 9 (`BodyLength`) as the framing mechanism:
/// 1. Read until `\x019=` to find the start of body length
/// 2. Read the body length value until next SOH
/// 3. Read exactly that many bytes for the body
/// 4. Read the checksum field (`10=xxx\x01`)
pub struct FixParser<R> {
    reader: BufReader<R>,
}

impl<R: AsyncRead + Unpin> FixParser<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
        }
    }

    /// Read one complete FIX message from the stream.
    ///
    /// Returns the raw bytes of the complete message including all SOH delimiters.
    /// Returns `Ok(None)` on EOF (connection closed).
    pub async fn read_message(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut msg = Vec::with_capacity(256);

        // Phase 1: Read bytes until we find "\x019=" (SOH + "9=").
        // The message starts with "8=...\x01" then "9=".
        // We read byte-by-byte looking for the pattern.
        loop {
            let b = match self.read_byte().await {
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    if msg.is_empty() {
                        return Ok(None); // Clean EOF
                    }
                    return Err(e);
                }
                Err(e) => return Err(e),
            };
            msg.push(b);

            // Check if we just completed "\x019="
            if msg.len() >= 3
                && msg[msg.len() - 1] == b'='
                && msg[msg.len() - 2] == b'9'
                && msg[msg.len() - 3] == SOH
            {
                break;
            }
        }

        // Phase 2: Read the body length value (digits until SOH).
        let mut length_bytes = Vec::new();
        loop {
            let b = self.read_byte().await?;
            if b == SOH {
                msg.push(b); // The SOH after body length
                break;
            }
            if !b.is_ascii_digit() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("non-digit in body length: {b}"),
                ));
            }
            length_bytes.push(b);
            msg.push(b);
        }

        let length_str = String::from_utf8_lossy(&length_bytes);
        let body_length: usize = length_str.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid body length '{length_str}': {e}"),
            )
        })?;

        // Phase 3: Read exactly body_length bytes.
        let mut body = vec![0u8; body_length];
        self.reader.read_exact(&mut body).await?;
        msg.extend_from_slice(&body);

        // Phase 4: Read the checksum field (10=xxx\x01).
        loop {
            let b = self.read_byte().await?;
            msg.push(b);
            if b == SOH {
                break;
            }
        }

        Ok(Some(msg))
    }

    async fn read_byte(&mut self) -> io::Result<u8> {
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf).await?;
        Ok(buf[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_read_single_message() {
        let msg = b"8=FIX.4.2\x019=5\x0135=A\x0110=163\x01";
        let mut parser = FixParser::new(&msg[..]);
        let result = parser.read_message().await.unwrap().unwrap();
        assert_eq!(result, msg.to_vec());
    }

    #[tokio::test]
    async fn test_read_two_messages() {
        let msg1 = b"8=FIX.4.2\x019=5\x0135=A\x0110=163\x01";
        let msg2 = b"8=FIX.4.2\x019=5\x0135=5\x0110=042\x01";
        let mut data = Vec::new();
        data.extend_from_slice(msg1);
        data.extend_from_slice(msg2);

        let mut parser = FixParser::new(&data[..]);
        let r1 = parser.read_message().await.unwrap().unwrap();
        let r2 = parser.read_message().await.unwrap().unwrap();
        assert_eq!(r1, msg1.to_vec());
        assert_eq!(r2, msg2.to_vec());
    }

    #[tokio::test]
    async fn test_read_eof() {
        let data: &[u8] = b"";
        let mut parser = FixParser::new(data);
        let result = parser.read_message().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_read_real_message() {
        // A realistic logon message.
        let msg = b"8=FIX.4.2\x019=61\x0135=A\x0134=1\x0149=ISLD\x0152=20260228-12:00:00\x0156=TW\x0198=0\x01108=30\x0110=163\x01";
        let mut parser = FixParser::new(&msg[..]);
        let result = parser.read_message().await.unwrap().unwrap();
        assert_eq!(result, msg.to_vec());
    }
}
