use crate::{
    log::{LogEnum, LogTrait},
    parser::Parser,
    session::FixIn,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub async fn write_loop<W>(
    mut connection: W,
    mut message_out: UnboundedReceiver<Vec<u8>>,
    log: LogEnum,
) where
    W: AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            Some(msg) = message_out.recv() => {
                if let Err(err) = (connection).write(&msg).await {
                    log.on_event(&err.to_string());
                };
            },
            else => {
                return
            }
        }
    }
}

pub async fn read_loop<T>(mut parser: Parser<T>, msg_in: UnboundedSender<FixIn>)
where
    T: Unpin + AsyncRead,
{
    loop {
        tokio::select! {
            Ok(msg) = parser.read_message() => {

                let _ = msg_in.send(FixIn {
                    bytes: msg,
                    receive_time: parser.last_read.into(),
                });

            },
            else => {
                return
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::connection::{read_loop, write_loop};
    use crate::log::{null_log::NullLog, LogEnum};
    use crate::parser::Parser;
    use crate::session::FixIn;
    use tokio::io::BufReader;
    use tokio::sync::mpsc::unbounded_channel;

    #[tokio::test]
    async fn test_write_loop() {
        let mut writer: Vec<u8> = vec![];
        let (msg_out_tx, msg_out_rx) = unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
            let _ = msg_out_tx.send(br#"test msg 1 "#.to_vec());
            let _ = msg_out_tx.send(br#"test msg 2 "#.to_vec());
            let _ = msg_out_tx.send(br#"test msg 3"#.to_vec());
        });
        let nl = LogEnum::NullLog(NullLog {});
        write_loop(&mut writer, msg_out_rx, nl).await;

        let expected = "test msg 1 test msg 2 test msg 3";
        let res = &String::from_utf8_lossy(&writer).to_string();
        assert_eq!(res, expected, "expected {} got {}", expected, res);
    }

    #[tokio::test]
    async fn test_read_loop() {
        let (msg_in_tx, mut msg_in_rx) = unbounded_channel::<FixIn>();
        let stream = "hello8=FIX.4.09=5blah10=103garbage8=FIX.4.09=4foo10=103";
        let buf_reader = BufReader::new(stream.as_bytes());
        let parser = Parser::new(buf_reader);

        tokio::spawn(async move { read_loop(parser, msg_in_tx).await });

        struct TestCase {
            expected_msg: String,
            channel_closed: bool,
        }

        let mut tests = vec![
            TestCase {
                expected_msg: String::from("8=FIX.4.09=5blah10=103"),
                channel_closed: false,
            },
            TestCase {
                expected_msg: String::from("8=FIX.4.09=4foo10=103"),
                channel_closed: false,
            },
            TestCase {
                expected_msg: String::from(""),
                channel_closed: true,
            },
        ];

        for test in tests.iter_mut() {
            let msg_result = msg_in_rx.recv().await;
            if msg_result.is_none() {
                assert!(test.channel_closed, "Channel unexpectedly closed");
                continue;
            }
            let msg = msg_result.unwrap();
            let got = String::from_utf8_lossy(&msg.bytes).to_string();
            assert_eq!(
                &got, &test.expected_msg,
                "Expected {} got {}",
                &test.expected_msg, &got
            );
        }
    }
}
