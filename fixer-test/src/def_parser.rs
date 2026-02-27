use std::fs;
use std::path::Path;

/// A parsed command from a `.def` test definition file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefCommand {
    /// Open a TCP connection (client initiates).
    Connect { connection_id: usize },
    /// Close a TCP connection (client initiates).
    Disconnect { connection_id: usize },
    /// Wait for server to accept a connection.
    WaitConnect { connection_id: usize },
    /// Wait for server to close the connection.
    WaitDisconnect { connection_id: usize },
    /// Send a FIX message to the server.
    Initiate {
        connection_id: usize,
        raw_msg: String,
    },
    /// Receive a FIX message from the server and verify it matches.
    Expect {
        connection_id: usize,
        raw_msg: String,
    },
}

/// Parse a `.def` file into a sequence of test commands.
///
/// Returns the commands and the line numbers they came from (1-based) for error reporting.
pub fn parse_def_file(path: &Path) -> Result<Vec<(usize, DefCommand)>, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    parse_def_str(&content)
}

/// Parse `.def` content from a string.
pub fn parse_def_str(content: &str) -> Result<Vec<(usize, DefCommand)>, String> {
    let mut commands = Vec::new();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;
        let line = line.trim();

        // Skip empty lines and comments.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let cmd = parse_line(line)
            .map_err(|e| format!("line {line_num}: {e}"))?;
        commands.push((line_num, cmd));
    }

    Ok(commands)
}

/// Parse a single non-empty, non-comment line into a `DefCommand`.
fn parse_line(line: &str) -> Result<DefCommand, String> {
    let first = line.as_bytes().first().copied().ok_or("empty line")?;

    match first {
        // Uppercase I = Initiate (send message) or iCONNECT
        b'I' => Ok(parse_initiate_or_connect(line)),
        // Uppercase E = Expect (receive message)
        b'E' => Ok(parse_expect_or_wait(line)),
        // Lowercase i = control command (connect, disconnect, set_session)
        b'i' => parse_control(line),
        // Lowercase e = wait command (connect, disconnect)
        b'e' => parse_wait(line),
        _ => Err(format!("unexpected line prefix: {line}")),
    }
}

/// Parse `I...` lines: either `Initiate` with a FIX message or `ICONNECT`.
fn parse_initiate_or_connect(line: &str) -> DefCommand {
    let (cid, body) = extract_connection_id_and_body(line);

    if body == "CONNECT" {
        return DefCommand::Connect {
            connection_id: cid,
        };
    }

    DefCommand::Initiate {
        connection_id: cid,
        raw_msg: body.to_string(),
    }
}

/// Parse `E...` lines: either `Expect` with a FIX message or `EDISCONNECT`/`ECONNECT`.
fn parse_expect_or_wait(line: &str) -> DefCommand {
    let (cid, body) = extract_connection_id_and_body(line);

    if body == "DISCONNECT" {
        return DefCommand::WaitDisconnect {
            connection_id: cid,
        };
    }
    if body == "CONNECT" {
        return DefCommand::WaitConnect {
            connection_id: cid,
        };
    }

    DefCommand::Expect {
        connection_id: cid,
        raw_msg: body.to_string(),
    }
}

/// Parse `i...` lines: `iCONNECT`, `iDISCONNECT`, `i1,CONNECT`, etc.
fn parse_control(line: &str) -> Result<DefCommand, String> {
    let (cid, body) = extract_connection_id_and_body(line);

    match body {
        "CONNECT" => Ok(DefCommand::Connect {
            connection_id: cid,
        }),
        "DISCONNECT" => Ok(DefCommand::Disconnect {
            connection_id: cid,
        }),
        _ => Err(format!("unknown control command: {body}")),
    }
}

/// Parse `e...` lines: `eCONNECT`, `eDISCONNECT`, `e1,CONNECT`, etc.
fn parse_wait(line: &str) -> Result<DefCommand, String> {
    let (cid, body) = extract_connection_id_and_body(line);

    match body {
        "CONNECT" => Ok(DefCommand::WaitConnect {
            connection_id: cid,
        }),
        "DISCONNECT" => Ok(DefCommand::WaitDisconnect {
            connection_id: cid,
        }),
        _ => Err(format!("unknown wait command: {body}")),
    }
}

/// Extract the connection ID and body from a line.
///
/// Format: `<prefix><digit>,<body>` or `<prefix><body>`.
/// Connection ID defaults to 1 if not specified.
///
/// Examples:
/// - `iCONNECT` → (1, "CONNECT")
/// - `i2,CONNECT` → (2, "CONNECT")
/// - `I8=FIX.4.2...` → (1, "8=FIX.4.2...")
/// - `I1,8=FIX.4.2...` → (1, "8=FIX.4.2...")
fn extract_connection_id_and_body(line: &str) -> (usize, &str) {
    // Skip the first character (I/E/i/e).
    let rest = &line[1..];

    // Check if the second character is a digit followed by a comma.
    let bytes = rest.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_digit() && bytes[1] == b',' {
        let cid = (bytes[0] - b'0') as usize;
        (cid, &rest[2..])
    } else {
        (1, rest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_connection_id_no_id() {
        assert_eq!(extract_connection_id_and_body("iCONNECT"), (1, "CONNECT"));
        assert_eq!(
            extract_connection_id_and_body("I8=FIX.4.2"),
            (1, "8=FIX.4.2")
        );
    }

    #[test]
    fn test_extract_connection_id_with_id() {
        assert_eq!(
            extract_connection_id_and_body("i2,CONNECT"),
            (2, "CONNECT")
        );
        assert_eq!(
            extract_connection_id_and_body("I1,8=FIX.4.2"),
            (1, "8=FIX.4.2")
        );
        assert_eq!(
            extract_connection_id_and_body("E3,8=FIX.4.2"),
            (3, "8=FIX.4.2")
        );
    }

    #[test]
    fn test_parse_connect_commands() {
        assert_eq!(
            parse_line("iCONNECT").unwrap(),
            DefCommand::Connect { connection_id: 1 }
        );
        assert_eq!(
            parse_line("i2,CONNECT").unwrap(),
            DefCommand::Connect { connection_id: 2 }
        );
    }

    #[test]
    fn test_parse_disconnect_commands() {
        assert_eq!(
            parse_line("iDISCONNECT").unwrap(),
            DefCommand::Disconnect { connection_id: 1 }
        );
        assert_eq!(
            parse_line("eDISCONNECT").unwrap(),
            DefCommand::WaitDisconnect { connection_id: 1 }
        );
        assert_eq!(
            parse_line("e2,DISCONNECT").unwrap(),
            DefCommand::WaitDisconnect { connection_id: 2 }
        );
    }

    #[test]
    fn test_parse_wait_connect() {
        assert_eq!(
            parse_line("eCONNECT").unwrap(),
            DefCommand::WaitConnect { connection_id: 1 }
        );
    }

    #[test]
    fn test_parse_initiate() {
        let cmd =
            parse_line("I8=FIX.4.235=A34=549=TW52=<TIME>56=ISLD98=0108=30").unwrap();
        assert_eq!(
            cmd,
            DefCommand::Initiate {
                connection_id: 1,
                raw_msg: "8=FIX.4.235=A34=549=TW52=<TIME>56=ISLD98=0108=30".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_initiate_with_connection_id() {
        let cmd = parse_line("I2,8=FIX.4.235=A34=149=TW52=<TIME>56=ISLD98=0108=30")
            .unwrap();
        assert_eq!(
            cmd,
            DefCommand::Initiate {
                connection_id: 2,
                raw_msg: "8=FIX.4.235=A34=149=TW52=<TIME>56=ISLD98=0108=30".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_expect() {
        let cmd = parse_line(
            "E8=FIX.4.29=6135=A34=149=ISLD52=00000000-00:00:00.00056=TW98=0108=3010=0",
        )
        .unwrap();
        assert_eq!(
            cmd,
            DefCommand::Expect {
                connection_id: 1,
                raw_msg:
                    "8=FIX.4.29=6135=A34=149=ISLD52=00000000-00:00:00.00056=TW98=0108=3010=0"
                        .to_string(),
            }
        );
    }

    #[test]
    fn test_parse_def_str_skips_comments_and_blanks() {
        let content = "\
# comment
iCONNECT
I8=FIX.4.235=A34=149=TW52=<TIME>56=ISLD98=0108=30

# another comment
E8=FIX.4.29=6135=A34=149=ISLD52=00000000-00:00:00.00056=TW98=0108=3010=0
eDISCONNECT
";
        let cmds = parse_def_str(content).unwrap();
        assert_eq!(cmds.len(), 4);
        assert_eq!(cmds[0].0, 2); // line number
        assert_eq!(
            cmds[0].1,
            DefCommand::Connect { connection_id: 1 }
        );
        assert_eq!(cmds[3].0, 7);
        assert_eq!(
            cmds[3].1,
            DefCommand::WaitDisconnect { connection_id: 1 }
        );
    }

    #[test]
    fn test_parse_multi_connection() {
        let content = "\
i1,CONNECT
I1,8=FIX.4.235=A34=149=TW52=<TIME>56=ISLD98=0108=30
E1,8=FIX.4.29=6135=A34=149=ISLD52=00000000-00:00:00.00056=TW98=0108=3010=0
i2,CONNECT
I2,8=FIX.4.235=A34=149=TW52=<TIME>56=ISLD98=0108=30
e2,DISCONNECT
i1,DISCONNECT
";
        let cmds = parse_def_str(content).unwrap();
        assert_eq!(cmds.len(), 7);
        assert_eq!(
            cmds[0].1,
            DefCommand::Connect { connection_id: 1 }
        );
        assert_eq!(
            cmds[3].1,
            DefCommand::Connect { connection_id: 2 }
        );
        assert_eq!(
            cmds[5].1,
            DefCommand::WaitDisconnect { connection_id: 2 }
        );
        assert_eq!(
            cmds[6].1,
            DefCommand::Disconnect { connection_id: 1 }
        );
    }

    #[test]
    fn test_parse_real_def_file() {
        let path = Path::new("_test/definitions/server/fix42/1a_ValidLogonMsgSeqNumTooHigh.def");
        if !path.exists() {
            return; // skip if test assets not available
        }
        let cmds = parse_def_file(path).unwrap();

        // This file has: iCONNECT, I(logon), E(logon), E(resend), I(logout), E(logout), eDISCONNECT
        assert_eq!(cmds.len(), 7);
        assert_eq!(cmds[0].1, DefCommand::Connect { connection_id: 1 });
        assert!(matches!(cmds[1].1, DefCommand::Initiate { connection_id: 1, .. }));
        assert!(matches!(cmds[2].1, DefCommand::Expect { connection_id: 1, .. }));
        assert!(matches!(cmds[3].1, DefCommand::Expect { connection_id: 1, .. }));
        assert!(matches!(cmds[4].1, DefCommand::Initiate { connection_id: 1, .. }));
        assert!(matches!(cmds[5].1, DefCommand::Expect { connection_id: 1, .. }));
        assert_eq!(cmds[6].1, DefCommand::WaitDisconnect { connection_id: 1 });

        // Verify the raw_msg contains SOH-delimited fields.
        if let DefCommand::Initiate { raw_msg, .. } = &cmds[1].1 {
            assert!(raw_msg.contains("8=FIX.4.2"));
            assert!(raw_msg.contains("35=A"));
            // Should contain SOH bytes between fields.
            assert!(raw_msg.as_bytes().contains(&0x01));
        } else {
            panic!("expected Initiate");
        }
    }

    #[test]
    fn test_parse_real_multi_connection_def() {
        let path = Path::new("_test/definitions/server/fix42/1b_DuplicateIdentity.def");
        if !path.exists() {
            return;
        }
        let cmds = parse_def_file(path).unwrap();

        // Should have multi-connection commands.
        assert!(cmds.iter().any(|(_, cmd)| matches!(cmd, DefCommand::Connect { connection_id: 2 })));
        assert!(cmds.iter().any(|(_, cmd)| matches!(cmd, DefCommand::WaitDisconnect { connection_id: 2 })));
    }
}
