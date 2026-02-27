use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::comparator::{CompareResult, Comparator};
use crate::def_parser::{DefCommand, parse_def_file};
use crate::fix_helpers::{fixify, timify};
use crate::fix_parser::FixParser;

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Result of running a single `.def` test file.
#[derive(Debug)]
pub struct TestResult {
    pub name: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Result of running an entire test suite.
pub struct SuiteResult {
    pub results: Vec<TestResult>,
    pub total: usize,
    pub failures: usize,
}

/// Orchestrates acceptance test execution against an echo server.
pub struct TestRunner {
    address: String,
    port: u16,
    comparator: Comparator,
}

impl TestRunner {
    pub fn new(address: String, port: u16, comparator: Comparator) -> Self {
        Self {
            address,
            port,
            comparator,
        }
    }

    /// Run all `.def` files and return aggregated results.
    pub async fn run_suite(&self, def_files: &[String]) -> SuiteResult {
        let mut results = Vec::new();

        for def_file in def_files {
            let result = self.run_test(def_file).await;
            results.push(result);
        }

        let total = results.len();
        let failures = results.iter().filter(|r| !r.success).count();
        SuiteResult {
            results,
            total,
            failures,
        }
    }

    /// Run a single `.def` test file.
    pub async fn run_test(&self, def_file: &str) -> TestResult {
        let name = def_file.to_string();

        match self.run_test_inner(def_file).await {
            Ok(()) => TestResult {
                name,
                success: true,
                error: None,
            },
            Err(e) => TestResult {
                name,
                success: false,
                error: Some(e),
            },
        }
    }

    async fn run_test_inner(&self, def_file: &str) -> Result<(), String> {
        let path = Path::new(def_file);
        let commands = parse_def_file(path)?;

        let mut connections: HashMap<usize, Connection> = HashMap::new();

        for (line_num, cmd) in &commands {
            let result = self
                .execute_command(cmd, &mut connections, *line_num)
                .await;
            if let Err(e) = result {
                // Clean up all connections on error.
                for (_, conn) in connections.drain() {
                    drop(conn);
                }
                return Err(format!("line {line_num}: {e}"));
            }
        }

        // Clean up remaining connections.
        for (_, conn) in connections.drain() {
            drop(conn);
        }

        Ok(())
    }

    async fn execute_command(
        &self,
        cmd: &DefCommand,
        connections: &mut HashMap<usize, Connection>,
        line_num: usize,
    ) -> Result<(), String> {
        match cmd {
            DefCommand::Connect { connection_id } => {
                self.connect(*connection_id, connections).await
            }
            DefCommand::Disconnect { connection_id } => {
                Self::disconnect(*connection_id, connections)
            }
            DefCommand::WaitConnect { connection_id } => {
                // For server-mode tests, WaitConnect means accept.
                // In our case (client connecting to echo server), treat as Connect.
                self.connect(*connection_id, connections).await
            }
            DefCommand::WaitDisconnect { connection_id } => {
                self.wait_disconnect(*connection_id, connections, line_num)
                    .await
            }
            DefCommand::Initiate {
                connection_id,
                raw_msg,
            } => {
                self.initiate(*connection_id, raw_msg, connections, line_num)
                    .await
            }
            DefCommand::Expect {
                connection_id,
                raw_msg,
            } => {
                self.expect(*connection_id, raw_msg, connections, line_num)
                    .await
            }
        }
    }

    async fn connect(
        &self,
        cid: usize,
        connections: &mut HashMap<usize, Connection>,
    ) -> Result<(), String> {
        let addr = format!("{}:{}", self.address, self.port);
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("connect to {addr}: {e}"))?;
        stream
            .set_nodelay(true)
            .map_err(|e| format!("set_nodelay: {e}"))?;

        let (read_half, write_half) = stream.into_split();
        let conn = Connection {
            parser: FixParser::new(read_half),
            writer: write_half,
        };
        connections.insert(cid, conn);
        Ok(())
    }

    fn disconnect(
        cid: usize,
        connections: &mut HashMap<usize, Connection>,
    ) -> Result<(), String> {
        connections
            .remove(&cid)
            .ok_or_else(|| format!("no connection {cid} to disconnect"))?;
        Ok(())
    }

    async fn wait_disconnect(
        &self,
        cid: usize,
        connections: &mut HashMap<usize, Connection>,
        _line_num: usize,
    ) -> Result<(), String> {
        let conn = connections
            .get_mut(&cid)
            .ok_or_else(|| format!("no connection {cid} for wait_disconnect"))?;

        // Wait for the server to close the connection (EOF) or timeout.
        let result = timeout(DISCONNECT_TIMEOUT, conn.parser.read_message()).await;

        match result {
            Ok(Ok(None)) => {
                // EOF — server closed connection. Success.
                connections.remove(&cid);
                Ok(())
            }
            Ok(Ok(Some(_data))) => {
                // Got data instead of disconnect.
                connections.remove(&cid);
                Err("expected disconnect but received data".to_string())
            }
            Ok(Err(e)) => {
                // IO error — likely connection reset, which counts as disconnect.
                connections.remove(&cid);
                if e.kind() == std::io::ErrorKind::ConnectionReset {
                    Ok(())
                } else {
                    Err(format!("wait_disconnect IO error: {e}"))
                }
            }
            Err(_) => {
                // Timeout.
                connections.remove(&cid);
                Err("wait_disconnect timed out after 10s".to_string())
            }
        }
    }

    async fn initiate(
        &self,
        cid: usize,
        raw_msg: &str,
        connections: &mut HashMap<usize, Connection>,
        _line_num: usize,
    ) -> Result<(), String> {
        let conn = connections
            .get_mut(&cid)
            .ok_or_else(|| format!("no connection {cid} for initiate"))?;

        // Apply timify (replace <TIME> with current timestamp) then fixify (calculate body length + checksum).
        let msg_bytes = raw_msg.as_bytes();
        let timified = timify(msg_bytes);
        let fixed = fixify(&timified);

        conn.writer
            .write_all(&fixed)
            .await
            .map_err(|e| format!("write: {e}"))?;
        conn.writer.flush().await.map_err(|e| format!("flush: {e}"))?;

        Ok(())
    }

    async fn expect(
        &self,
        cid: usize,
        raw_msg: &str,
        connections: &mut HashMap<usize, Connection>,
        _line_num: usize,
    ) -> Result<(), String> {
        let conn = connections
            .get_mut(&cid)
            .ok_or_else(|| format!("no connection {cid} for expect"))?;

        // Build the expected message (timify + fixify).
        let msg_bytes = raw_msg.as_bytes();
        let timified = timify(msg_bytes);
        let expected = fixify(&timified);

        // Read actual message from server with timeout.
        let actual = timeout(READ_TIMEOUT, conn.parser.read_message())
            .await
            .map_err(|_| format!("read timed out after {READ_TIMEOUT:?}"))?
            .map_err(|e| format!("read error: {e}"))?
            .ok_or_else(|| "connection closed while expecting message".to_string())?;

        // Compare.
        match self.comparator.compare(&expected, &actual) {
            CompareResult::Match => Ok(()),
            CompareResult::Mismatch { reason } => Err(reason),
        }
    }
}

/// A TCP connection to the echo server with parser and writer halves.
struct Connection {
    parser: FixParser<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

/// Format suite results as XML (compatible with quickfix Ruby runner output).
pub fn format_results_xml(results: &SuiteResult) -> String {
    use std::fmt::Write;

    let mut xml = String::from("<at>\n");

    for result in &results.results {
        let status = if result.success { "success" } else { "failure" };
        let _ = write!(xml, "  <test name='{}' result='{status}'", result.name);
        if let Some(err) = &result.error {
            let escaped = err
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('\'', "&apos;");
            let _ = write!(xml, " description='{escaped}'");
        }
        xml.push_str("/>\n");
    }

    let _ = writeln!(
        xml,
        "  <results total='{}' failures='{}'/>",
        results.total, results.failures
    );
    xml.push_str("</at>\n");
    xml
}
