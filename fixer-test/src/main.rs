pub mod comparator;
pub mod def_parser;
pub mod echo_server;
pub mod fix_helpers;
pub mod fix_parser;
pub mod runner;

use std::path::Path;
use std::process::ExitCode;

use comparator::Comparator;
use runner::TestRunner;

fn usage() -> ! {
    eprintln!("Usage: fixer-test <cfg_file> <port> <def_file>...");
    eprintln!();
    eprintln!("  cfg_file    Path to a .cfg file for the echo server");
    eprintln!("  port        Port number the echo server listens on");
    eprintln!("  def_file    One or more .def test definition files");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  fixer-test _test/cfg/server/fix42.cfg 5003 _test/definitions/server/fix42/*.def");
    std::process::exit(2);
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Check for --no-server flag (for testing against an external server).
    let no_server = args.first().is_some_and(|a| a == "--no-server");
    let args = if no_server { &args[1..] } else { &args[..] };

    if args.len() < 3 {
        usage();
    }

    let cfg_file = &args[0];
    let port: u16 = args[1].parse().unwrap_or_else(|e| {
        eprintln!("invalid port '{}': {e}", args[1]);
        std::process::exit(2);
    });
    let def_files: Vec<String> = args[2..].to_vec();

    // Load field comparison patterns.
    let fields_fmt = Path::new("_test/fields.fmt");
    let comparator = if fields_fmt.exists() {
        Comparator::load_patterns(fields_fmt).unwrap_or_else(|e| {
            eprintln!("failed to load fields.fmt: {e}");
            std::process::exit(1);
        })
    } else {
        eprintln!("warning: _test/fields.fmt not found, using exact comparison");
        Comparator::default()
    };

    let mut acceptor_opt = None;
    let mut send_task_opt = None;

    if no_server {
        eprintln!("Using external server on port {port}...");
    } else {
        // Start the echo server.
        eprintln!("Starting echo server with {cfg_file} on port {port}...");
        let (acceptor, send_task) =
            echo_server::start_echo_server(cfg_file).await.unwrap_or_else(|e| {
                eprintln!("failed to start echo server: {e}");
                std::process::exit(1);
            });

        // Give the server a moment to bind the port.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        acceptor_opt = Some(acceptor);
        send_task_opt = Some(send_task);
    }

    // Run the test suite.
    let runner = TestRunner::new("127.0.0.1".to_string(), port, comparator);
    let results = runner.run_suite(&def_files).await;

    // Print results.
    for result in &results.results {
        if result.success {
            eprintln!("  PASS  {}", result.name);
        } else {
            eprintln!("  FAIL  {}", result.name);
            if let Some(err) = &result.error {
                eprintln!("        {err}");
            }
        }
    }

    eprintln!();
    eprintln!(
        "{} tests, {} failures",
        results.total, results.failures
    );

    // Print XML output to stdout.
    print!("{}", runner::format_results_xml(&results));

    // Stop echo server.
    if let Some(mut acceptor) = acceptor_opt {
        acceptor.stop().await;
    }
    if let Some(send_task) = send_task_opt {
        send_task.abort();
    }

    if results.failures > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
