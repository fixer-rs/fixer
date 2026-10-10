# Windows build and run

The library supports native Windows builds. Install the Rust MSVC toolchain and
the Visual Studio C++ linker, then run Cargo directly from PowerShell.

## Prerequisites

Install Rust with the default `x86_64-pc-windows-msvc` toolchain and install
Visual Studio 2022 Build Tools with the **Desktop development with C++**
workload. Verify the toolchain from a new PowerShell window:

```powershell
rustc --version
cargo --version
rustup show active-toolchain
```

## Build and test

From the repository root:

```powershell
cargo build --workspace
cargo test --workspace
```

The repository `Makefile` is intended for Unix shells. On Windows, use the
Cargo commands above. Code generation can be run directly as follows:

```powershell
cargo run -p fixer-gen -- spec/FIX40.xml spec/FIX41.xml spec/FIX42.xml spec/FIX43.xml spec/FIX44.xml spec/FIX50.xml spec/FIX50SP1.xml spec/FIX50SP2.xml -o fixer-fix/src
```

## Run the examples

Start the acceptor and initiator in separate PowerShell windows:

```powershell
cargo run --example echo_server -- examples/echo_server/echo_server.cfg
cargo run -p fixer-fix --example trade_client -- examples/trade_client/trade_client.cfg
```

Configuration paths use Rust's platform-aware `Path` handling, so Windows paths
such as `C:\fixer\logs` are supported.
