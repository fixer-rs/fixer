# fixer

[![Rust](https://github.com/fixer-rs/fixer/actions/workflows/rust.yml/badge.svg?branch=wip)](https://github.com/fixer-rs/fixer/actions/workflows/rust.yml)

Open Source [FIX Protocol](http://www.fixprotocol.org/) library implemented in Rust.

> **Note:** This project is still under heavy development.

## About

fixer is a [FIX Protocol Community](https://www.fixtrading.org/) implementation for the [Rust programming language](https://www.rust-lang.org/).

- 100% free and open source
- Supports FIX versions 4.0 - 5.0SP2
- Spec driven run-time message validation
- Spec driven code generation of type-safe FIX messages, fields, and repeating groups
- Support for protocol customizations
- Session state storage options: SQL, MongoDB, On-disk, or In-memory
- Logging options: File, Screen
- Failover and High Availability
- Daily and weekly scheduling of session connections
- Integrated support for TLS communications
- Automated unit and acceptance tests

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
fixer = { git = "https://github.com/fixer-rs/fixer" }
```

## FIX Messaging Model

To send and receive FIX messages, your application will use the generated type-safe message packages.

fixer includes a code generator (`fixer-gen`) that produces Rust modules from the FIX 4.0 - FIX 5.0SP2 XML specifications. The generated code lives in the `fixer-fix` crate and provides:

- `tag` — Tag constants
- `field` — Typed field wrapper structs
- `enums` — Field enumeration values
- `fix40` through `fix50sp2` — Per-version message types with constructors, setters, and getters
- `fixt11` — FIXT 1.1 session-level messages

For most FIX applications, these generated resources are sufficient. Custom FIX applications may generate source specific to the FIX spec of that application using the `fixer-gen` tool.

### Code Generation

To regenerate the FIX message types from the XML specifications:

```sh
make generate
```

To generate with `f64` instead of `Decimal` for numeric fields:

```sh
make generate-float
```

## Examples

The `examples/` directory contains working applications that demonstrate how to use fixer:

- **Echo Server** — A FIX Acceptor that echoes incoming messages back to the sender
- **Trade Client** — A FIX Initiator that sends a `NewOrderSingle` after logon and prints execution reports

Run both together to see a complete FIX session:

```sh
# Terminal 1: start the echo server
cargo run --example echo_server -- examples/echo_server/echo_server.cfg

# Terminal 2: start the trade client
cargo run -p fixer-fix --example trade_client -- examples/trade_client/trade_client.cfg
```

See [`examples/README.md`](examples/README.md) for more details.

## Build and Test

```sh
# run lints and tests
make clippy
make test

# format code
make fmt
```

## General Support

### FIX Protocol

More information about the FIX protocol can be found at the [FIX Trading Community](http://fixtradingcommunity.org) website.

### Bugs and Issues

Bugs and issues can be submitted through the GitHub repository issues list.

Please provide sample code, logs, and a description of the problem when submitting an issue.

## Contributing

Contributions are welcome. Please open an issue or pull request on GitHub.

## Collaboration

I'm Karuna Murti, the author of fixer. I'm interested in working together with people who want to build a company or implement this in their company. If you're interested, feel free to reach out at karuna.murti@gmail.com.

## Licensing

This software is available under the QuickFIX Software License. Please see the [LICENSE.txt](LICENSE.txt) for the terms specified by the QuickFIX Software License.
