# Fixer Examples

Working examples that demonstrate how to build FIX applications with fixer.

## Examples

### Echo Server (Acceptor)

A minimal FIX Acceptor that echoes `NewOrderSingle` (35=D) messages back to the
sender. Demonstrates the `Application` trait, `Acceptor` lifecycle, and
`send_to_target`.

### Trade Client (Initiator)

A FIX Initiator that connects to a server and sends orders after logon.
Demonstrates the `Initiator`, generated message types from `fixer-fix`
(`NewOrderSingle`, `ExecutionReport`), enum constants, and typed field access.

## Quick Start

Run both examples together to see a complete FIX session. You need two
terminals.

**Terminal 1** -- start the echo server:

```sh
cargo run --example echo_server -- examples/echo_server/echo_server.cfg
```

**Terminal 2** -- start the trade client:

```sh
cargo run -p fixer-fix --example trade_client -- examples/trade_client/trade_client.cfg
```

## What You'll See

1. The trade client connects to the echo server on port 5001
2. Both sides perform a FIX 4.2 logon handshake
3. After logon, the client sends a `NewOrderSingle` for AAPL (limit buy, 100 shares @ 150.25)
4. The echo server echoes the message back
5. The client prints the received execution report fields
6. Both sides exchange heartbeats every 30 seconds
7. Press Ctrl+C in either terminal to stop

## Configuration

Each example has a `.cfg` file using fixer's INI-style format:

- `[DEFAULT]` -- settings inherited by all sessions
- `[SESSION]` -- per-session overrides

Key settings:

| Setting | Echo Server | Trade Client |
|---|---|---|
| `BeginString` | FIX.4.2 | FIX.4.2 |
| `SenderCompID` | ISLD | TW |
| `TargetCompID` | TW | ISLD |
| `SocketAcceptPort` | 5001 | -- |
| `SocketConnectHost` | -- | localhost |
| `SocketConnectPort` | -- | 5001 |

## Adapting for Your Use

- **Change the FIX version**: Update `BeginString` and `DataDictionary` in the
  `.cfg` file. Use message types from the corresponding `fixer_fix::fix4x`
  module.
- **Add more message types**: Handle additional `MsgType` values in `from_app`.
- **Add persistence**: Replace `MemoryStoreFactory` with `FileStoreFactory` or
  `SqlStoreFactory` (behind the `sql_store` feature flag).
- **Add file logging**: Replace `ScreenLogFactory` with `FileLogFactory` and set
  `FileLogPath` in the config.
- **Add TLS**: Set `SocketUseSSL=Y` and configure certificate paths in the
  `.cfg` file.
