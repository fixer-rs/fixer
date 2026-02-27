// Trade Client Example
//
// A FIX Initiator that connects to a server and sends a NewOrderSingle (35=D)
// after logon. This demonstrates:
//
// - Implementing the `Application` trait with an `Initiator`
// - Using generated message types (`NewOrderSingle`, `ExecutionReport`)
// - Using enum constants (`enums::side::BUY`, `enums::ord_type::LIMIT`)
// - Sending messages with `send_to_target`
// - Receiving and parsing execution reports in `from_app`
//
// Usage:
//     cargo run -p fixer-fix --example trade_client -- examples/trade_client/trade_client.cfg
//
// Connects to localhost:5001 by default (compatible with the echo_server example).

use fixer::{
    application::Application,
    errors::MessageRejectErrorResult,
    initiator::Initiator,
    log::screen_log::ScreenLogFactory,
    message::Message,
    registry::send_to_target,
    session::session_id::SessionID,
    settings::Settings,
    store::MemoryStoreFactory,
    tag::TAG_MSG_TYPE,
};
use fixer_fix::{
    enums,
    field,
    fix42::{execution_report::ExecutionReport, new_order_single::NewOrderSingle},
};
use jiff::Timestamp;
use rust_decimal::Decimal;
use simple_error::SimpleResult;
use std::{str::FromStr, sync::Arc};
use tokio::{io::BufReader, sync::mpsc};

/// A pending order to be sent through a session.
struct PendingOrder {
    message: Message,
    session_id: Arc<SessionID>,
}

/// The trade client application. Sends an order on logon and prints execution
/// reports received from the server.
///
/// All `Application` callbacks take `&self` (not `&mut self`), so we use a
/// channel to bridge into the async world where `send_to_target` can be awaited.
struct TradeApp {
    order_tx: mpsc::UnboundedSender<PendingOrder>,
}

impl TradeApp {
    /// Build a sample `NewOrderSingle` for AAPL.
    fn build_order() -> NewOrderSingle {
        let mut order = NewOrderSingle::new(
            field::ClOrdIDField::new("ORD-001".to_string()),
            field::HandlInstField::new(
                enums::handl_inst::AUTOMATED_EXECUTION_ORDER_PRIVATE_NO_BROKER_INTERVENTION
                    .to_string(),
            ),
            field::SymbolField::new("AAPL".to_string()),
            field::SideField::new(enums::side::BUY.to_string()),
            field::TransactTimeField::new(Timestamp::now()),
            field::OrdTypeField::new(enums::ord_type::LIMIT.to_string()),
        );

        order.set_order_qty(Decimal::from_str("100").unwrap(), 0);
        order.set_price(Decimal::from_str("150.25").unwrap(), 2);
        order.set_time_in_force(enums::time_in_force::DAY.to_string());
        order.set_account("ACCT-123".to_string());

        order
    }

    /// Parse and print an execution report.
    fn print_execution_report(msg: &Message) {
        let er = ExecutionReport::from_message(msg.clone());

        let order_id = er.get_order_id().unwrap_or_default();
        let cl_ord_id = er.get_cl_ord_id().unwrap_or_default();
        let exec_type = er.get_exec_type().unwrap_or_default();
        let ord_status = er.get_ord_status().unwrap_or_default();
        let symbol = er.get_symbol().unwrap_or_default();
        let side = er.get_side().unwrap_or_default();
        let leaves_qty = er.get_leaves_qty().unwrap_or_default();
        let cum_qty = er.get_cum_qty().unwrap_or_default();
        let avg_px = er.get_avg_px().unwrap_or_default();

        println!("  OrderID={order_id} ClOrdID={cl_ord_id}");
        println!("  ExecType={exec_type} OrdStatus={ord_status}");
        println!("  Symbol={symbol} Side={side}");
        println!("  LeavesQty={leaves_qty} CumQty={cum_qty} AvgPx={avg_px}");
    }
}

impl Application for TradeApp {
    fn on_create(&self, session_id: &Arc<SessionID>) {
        println!("Session created: {session_id}");
    }

    fn on_logon(&self, session_id: &Arc<SessionID>) {
        println!("Logon: {session_id}");
        println!("Sending NewOrderSingle for AAPL...");

        let order = Self::build_order();
        let _ = self.order_tx.send(PendingOrder {
            message: order.to_message(),
            session_id: session_id.clone(),
        });
    }

    fn on_logout(&self, session_id: &Arc<SessionID>) {
        println!("Logout: {session_id}");
    }

    fn to_admin(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) {}

    fn to_app(&self, _msg: &mut Message, _session_id: &Arc<SessionID>) -> SimpleResult<()> {
        Ok(())
    }

    fn from_admin(
        &self,
        _msg: &Message,
        _session_id: &Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        Ok(())
    }

    fn from_app(
        &self,
        msg: &Message,
        session_id: &Arc<SessionID>,
    ) -> MessageRejectErrorResult {
        let msg_type = msg.header.get_bytes(TAG_MSG_TYPE).unwrap_or(b"");
        let msg_type_str = String::from_utf8_lossy(msg_type);

        match msg_type_str.as_ref() {
            "8" => {
                println!("Received ExecutionReport from {session_id}:");
                Self::print_execution_report(msg);
            }
            other => {
                println!("Received message type={other} from {session_id}");
            }
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: trade_client <config.cfg>");
        eprintln!(
            "Example: cargo run -p fixer-fix --example trade_client -- examples/trade_client/trade_client.cfg"
        );
        std::process::exit(1);
    });

    let cfg_data = tokio::fs::read_to_string(&cfg_path).await?;
    let settings = Settings::parse(BufReader::new(cfg_data.as_bytes())).await?;

    let (order_tx, mut order_rx) = mpsc::unbounded_channel::<PendingOrder>();

    let app: Arc<dyn Application> = Arc::new(TradeApp { order_tx });
    let store_factory = MemoryStoreFactory::new();
    let log_factory = ScreenLogFactory::new();

    let mut initiator = Initiator::new(app, store_factory, settings, log_factory).await?;
    initiator.start().await?;

    println!("Trade client started. Connecting to server...");
    println!("Press Ctrl+C to stop.");

    // Spawn a background task that drains the order channel and sends
    // messages through the appropriate sessions.
    let send_task = tokio::spawn(async move {
        while let Some(pending) = order_rx.recv().await {
            if let Err(e) = send_to_target(&pending.message, &pending.session_id).await {
                eprintln!("Failed to send order: {e}");
            } else {
                println!("Order sent successfully.");
            }
        }
    });

    tokio::signal::ctrl_c().await?;

    println!("\nStopping trade client...");
    initiator.stop().await;
    send_task.abort();
    println!("Stopped.");

    Ok(())
}
