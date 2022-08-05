// Log is a generic trait for logging FIX messages and events.
pub trait Log<T> {
    // on_incoming log incoming fix message
    fn on_incoming(data: Vec<u8>);

    // on_outgoing log outgoing fix message
    fn on_outgoing(data: Vec<u8>);

    // on_event log fix event
    fn on_event(event: String);

    // on_eventf log fix event according to format specifier
    fn on_eventf(event: String, t: T);
}

// The LogFactory trait creates global and session specific Log instances
// pub trait LogFactory<T> {
//     // create global log
//     fn create() -> Result<dyn Log<T>, String>;

//     // create_session_log session specific log
//     fn create_session_log(session_id: SessionID) -> Result<dyn Log<T>, String>;
// }
