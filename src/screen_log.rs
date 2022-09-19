use crate::log::Log;
use chrono::Utc;
use std::fmt::Debug;
struct ScreenLog {
    prefix: String,
}

const TIME_FORMAT: &str = "%Y-%m-%d %H:%M:%S %z %Z";

impl Log for ScreenLog {
    fn on_incoming(&self, data: Vec<u8>) {
        let log_time = Utc::now();

        print!(
            "<{}, {}, incoming>\n  ({})\n",
            log_time.format(TIME_FORMAT),
            &self.prefix,
            String::from_utf8_lossy(&data)
        )
    }

    fn on_outgoing(&self, data: Vec<u8>) {
        let log_time = Utc::now();

        print!(
            "<{}, {}, outgoing>\n  ({})\n",
            log_time.format(TIME_FORMAT),
            &self.prefix,
            String::from_utf8_lossy(&data)
        )
    }

    fn on_event(&self, data: String) {
        let log_time = Utc::now();

        print!(
            "<{}, {}, event>\n  ({})\n",
            log_time.format(TIME_FORMAT),
            &self.prefix,
            &data
        )
    }

    fn on_eventf(&self, format: String, params: Vec<Box<dyn Debug>>) {
        // self.on_event(format!(&format, ..params))
    }
}

// func (l screenLog) OnEventf(format string, a ...interface{}) {
// 	l.OnEvent(fmt.Sprintf(format, a...))
// }

// type screenLogFactory struct{}

// func (screenLogFactory) Create() (Log, error) {
// 	log := screenLog{"GLOBAL"}
// 	return log, nil
// }

// func (screenLogFactory) CreateSessionLog(sessionID SessionID) (Log, error) {
// 	log := screenLog{sessionID.String()}
// 	return log, nil
// }

// //NewScreenLogFactory creates an instance of LogFactory that writes messages and events to stdout.
// func NewScreenLogFactory() LogFactory {
// 	return screenLogFactory{}
// }

// TODO
