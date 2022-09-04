use crate::log::{Log, LogFactory};

struct ScreenLog {
    prefix: String,
}

// impl Log for ScreenLog {
//     fn on_incoming(&self, data: Vec<u8>) {
//         todo!()
//     }

//     fn on_outgoing(&self, data: Vec<u8>) {
//         todo!()
//     }

//     fn on_event(&self, event: String) {
//         todo!()
//     }

//     fn on_eventf(&self, event: String, t: T) {
//         todo!()
//     }
// }

// func (l screenLog) OnIncoming(s []byte) {
// 	logTime := time.Now().UTC()
// 	fmt.Printf("<%v, %s, incoming>\n  (%s)\n", logTime, l.prefix, s)
// }

// func (l screenLog) OnOutgoing(s []byte) {
// 	logTime := time.Now().UTC()
// 	fmt.Printf("<%v, %s, outgoing>\n  (%s)\n", logTime, l.prefix, s)
// }

// func (l screenLog) OnEvent(s string) {
// 	logTime := time.Now().UTC()
// 	fmt.Printf("<%v, %s, event>\n  (%s)\n", logTime, l.prefix, s)
// }

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
