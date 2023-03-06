// import "github.com/quickfixgo/quickfix/internal"

use crate::internal::event::Event;
use crate::message::Message;
use crate::session::session_state::{InSessionTime, SessionState};
use crate::session::Session;
use async_trait::async_trait;
use delegate::delegate;

#[derive(Default)]
pub struct LatentState {
    pub in_session_time: InSessionTime,
}

impl ToString for LatentState {
    fn to_string(&self) -> String {
        String::from("Latent State")
    }
}

#[async_trait]
impl SessionState for LatentState {
    delegate! {
        to self.in_session_time {
            fn is_session_time(&self) -> bool;
        }
    }

    async fn fix_msg_in(self, session: &'_ mut Session, msg: &'_ Message) -> Box<dyn SessionState> {
        session.log.on_eventf(
            "Invalid Session State: Unexpected Msg {{msg}} while in Latent state",
            hashmap! {String::from("msg") => format!("{:?}", msg)},
        );
        Box::new(self)
    }

    fn timeout(self, _session: &mut Session, _event: Event) -> Box<dyn SessionState> {
        Box::new(self)
    }

    fn is_logged_on(&self) -> bool {
        false
    }

    fn is_connected(&self) -> bool {
        false
    }

    fn shutdown_now(&self, _session: &Session) {}

    fn stop(self, _session: &mut Session) -> Box<dyn SessionState> {
        Box::new(self)
    }
}

#[cfg(test)]
mod tests {

    // import (
    //     "testing"

    //     "github.com/stretchr/testify/suite"
    // )

    // type LatentStateTestSuite struct {
    //     SessionSuiteRig
    // }

    // func TestLatentStateTestSuite(t *testing.T) {
    //     suite.Run(t, new(LatentStateTestSuite))
    // }

    // func (s *LatentStateTestSuite) SetupTest() {
    //     s.Init()
    //     s.session.State = latentState{}
    // }

    // func (s *LatentStateTestSuite) TestPreliminary() {
    //     s.False(s.session.IsLoggedOn())
    //     s.False(s.session.IsConnected())
    //     s.True(s.session.IsSessionTime())
    // }

    // func (s *LatentStateTestSuite) TestDisconnected() {
    //     s.session.Disconnected(s.session)
    //     s.State(latentState{})
    // }

    // func (s *LatentStateTestSuite) TestStop() {
    //     s.session.Stop(s.session)
    //     s.Stopped()
    // }
}
