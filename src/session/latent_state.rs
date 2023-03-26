use crate::session::session_state::InSessionTime;
use delegate::delegate;

#[derive(Default, Debug, Clone)]
pub struct LatentState {
    pub in_session_time: InSessionTime,
}

impl ToString for LatentState {
    fn to_string(&self) -> String {
        String::from("Latent State")
    }
}

impl LatentState {
    delegate! {
        to self.in_session_time {
            pub fn is_session_time(&self) -> bool;
        }
    }

    pub fn is_logged_on(&self) -> bool {
        false
    }

    pub fn is_connected(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
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
