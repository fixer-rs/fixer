use crate::session::latent_state::LatentState;
use delegate::delegate;

#[derive(Default, Debug, Clone)]
pub struct NotSessionTime {
    pub latent_state: LatentState,
}

impl ToString for NotSessionTime {
    fn to_string(&self) -> String {
        String::from("Not session time")
    }
}

impl NotSessionTime {
    delegate! {
        to self.latent_state {
            pub fn is_connected(&self) -> bool;
            pub fn is_logged_on(&self) -> bool;
        }
    }

    pub fn is_session_time(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    // type NotSessionTimeTestSuite struct {
    // 	SessionSuiteRig
    // }

    // func TestNotSessionTime(t *testing.T) {
    // 	suite.Run(t, new(NotSessionTimeTestSuite))
    // }

    // func (s *NotSessionTimeTestSuite) SetupTest() {
    // 	s.Init()
    // 	s.session.State = notSessionTime{}
    // }

    // func (s *NotSessionTimeTestSuite) TestPreliminary() {
    // 	s.False(s.session.IsLoggedOn())
    // 	s.False(s.session.IsConnected())
    // 	s.False(s.session.IsSessionTime())
    // }

    // func (s *NotSessionTimeTestSuite) TestDisconnected() {
    // 	s.session.Disconnected(s.session)
    // 	s.State(notSessionTime{})
    // }

    // func (s *NotSessionTimeTestSuite) TestStop() {
    // 	s.session.Stop(s.session)
    // 	s.Stopped()
    // }
}
