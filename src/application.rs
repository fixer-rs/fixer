use crate::errors::MessageRejectErrorResult;
use crate::message::Message;
use crate::session::session_id::SessionID;
use simple_error::SimpleResult;

// Application interface should be implemented by FIX Applications.
// This is the primary interface for processing messages from a FIX Session.
pub trait Application: Send + Sync {
    // on_create notification of a session begin created.
    fn on_create(&mut self, session_id: &SessionID);

    // on_logon notification of a session successfully logging on.
    fn on_logon(&mut self, session_id: &SessionID);

    // on_logout notification of a session logging off or disconnecting.
    fn on_logout(&mut self, session_id: &SessionID);

    // to_admin notification of admin message being sent to target.
    fn to_admin(&mut self, msg: &Message, session_id: &SessionID);

    // to_app notification of app message being sent to target.
    fn to_app(&mut self, msg: &Message, session_id: &SessionID) -> SimpleResult<()>;

    // from_admin notification of admin message being received from target.
    fn from_admin(&mut self, msg: &Message, session_id: &SessionID) -> MessageRejectErrorResult;

    // from_app notification of app message being received from target.
    fn from_app(&mut self, msg: &Message, session_id: &SessionID) -> MessageRejectErrorResult;
}
