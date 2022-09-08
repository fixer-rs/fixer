use crate::errors::MessageRejectErrorTrait;
use crate::message::Message;
use crate::session_id::SessionID;
use simple_error::SimpleResult;

// Application interface should be implemented by FIX Applications.
// This is the primary interface for processing messages from a FIX Session.
pub trait Application {
    // on_create notification of a session begin created.
    fn on_create(session_id: SessionID);

    // on_logon notification of a session successfully logging on.
    fn on_logon(session_id: SessionID);

    // on_logout notification of a session logging off or disconnecting.
    fn on_logout(session_id: SessionID);

    // to_admin notification of admin message being sent to target.
    fn to_admin<'a>(message: &'a Message, session_id: SessionID);

    // to_app notification of app message being sent to target.
    fn to_app<'a>(message: &'a Message, session_id: SessionID) -> SimpleResult<()>;

    // from_admin notification of admin message being received from target.
    fn from_admin<'a>(
        message: &'a Message,
        session_id: SessionID,
    ) -> Box<dyn MessageRejectErrorTrait>;

    // from_app notification of app message being received from target.
    fn from_app<'a>(
        message: &'a Message,
        session_id: SessionID,
    ) -> Box<dyn MessageRejectErrorTrait>;
}
